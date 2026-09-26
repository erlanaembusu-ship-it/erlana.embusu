"""Асинхронный клиент к NCALayer (сервис НУЦ РК) по WebSocket.

Протокол (подтверждён официальными материалами)
----------------------------------------------
* Транспорт: WebSocket на ``127.0.0.1:13579``. Каждому модулю соответствует свой
  путь, напр. ``ws://127.0.0.1:13579/kz.gov.pki.knca.basics``
  (модуль ``kz.gov.pki.knca.basics``) и ``.../kz.gov.pki.knca`` (старый модуль).
* Конверт запроса: ``{"module": "...", "method": "...", "args": {...}}``.
* ``basics.sign`` принимает ``args.data`` как строку ИЛИ МАССИВ строк —
  **именно так вся пачка файлов подписывается одной операцией, т.е. одним
  системным диалогом** вместо диалога на каждый файл.
* Ответ: ``{"status": true, "body": {"result": ...}}``;
  ``{"status": false, "code": ..., "message": ..., "details": ...}`` — ошибка;
  ``body`` без ``result`` — пользователь отменил операцию.

Безопасность пароля ЭЦП
-----------------------
Пароль живёт только в оперативной памяти (``SecretPassword`` на базе
``bytearray`` с затиранием нулями). Он никогда не пишется на диск, не попадает
в логи и не сериализуется. Пароль запрашивается в GUI один раз за сессию.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Self

import websockets
from websockets.asyncio.client import ClientConnection

from config.niche_blueprints import SignMode
from config.settings import LOOPBACK_HOSTS, NCALayerSettings
from utils.logger import get_logger

# __all__ объявлен в конце модуля (после определения всех имён).


# --------------------------------------------------------------------------- #
# Данные
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class NCAStatus:
    """Состояние локального сервиса подписи."""

    available: bool
    url: str
    latency_ms: float = 0.0
    error: str = ""


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """Информация о ключе/сертификате ЭЦП."""

    available: bool = False
    bin_iin: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    algorithm: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def fio(self) -> str:
        for part in self.subject.split(","):
            if part.strip().upper().startswith(("CN=", "G=")):
                return part.split("=", 1)[-1].strip()
        return self.subject

    def describe(self) -> str:
        bits = [self.bin_iin or "—", self.fio or "—"]
        if self.not_after:
            bits.append(f"до {self.not_after}")
        return " | ".join(bits)

    @classmethod
    def from_raw(cls, data: Any) -> KeyInfo:
        """Нормализует ответ NCALayer (basics/legacy) в KeyInfo."""
        if not isinstance(data, dict):
            return cls(available=bool(data), raw={"value": data})

        def pick(*names: str) -> str:
            for name in names:
                value = payload.get(name)
                if isinstance(value, (str, int)) and str(value).strip():
                    return str(value).strip()
            return ""

        # Вложенные структуры: {"keyInfo": {...}}, {"certificate": "-----BEGIN..."}
        payload = data
        for key in ("keyInfo", "key", "result", "certificateInfo"):
            nested = data.get(key)
            if isinstance(nested, dict):
                payload = {**data, **nested}
                break

        info = cls(
            available=True,
            bin_iin=pick(
                "binIin", "bin_iin", "iin", "bin", "binIIN", "iIN", "serialNumber"
            ),
            subject=pick(
                "subject", "subjectDN", "subjectDn", "distinguishedName", "owner"
            ),
            issuer=pick("issuer", "issuerDN", "issuerDn", "ca"),
            serial=pick("serialNumber", "serial", "sn"),
            not_before=pick("notBefore", "validFrom", "valid_from"),
            not_after=pick("notAfter", "validTo", "valid_to"),
            algorithm=pick("algorithm", "keyAlgorithm", "keyType"),
            raw=payload,
        )
        if info.bin_iin and not info.bin_iin.isdigit():
            # Иногда NCALayer возвращает строку со вставками — чистим до цифр
            digits = "".join(ch for ch in info.bin_iin if ch.isdigit())
            if len(digits) >= 12:
                info = replace(info, bin_iin=digits[:12])
        return info

    @classmethod
    def from_certificate(cls, cert: Any) -> KeyInfo:
        """Собирает KeyInfo напрямую из X.509 сертификата."""
        not_before = not_after = ""
        try:
            not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
            not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:  # pragma: no cover - разные версии cryptography
            with contextlib.suppress(Exception):  # старые API без _utc
                not_before = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
                not_after = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
        algorithm = ""
        with contextlib.suppress(Exception):  # не все сертификаты отдают алгоритм
            algorithm = cert.signature_hash_algorithm.name.upper()  # type: ignore[union-attr]
        from cryptography.hazmat.primitives import hashes as _hashes

        return cls(
            available=True,
            bin_iin=extract_bin_iin_from_certificate(cert),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial=str(cert.serial_number),
            not_before=not_before,
            not_after=not_after,
            algorithm=algorithm,
            raw={"fingerprint": cert.fingerprint(_hashes.SHA256()).hex()},
        )


class NCALayerError(RuntimeError):
    """Ошибка взаимодействия с NCALayer."""

    def __init__(
        self, message: str, code: str = "", details: str = "", canceled: bool = False
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details
        self.canceled = canceled

    @property
    def is_user_cancel(self) -> bool:
        if self.canceled:
            return True
        text = f"{self} {self.details}".lower()
        return any(word in text for word in ("cancel", "отмен", "прерван"))


class SecretPassword:
    """Пароль ЭЦП в оперативной памяти с затиранием при уничтожении."""

    __slots__ = ("_buf",)

    def __init__(self, value: str) -> None:
        self._buf = bytearray(value.encode("utf-8"))

    def reveal(self) -> str:
        return self._buf.decode("utf-8")

    @property
    def is_empty(self) -> bool:
        return not self._buf

    def wipe(self) -> None:
        for index in range(len(self._buf)):
            self._buf[index] = 0
        self._buf.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.wipe()

    def __del__(self) -> None:  # pragma: no cover - best effort
        # Затирание при сборке мусора — намеренно тихое: __del__ не должен
        # бросать исключений.
        with contextlib.suppress(Exception):
            self.wipe()

    def __repr__(self) -> str:
        return "SecretPassword(***)"

    __str__ = __repr__


@dataclass(slots=True)
class SignItem:
    """Единица работы для пакетной подписи.

    Либо ``path`` (файл на диске), либо ``data`` (сгенерированный в памяти
    документ) — ровно один из двух должен быть задан.
    """

    key: str
    label: str = ""
    path: Path | None = None
    data: bytes | None = None
    mode: SignMode = SignMode.CMS
    content_type: str = "application/octet-stream"

    def load(self) -> bytes:
        if self.data is not None:
            return self.data
        if self.path is not None:
            return self.path.read_bytes()
        raise ValueError(f"SignItem({self.key}): не задан ни path, ни data")

    @property
    def file_name(self) -> str:
        if self.path is not None:
            return self.path.name
        return f"{self.key}.bin"


@dataclass(frozen=True, slots=True)
class SignedDocument:
    """Подписанный документ, готовый к загрузке на портал."""

    key: str
    file_name: str
    sha256: str
    size: int
    content_b64: str
    signature_b64: str
    sign_ms: float
    from_batch: bool
    content_type: str = "application/octet-stream"

    @property
    def has_signature(self) -> bool:
        return bool(self.signature_b64)


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(text: str) -> bytes:
    return base64.b64decode(text)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------------------------- #
# Разбор сертификата ЭЦП
# --------------------------------------------------------------------------- #
# 12 цифр БИН/ИИН; допускаем префикс IIN/BIN, приклеенный к номеру
# (настоящие сертификаты НУЦ: SERIALNUMBER=IIN123456789012, OU=BIN…).
_BIN_IIN_RE = r"(?<![0-9])(?:IIN|BIN)?([0-9]{12})(?![0-9])"
_BIN_IIN_MARKED_RE = r"(?:IIN|BIN)\s*[:=]?\s*[0-9]{12}"


def extract_bin_iin_from_certificate(cert: Any) -> str:
    """Достаёт БИН/ИИН (12 цифр) из сертификата ЭЦП РК.

    Сертификаты НУЦ РК держат БИН/ИИН в атрибуте ``serialNumber`` (``SN``) с
    префиксом ``IIN``/``BIN`` (профиль сертификата npck.kz) либо в
    пользовательских OID ветки 1.2.398.3.3.4. Перебираем значения subject,
    SubjectAlternativeName и расширений. Приоритет: значения с явной меткой
    IIN/BIN → OID ветки РК → общий перебор (защита от «случайных» 12 цифр
    вроде телефона в CN).
    """
    import re

    candidates: list[str] = []
    try:
        rfc_rdns = getattr(cert.subject, "rdns", None)
        if rfc_rdns is not None:
            for rdn in rfc_rdns:
                for attribute in rdn:
                    candidates.append(str(attribute.value))
                    candidates.append(str(getattr(attribute, "oid", "")))
        else:  # pragma: no cover - старые версии cryptography
            candidates.append(str(cert.subject))

        with contextlib.suppress(Exception):  # SAN может отсутствовать
            from cryptography import x509 as _x509

            san = cert.extensions.get_extension_for_class(
                _x509.SubjectAlternativeName,
            ).value
            for entry in san:
                candidates.append(str(getattr(entry, "value", entry)))

        for extension in cert.extensions:
            with contextlib.suppress(Exception):  # нестандартные расширения
                candidates.append(str(extension.value))
    except Exception:  # pragma: no cover - защита от нестандартных сертификатов
        return ""

    def first_match(text: str) -> str:
        match = re.search(_BIN_IIN_RE, text, re.IGNORECASE)
        return match.group(1) if match else ""

    # 1) Явно помеченные значения (IIN…/BIN… — префикс или «метка=номер»).
    for value in candidates:
        text = str(value)
        if re.search(_BIN_IIN_MARKED_RE, text, re.IGNORECASE):
            found = first_match(text)
            if found:
                return found
    # 2) OID ветки РК (там лежит БИН/ИИН ЮЛ).
    for value in candidates:
        text = str(value)
        if "1.2.398" in text and "=" in text:
            found = first_match(text.split("=", 1)[-1])
            if found:
                return found
    # 3) Общий перебор.
    for value in candidates:
        found = first_match(str(value))
        if found:
            return found
    return ""


def certificates_from_cms(der: bytes) -> list[Any]:
    """Извлекает сертификаты из CMS/PKCS7 (DER) подписи NCALayer."""
    from cryptography.hazmat.primitives.serialization import pkcs7

    try:
        return list(pkcs7.load_der_pkcs7_certificates(der))
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Клиент NCALayer
# --------------------------------------------------------------------------- #
class NCALayerClient:
    """Асинхронный клиент NCALayer с пакетной подписью.

    Один экземпляр — один WebSocket. Вызовы сериализуются внутренним локом,
    поэтому ``recv()`` всегда соответствует отправленному запросу.
    """

    def __init__(
        self,
        settings: NCALayerSettings | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.settings = settings or NCALayerSettings()
        self.log = logger or get_logger("ncalayer")
        self._ws: ClientConnection | None = None
        self._ws_module: str = ""
        self._connect_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._greeting: dict[str, Any] | None = None
        self._request_seq = 0
        # Защита от рассинхрона «документ получил чужую подпись»: помним,
        # какая подпись какому документу уже досталась (последние 256).
        self._seen_signatures: dict[str, str] = {}
        self.stats: dict[str, int] = {
            "calls": 0,
            "batches": 0,
            "signatures": 0,
            "errors": 0,
            "reconnects": 0,
        }

    # -- жизненный цикл ----------------------------------------------------- #
    async def probe(self) -> NCAStatus:
        """Быстрая проверка: открыт ли порт NCALayer (без WS-рукопожатия)."""
        started = time.perf_counter()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.settings.host, self.settings.port),
                timeout=self.settings.probe_timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency = (time.perf_counter() - started) * 1000.0
            return NCAStatus(True, self.settings.basics_url, latency)
        except Exception as exc:
            return NCAStatus(False, self.settings.basics_url, 0.0, str(exc))

    @property
    def connected(self) -> bool:
        return self._ws is not None

    @property
    def greeting(self) -> dict[str, Any] | None:
        return self._greeting

    def _module_url(self, module: str) -> str:
        return (
            self.settings.legacy_url if module == "legacy" else self.settings.basics_url
        )

    async def connect(self, module: str = "basics") -> ClientConnection:
        """Открывает WebSocket к модулю NCALayer и съедает приветствие сервиса.

        Настоящий NCALayer требует TLS (wss) и использует локальный
        самоподписанный сертификат — доверяем ему (это локальный сервис НУЦ РК
        на 127.0.0.1, митм-захват неприменим по смыслу).
        """
        async with self._connect_lock:
            if self._ws is not None:
                if self._ws_module == module:
                    return self._ws
                # Соединение открыто к другому модулю (у каждого модуля свой
                # WS-путь) — переподключаемся, иначе запрос уйдёт не туда.
                await self._close_ws()
            url = self._module_url(module)
            self.log.debug("Подключение к NCALayer: %s", url)
            connect_kwargs: dict[str, Any] = {
                "open_timeout": self.settings.probe_timeout * 5,
                "ping_interval": self.settings.keep_alive_ping,
                "max_size": None,
                "close_timeout": 2,
            }
            # NCALayer — локальный сервис; ЛЮБОЕ подключение к нелокальному
            # хосту запрещено (ws без TLS на чужом хосте = MITM читает всё,
            # включая подписываемые документы и пароль).
            if self.settings.host not in LOOPBACK_HOSTS:
                raise NCALayerError(
                    f"NCALayer должен работать на локальном адресе, а не на "
                    f"«{self.settings.host}»: подключение к удалённому хосту "
                    "запрещено (127.0.0.1/::1/localhost — единственные "
                    "допустимые)",
                    code="NCA_NOT_LOOPBACK",
                )
            if url.startswith("wss://"):
                import ssl as _ssl

                # Самоподписанный сертификат допустим только для локального
                # сервиса НУЦ РК. На любом другом хосте отключённая проверка
                # TLS открыла бы MITM — такое подключение запрещено.
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                connect_kwargs["ssl"] = ctx
            ws = await websockets.connect(url, **connect_kwargs)
            self._ws = ws
            self._ws_module = module
            self._greeting = await self._read_greeting(ws)
            self.log.info("NCALayer подключён: %s", url)
            return ws

    async def _read_greeting(self, ws: ClientConnection) -> dict[str, Any] | None:
        """NCALayer при подключении сам присылает приветствие/версию."""
        for _ in range(3):
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=0.5)
            except TimeoutError:
                return None
            except Exception:
                return None
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if isinstance(payload, dict):
                return payload
        return None

    async def _close_ws(self) -> None:
        """Закрывает текущий сокет без взятия локов (вызывать под _connect_lock)."""
        ws, self._ws = self._ws, None
        self._ws_module = ""
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
            self.log.debug("Соединение с NCALayer закрыто")

    async def close(self) -> None:
        """Закрывает соединение (безопасно вызывать многократно)."""
        async with self._connect_lock:
            await self._close_ws()

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # -- RPC ---------------------------------------------------------------- #
    def _envelope(self, module: str, method: str, args: Any) -> dict[str, Any]:
        """Конверт запроса NCALayer: {"module", "method", "args", "id"}."""
        self._request_seq += 1
        module_name = (
            self.settings.module_basics
            if module == "basics"
            else self.settings.module_legacy
        )
        return {
            "module": module_name,
            "method": method,
            "args": args,
            "id": self._request_seq,
        }

    async def _rpc(
        self, request: dict[str, Any], timeout: float, module: str = "basics"
    ) -> Any:
        """Отправляет запрос и разбирает ответ (basics либо legacy-конверт)."""
        async with self._send_lock:
            try:
                await self.connect(module)
            except Exception as exc:
                # Сюда попадают проблемы подключения (NCALayer не запущен,
                # порт занят, TLS-несовместимость) — оборачиваем понятным
                # сообщением, чтобы в GUI не всплывало сырое исключение.
                self.stats["errors"] += 1
                raise NCALayerError(
                    "NCALayer недоступен. Убедитесь, что он запущен "
                    f"({self.settings.host}:{self.settings.port}), затем повторите.",
                    code="NCA_UNAVAILABLE",
                    details=str(exc),
                ) from exc
            assert self._ws is not None
            self.stats["calls"] += 1
            try:
                await self._ws.send(json.dumps(request, ensure_ascii=False))
                raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
            except asyncio.CancelledError:
                # Отмена задачи (lock, disarm, закрытие окна) ОБЯЗАНА сбросить
                # сокет: CancelledError — BaseException и общим except Exception
                # не ловится, из-за чего запоздавший ответ доставался следующему
                # запросу и документ получал чужую подпись.
                self.stats["errors"] += 1
                await self._reset()
                raise
            except TimeoutError as exc:
                self.stats["errors"] += 1
                # Сокет обязательно сбрасываем: запоздавший ответ NCALayer иначе
                # был бы прочитан как ответ на СЛЕДУЮЩИЙ запрос (рассинхрон
                # запрос/ответ → чужая подпись в чужом документе).
                await self._reset()
                raise NCALayerError(
                    "NCALayer не ответил за отведённое время",
                    details=f"timeout={timeout}s",
                ) from exc
            except Exception as exc:
                self.stats["errors"] += 1
                await self._reset()
                raise NCALayerError(f"Соединение с NCALayer потеряно: {exc}") from exc
            expected_id = request.get("id")
            try:
                response = self._parse_response(raw)
                if (
                    expected_id is not None
                    and isinstance(response, dict)
                    and response.get("id") not in (None, expected_id)
                ):
                    raise NCALayerError(
                        "NCALayer ответил на другой запрос (id не совпал)",
                        code="NCA_DESYNC",
                    )
            except Exception:
                # Некорректный или чужой ответ тоже рассинхронизирует поток.
                await self._reset()
                raise
            return response

    async def _reset(self) -> None:
        self.stats["reconnects"] += 1
        try:
            await self.close()
        except Exception:
            pass

    def _check_signature_owner(self, key: str, signature_b64: str) -> None:
        """Защита от рассинхрона: одна подпись не принадлежит двум документам.

        При рассинхроне запрос/ответ документ B мог получить подпись документа
        A. Такой случай фиксируется и поднимается — отправлять на портал
        чужую подпись нельзя.
        """
        if not signature_b64:
            return
        previous = self._seen_signatures.get(signature_b64)
        if previous is not None and previous != key:
            self.stats["errors"] += 1
            raise NCALayerError(
                "Обнаружен рассинхрон подписи: документ получил чужую подпись",
                code="NCA_SIGNATURE_DESYNC",
                details=f"«{key}» унаследовал подпись «{previous}»",
            )
        if previous is None:
            self._seen_signatures[signature_b64] = key
            if len(self._seen_signatures) > 256:
                # ограничиваем память: удаляем самые старые записи
                for stale in list(self._seen_signatures)[:-128]:
                    self._seen_signatures.pop(stale, None)

    def _parse_response(self, raw: str | bytes) -> Any:
        try:
            response = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise NCALayerError("Некорректный ответ NCALayer") from exc
        if not isinstance(response, dict):
            raise NCALayerError("Неожиданный формат ответа NCALayer")

        # --- новый модуль kz.gov.pki.knca.basics ---
        if "status" in response:
            if not response.get("status"):
                raise NCALayerError(
                    str(response.get("message") or "ошибка NCALayer"),
                    code=str(response.get("code", "")),
                    details=str(response.get("details", "")),
                )
            body = response.get("body") or {}
            if not isinstance(body, dict) or "result" not in body:
                raise NCALayerError("Операция отменена пользователем", canceled=True)
            return body["result"]

        # --- старый модуль kz.gov.pki.knca (commonUtils) ---
        code = str(response.get("code", "200"))
        if code != "200":
            raise NCALayerError(
                str(response.get("message", "ошибка NCALayer")),
                code=code,
            )
        return response.get("responseObject")

    # -- информация о ключе -------------------------------------------------- #
    async def get_key_info(self, timeout: float | None = None) -> KeyInfo:
        """Возвращает БИН/ИИН и данные сертификата активного ключа ЭЦП."""
        timeout = timeout or max(self.settings.rpc_timeout, 5.0)
        args = {
            "allowedStorages": list(self.settings.allowed_storages),
            "locale": self.settings.locale,
        }
        errors: list[str] = []
        for module, method_args in (("basics", args), ("legacy", [])):
            try:
                result = await self._rpc(
                    self._envelope(module, "getKeyInfo", method_args),
                    timeout,
                    module,
                )
                info = KeyInfo.from_raw(result)
                if info.available:
                    return info
            except NCALayerError as exc:
                errors.append(f"{module}: {exc}")
                self.log.debug("getKeyInfo через %s недоступен: %s", module, exc)
        self.log.warning("Не удалось получить данные ключа ЭЦП (%s)", "; ".join(errors))
        return KeyInfo(available=False, raw={"errors": errors})

    # -- подпись ------------------------------------------------------------- #
    async def sign_cms_batch(
        self,
        items: Iterable[SignItem],
        password: SecretPassword | None = None,
        batch: bool = True,
        timeout: float | None = None,
    ) -> list[SignedDocument]:
        """Подписывает НАБОР документов. Пакетно — один вызов = один диалог.

        Соответствует возможностям ``kz.gov.pki.knca.basics``: ``args.data``
        принимает МАССИВ base64-документов, поэтому весь пакет уходит одной
        операцией ``sign``. Если установлен старый NCALayer, который массив не
        принимает, включается ``batch_fallback_sequential``, и документы
        подписываются по одному (единственный сценарий с несколькими диалогами).
        """
        work_items = [item for item in items if item.mode is not SignMode.NONE]
        if not work_items:
            return []

        timeout = timeout or (
            self.settings.sign_batch_timeout
            if len(work_items) > 1
            else self.settings.sign_timeout
        )
        if batch and self.settings.batch_in_single_request:
            try:
                docs = await self._sign_batch(work_items, password, timeout)
                self.stats["batches"] += 1
                self.stats["signatures"] += len(docs)
                self.log.info(
                    "Пакетная подпись ЭЦП: %d документ(ов) одним вызовом NCALayer",
                    len(docs),
                )
                return docs
            except NCALayerError as exc:
                if exc.is_user_cancel or not self.settings.batch_fallback_sequential:
                    raise
                self.log.warning(
                    "Пакетный вызов отклонён NCALayer (%s) — перехожу к "
                    "последовательной подписи",
                    exc,
                )
        return await self._sign_sequential(work_items, password, timeout)

    # -- внутренняя механика подписи ----------------------------------------- #
    def _build_sign_args(
        self, datas: list[str] | str, fmt: str, password: SecretPassword | None
    ) -> dict[str, Any]:
        """Собирает args для метода ``sign`` модуля kz.gov.pki.knca.basics."""
        signing_params: dict[str, Any] = {
            "decode": bool(self.settings.cms_decode) if fmt == "cms" else False,
            "encapsulate": bool(self.settings.cms_encapsulate),
            "digested": False,
        }
        if self.settings.tsa_profile:
            signing_params["tsaProfile"] = {}
        signer_params: dict[str, Any] = {
            "extKeyUsageOids": list(self.settings.ext_key_usage_oids),
        }
        if (
            password is not None
            and not password.is_empty
            and self.settings.pass_password
        ):
            # НУЦ РК не документирует поле пароля: сервис, который его не знает,
            # просто проигнорирует лишний ключ. Диалог всё равно один — на пакет.
            signer_params["password"] = password.reveal()
        args: dict[str, Any] = {
            "allowedStorages": list(self.settings.allowed_storages),
            "format": fmt,
            "data": datas,
            "signingParams": signing_params,
            "signerParams": signer_params,
            "locale": self.settings.locale,
        }
        # Режим директора: ключ выбирается автоматически (без диалога выбора).
        if self.settings.auto_sign and self.settings.key_alias:
            args["keyAlias"] = self.settings.key_alias
        return args

    async def _load_contents(
        self,
        items: Sequence[SignItem],
    ) -> list[tuple[SignItem, bytes]]:
        """Читает файлы параллельно, не блокируя event loop."""
        contents = await asyncio.gather(
            *[asyncio.to_thread(item.load) for item in items],
        )
        return list(zip(items, contents, strict=True))

    async def _sign_batch(
        self, items: Sequence[SignItem], password: SecretPassword | None, timeout: float
    ) -> list[SignedDocument]:
        """Одна операция sign на всю пачку — один системный диалог."""
        started = time.perf_counter()
        loaded = await self._load_contents(items)
        fmt = "xml" if all(item.mode is SignMode.XML for item, _ in loaded) else "cms"
        args = self._build_sign_args(
            [b64encode(raw) for _, raw in loaded], fmt, password
        )
        result = await self._rpc(
            self._envelope("basics", "sign", args),
            timeout,
            "basics",
        )
        signatures = self._extract_signatures(result, len(loaded))
        for (item, _raw), signature in zip(loaded, signatures, strict=True):
            self._check_signature_owner(item.key, signature)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        per_doc_ms = elapsed_ms / max(len(loaded), 1)
        documents: list[SignedDocument] = []
        for (item, raw), signature in zip(loaded, signatures, strict=True):
            documents.append(
                SignedDocument(
                    key=item.key,
                    file_name=item.file_name,
                    sha256=sha256_hex(raw),
                    size=len(raw),
                    content_b64=b64encode(raw),
                    signature_b64=signature,
                    sign_ms=round(per_doc_ms, 1),
                    from_batch=True,
                    content_type=item.content_type,
                )
            )
        return documents

    async def _sign_sequential(
        self, items: Sequence[SignItem], password: SecretPassword | None, timeout: float
    ) -> list[SignedDocument]:
        """Резервный путь для старого NCALayer: документ за документом."""
        documents: list[SignedDocument] = []
        for item in items:
            started = time.perf_counter()
            raw = await asyncio.to_thread(item.load)
            fmt = "xml" if item.mode is SignMode.XML else "cms"
            args = self._build_sign_args(b64encode(raw), fmt, password)
            result = await self._rpc(
                self._envelope("basics", "sign", args),
                timeout,
                "basics",
            )
            signature = self._extract_signatures(result, 1)[0]
            self._check_signature_owner(item.key, signature)
            self.stats["signatures"] += 1
            documents.append(
                SignedDocument(
                    key=item.key,
                    file_name=item.file_name,
                    sha256=sha256_hex(raw),
                    size=len(raw),
                    content_b64=b64encode(raw),
                    signature_b64=signature,
                    sign_ms=round((time.perf_counter() - started) * 1000.0, 1),
                    from_batch=False,
                    content_type=item.content_type,
                )
            )
        return documents

    @staticmethod
    def _extract_signatures(result: Any, expected: int) -> list[str]:
        """Приводит результат подписи к списку base64-подписей.

        Разные сборки NCALayer возвращают разный формат: строку, список строк,
        список объектов ``{"fileName", "signature"}`` или объект со списком
        ``signatures``. Обрабатываем все варианты.
        """

        def coerce(entry: Any) -> str:
            if isinstance(entry, str):
                return entry
            if isinstance(entry, (bytes, bytearray)):
                return bytes(entry).decode("ascii", "replace")
            if isinstance(entry, dict):
                for key in (
                    "signature",
                    "cms",
                    "signatureBase64",
                    "base64",
                    "signedData",
                    "value",
                    "data",
                    "result",
                ):
                    value = entry.get(key)
                    if isinstance(value, str):
                        return value
            return ""

        if isinstance(result, list):
            candidates: list[Any] = list(result)
        elif isinstance(result, dict):
            nested: list[Any] | None = None
            for key in ("signatures", "results", "signedDocuments", "items", "data"):
                value = result.get(key)
                if isinstance(value, list):
                    nested = list(value)
                    break
            candidates = nested if nested is not None else [result]
        elif result:
            candidates = [result]
        else:
            candidates = []

        signatures = [sig for sig in (coerce(entry) for entry in candidates) if sig]
        if len(signatures) != expected:
            raise NCALayerError(
                "NCALayer вернул неожиданное число подписей",
                details=f"expected={expected}, got={len(signatures)}",
            )
        return signatures


def make_items(paths: Iterable[Path], mode: SignMode = SignMode.CMS) -> list[SignItem]:
    """Утилита: собирает SignItem'ы из путей (key = имя файла без расширения)."""
    items: list[SignItem] = []
    for path in paths:
        resolved = Path(path)
        items.append(
            SignItem(
                key=resolved.stem,
                label=resolved.name,
                path=resolved,
                mode=mode,
            )
        )
    return items


__all__ = [
    "KeyInfo",
    "NCALayerClient",
    "NCALayerError",
    "NCAStatus",
    "SecretPassword",
    "SignItem",
    "SignedDocument",
    "b64decode",
    "b64encode",
    "certificates_from_cms",
    "extract_bin_iin_from_certificate",
    "make_items",
    "sha256_hex",
]
