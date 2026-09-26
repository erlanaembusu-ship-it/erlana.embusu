"""Локальный эмулятор портала и NCALayer для автономного тестирования.

Зачем нужен
-----------
Полный цикл подачи нельзя отлаживать «на живом» портале по каждой правке.
Этот модуль поднимает два локальных сервиса:

* ``MockPortal`` — HTTP-сервер на ``127.0.0.1:8643``, повторяющий контракт
  портала: GraphQL-реестр лотов (``POST /v3/graphql``), challenge/логин по ЭЦП,
  keep-alive, загрузку вложений, submit с ключом идемпотентности и проверку
  факта подачи. Приём заявок открывается ровно в ``TrdBuy.startDate`` — до этого
  submit возвращает ``425 Too Early``, как и настоящий портал.
* ``MockNCALayer`` — WebSocket-сервер на ``127.0.0.1:13580``, повторяющий
  интерфейс модуля ``kz.gov.pki.knca.basics`` (``getKeyInfo`` и ``sign``,
  включая ПАКЕТНУЮ подпись массивом ``data``). Подписи — настоящие CMS
  (PKCS#7) на реальном ключе RSA и самоподписанном сертификате с БИН/ИИН,
  поэтому и портал-мок, и конвейер работают с реальной криптографией.

Зависимостей сверх проекта нет: HTTP-сервер написан на ``asyncio``, а CMS
строится средствами ``cryptography``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import hashlib
import json
import logging
import math
import re
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier

from utils.logger import get_logger

__all__ = [
    "MockNCALayer",
    "MockPortal",
    "MockServers",
    "cms_content",
    "cms_verify_signature",
    "make_test_certificate",
    "run_servers",
]

# БИН/ИИН, «зашитый» в тестовый сертификат
TEST_BIN = "123456789012"
TEST_SUBJECT_CN = "TEST SUPPLIER TOO"
OID_KZ_BIN = ObjectIdentifier("1.2.398.3.3.4.1.1")


# --------------------------------------------------------------------------- #
# Минимальный разбор DER/CMS
# --------------------------------------------------------------------------- #
def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(data: bytes, index: int) -> tuple[int, bytes, int]:
    """Читает один TLV: возвращает (тег, значение, следующий индекс)."""
    if index >= len(data):
        raise ValueError("DER: конец данных")
    tag = data[index]
    index += 1
    length = data[index]
    index += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[index : index + count], "big")
        index += count
    value = data[index : index + length]
    if len(value) != length:
        raise ValueError("DER: усечённое значение")
    return tag, value, index + length


def _der_full(tag: int, content: bytes) -> bytes:
    """Собирает полный TLV (тег + длина + содержимое) из разобранного элемента."""
    return bytes([tag]) + _der_length(len(content)) + content


def _der_children(value: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    index = 0
    while index < len(value):
        tag, child, index = _der_tlv(value, index)
        children.append((tag, child))
    return children


def _unwrap_tlv(data: bytes) -> bytes:
    """Снимает внешний TLV-конверт и возвращает его содержимое.

    Нужно для конструкций вида ``[0] EXPLICIT SignedData``: значением тега
    ``[0]`` является ПОЛНЫЙ TLV SignedData, а не его содержимое.
    """
    _tag, value, end = _der_tlv(data, 0)
    if end != len(data):
        raise ValueError("DER: неожиданные данные внутри контейнера")
    return value


def cms_content(der: bytes) -> bytes:
    """Возвращает встроенное содержимое CMS (encapContentInfo.eContent)."""
    tag, content_info, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("CMS: ожидался SEQUENCE ContentInfo")
    children = _der_children(content_info)
    if len(children) < 2:
        raise ValueError("CMS: нет [0] content")
    signed_data = _unwrap_tlv(children[1][1])
    sd_children = _der_children(signed_data)
    if len(sd_children) < 3:
        raise ValueError("CMS: некорректный SignedData")
    encap = sd_children[2][1]
    encap_children = _der_children(encap)
    if len(encap_children) < 2:
        raise ValueError("CMS: подпись detached — содержимого нет")
    # encapContentInfo.eContent — это [0] EXPLICIT OCTET STRING: внутрь тега
    # вложен ПОЛНЫЙ TLV OCTET STRING, поэтому его содержимое достаём напрямую
    _octet_tag, payload, _end = _der_tlv(encap_children[1][1], 0)
    return payload


def cms_verify_signature(der: bytes) -> tuple[bool, x509.Certificate | None, str]:
    """Проверяет подпись CMS по встроенному сертификату.

    Разбирает ``SignerInfo`` и проверяет RSA-PKCS1v15 по перекодированным
    ``signedAttrs`` (тег SET OF) — стандартная процедура проверки CMS/PKCS#7.
    Возвращает ``(ok, сертификат, пояснение)``.
    """
    try:
        _tag, content_info, _ = _der_tlv(der, 0)
        children = _der_children(content_info)
        signed_data = _unwrap_tlv(children[1][1])
        sd = _der_children(signed_data)
        certificates: list[x509.Certificate] = []
        signer_infos: bytes = b""
        for tag, value in sd[3:]:
            if tag == 0xA0:  # [0] IMPLICIT SET OF Certificate
                for cert_tag, cert_content in _der_children(value):
                    if cert_tag == 0x30:
                        with contextlib.suppress(Exception):
                            certificates.append(
                                x509.load_der_x509_certificate(
                                    _der_full(cert_tag, cert_content),
                                )
                            )
            elif tag == 0xA1:
                continue
            elif tag == 0x31:  # signerInfos (SET OF SignerInfo)
                signer_infos = value
        if not signer_infos or not certificates:
            return False, None, "CMS: нет подписанта или сертификата"

        signer_info = _der_children(signer_infos)[0][1]
        signed_attrs: bytes | None = None
        signature = b""
        for tag, value in _der_children(signer_info):
            if tag == 0xA0:
                signed_attrs = value
            elif tag == 0x04 and len(value) > 8:
                signature = value
        if signed_attrs is None or not signature:
            return False, None, "CMS: нет signedAttrs или подписи"

        to_verify = b"\x31" + _der_length(len(signed_attrs)) + signed_attrs
        certificate = certificates[0]
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):  # pragma: no cover
            return False, certificate, "CMS: неподдерживаемый алгоритм ключа"
        public_key.verify(signature, to_verify, padding.PKCS1v15(), hashes.SHA256())
        return True, certificate, "ok"
    except Exception as exc:
        return False, None, f"CMS: ошибка проверки ({exc})"


def make_test_certificate(
    bin_iin: str = TEST_BIN,
    cn: str = TEST_SUBJECT_CN,
    days: int = 365,
    iin: str = "880101300123",
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Создаёт ключ и самоподписанный сертификат, похожий на ЭЦП РК.

    Subject как у сертификата ЮЛ от НУЦ РК: ``SERIALNUMBER=IIN<ИИН сотрудника>``
    и ``OU=BIN<БИН организации>``. Парсер БИН в ядре обязан вернуть именно
    ``bin_iin`` (БИН), а не ИИН сотрудника.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, f"IIN{iin}"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"BIN{bin_iin}"),
        ]
    )
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


# --------------------------------------------------------------------------- #
# HTTP-примитивы (минимальный, но корректный HTTP/1.1)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class HttpRequest:
    method: str
    path: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw_target: str = ""

    @property
    def json(self) -> Any:
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return {}

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def http_date() -> str:
    """HTTP-дата в формате RFC 1123 (нужна клиенту для синхронизации часов)."""
    now = dt.datetime.now(dt.timezone.utc)
    return now.strftime("%a, %d %b %Y %H:%M:%S GMT")


class HttpConnection:
    """Обёртка над reader/writer: чтение запроса и отправка ответа."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        logger: logging.Logger,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.log = logger
        self.closed = False

    async def read_request(
        self, max_body: int = 64 * 1024 * 1024
    ) -> HttpRequest | None:
        try:
            request_line = await asyncio.wait_for(
                self.reader.readline(),
                timeout=60,
            )
        except TimeoutError:
            return None
        if not request_line:
            return None
        try:
            text = request_line.decode("latin-1").strip()
        except Exception:
            return None
        parts = text.split()
        if len(parts) < 3:
            return None
        method, target, _version = parts[0], parts[1], parts[2]

        headers: dict[str, str] = {}
        while True:
            line = await self.reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            try:
                key, _, value = line.decode("latin-1").partition(":")
            except Exception:
                continue
            headers[key.strip().lower()] = value.strip()

        body = b""
        length = int(headers.get("content-length") or 0)
        if length > 0:
            length = min(length, max_body)
            body = await self.reader.readexactly(length)

        path, _, query_string = target.partition("?")
        query: dict[str, str] = {}
        for pair in query_string.split("&"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            query[key] = value
        return HttpRequest(
            method=method.upper(),
            path=path,
            query=query,
            headers=headers,
            body=body,
            raw_target=target,
        )

    async def send(
        self,
        status: int,
        body: bytes,
        content_type: str = "application/json; charset=utf-8",
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        reason = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            409: "Conflict",
            425: "Too Early",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }.get(status, "OK")
        headers = {
            "Date": http_date(),
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "keep-alive",
            "Server": "FastBidMock/1.0",
        }
        if extra_headers:
            headers.update({key: str(value) for key, value in extra_headers.items()})
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in headers.items())
            + "\r\n"
        )
        self.writer.write(head.encode("latin-1") + body)
        try:
            await self.writer.drain()
        except Exception:
            self.closed = True

    async def send_json(
        self, status: int, payload: Any, extra_headers: Mapping[str, str] | None = None
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        await self.send(status, body, extra_headers=extra_headers)

    def close(self) -> None:
        self.closed = True
        with contextlib.suppress(Exception):
            self.writer.close()


# --------------------------------------------------------------------------- #
# Модель лота
# --------------------------------------------------------------------------- #
PORTAL_TZ = dt.timezone(dt.timedelta(hours=5))  # Asia/Almaty, UTC+5 без переходов


@dataclass
class MockLot:
    """Лот, который отдаёт «реестр». T0 = TrdBuy.startDate."""

    id: int = 777_001
    lot_number: str = "38876543-ОИ1"
    name: str = "Мясо говядина — поставка продуктов питания"
    description: str = "Поставка продуктов питания для нужд заказчика (тестовый лот)"
    amount: float = 4_500_000.0
    count: float = 120.0
    trd_buy_id: int = 555_001
    trd_buy_number: str = "12345678-1"
    customer_bin: str = "990140001234"
    customer_name: str = "ГУ «Тестовый заказчик»"
    kato: list[str] = field(default_factory=lambda: ["750000000"])
    status_id: int = 210
    status_name: str = "Опубликован"
    status_code: str = "PUBLISHED"
    buy_status_id: int = 220
    buy_status_name: str = "Опубликовано"
    # Через сколько секунд от старта мока открывается приём заявок
    open_after_s: float = 12.0
    window_s: float = 3600.0
    auto_open: bool = True
    # Не отдавать startDate (проверка работы по статусу при неизвестном T0).
    hide_start_date: bool = False
    start_epoch: float = 0.0

    # -- расписание --------------------------------------------------------- #
    def schedule(self, delay_s: float | None = None) -> None:
        """Перепланирует T0: ``delay_s`` секунд от текущего момента.

        start_epoch выравнивается вверх до целой секунды: реальный портал
        отдаёт startDate посекундно (``_fmt``), а дробные миллисекунды здесь
        означали бы «объявленный T0 наступил, а лот ещё закрыт» — до 1 с.
        """
        delay = self.open_after_s if delay_s is None else delay_s
        self.start_epoch = float(math.ceil(time.time() + float(delay)))
        self.status_id = 210
        self.status_name = "Опубликован"
        self.status_code = "PUBLISHED"

    def ensure_scheduled(self) -> None:
        if self.start_epoch <= 0:
            self.schedule(self.open_after_s)

    def now(self) -> float:
        return time.time()

    def is_open(self) -> bool:
        return self.now() >= self.start_epoch

    def refresh(self) -> None:
        """Переводит лот в «приём заявок», когда наступает startDate."""
        self.ensure_scheduled()
        if self.auto_open and self.is_open():
            self.status_id = 220
            self.status_name = "Прием заявок"
            self.status_code = "ACCEPTING"

    # -- сериализация ------------------------------------------------------- #
    def _fmt(self, epoch: float) -> str:
        return dt.datetime.fromtimestamp(epoch, PORTAL_TZ).strftime("%Y-%m-%d %H:%M:%S")

    def to_node(self) -> dict[str, Any]:
        """Узел ``Lots`` в терминах GraphQL v3."""
        self.refresh()
        start = "" if self.hide_start_date else self._fmt(self.start_epoch)
        end = self._fmt(self.start_epoch + self.window_s)
        return {
            "id": self.id,
            "lotNumber": self.lot_number,
            "nameRu": self.name,
            "nameKz": self.name,
            "descriptionRu": self.description,
            "descriptionKz": self.description,
            "amount": self.amount,
            "count": self.count,
            "refLotStatusId": self.status_id,
            "lastUpdateDate": self._fmt(self.now()),
            "unionLots": 0,
            "dumping": 0,
            "isConstructionWork": 0,
            "customerBin": self.customer_bin,
            "customerId": 1001,
            "customerNameRu": self.customer_name,
            "trdBuyId": self.trd_buy_id,
            "trdBuyNumberAnno": self.trd_buy_number,
            "plnPointKatoList": list(self.kato),
            "enstruList": [151110],
            "RefLotsStatus": {
                "id": self.status_id,
                "nameRu": self.status_name,
                "nameKz": self.status_name,
                "code": self.status_code,
            },
            "TrdBuy": {
                "id": self.trd_buy_id,
                "numberAnno": self.trd_buy_number,
                "nameRu": self.name,
                "totalSum": self.amount * 3,
                "countLots": 3,
                "refTradeMethodsId": 6,
                "refBuyStatusId": self.buy_status_id,
                "startDate": start,
                "endDate": end,
                "repeatStartDate": "",
                "repeatEndDate": "",
                "publishDate": start,
                "customerBin": self.customer_bin,
                "customerNameRu": self.customer_name,
                "RefBuyStatus": {
                    "id": self.buy_status_id,
                    "nameRu": self.buy_status_name,
                    "nameKz": self.buy_status_name,
                    "code": "PUBLISHED",
                },
            },
        }

    def fingerprint(self) -> str:
        """Отпечаток для ETag: меняется при смене статуса или перепланировании."""
        self.refresh()
        material = (
            f"{self.id}|{self.status_id}|{self.status_code}|{int(self.start_epoch)}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Mock-портал
# --------------------------------------------------------------------------- #
class MockPortal:
    """HTTP-заглушка портала: реестр + кабинет + контроль поведения."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8643,
        lot: MockLot | None = None,
        latency_ms: float = 0.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.log = logger or get_logger("mock.portal")
        self.lot = lot or MockLot()
        self.latency_ms = latency_ms
        self.attachments: dict[str, dict[str, Any]] = {}
        self.bids: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.challenges: dict[str, float] = {}
        self.counters: dict[str, int] = {}
        # Управляемые «поломки» для проверки устойчивости клиента
        self.forced: dict[str, Any] = {
            "unauthorized_pings": 0,  # сколько следующих ping вернут 401
            "fail_next_submit": 0,  # сколько следующих submit вернут 500
            # сколько следующих submit ПРИМУТ заявку, но вернут 500 (потерянный
            # ответ: проверка verify-перед-повтором)
            "accept_then_fail_submits": 0,
            "reject_all_submits": False,  # всегда отклонять подачу
            "idempotency_mode": "dedupe",  # dedupe | conflict
            "submit_delay_ms": 0.0,  # искусственная задержка submit
        }
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[asyncio.Task[Any]] = set()
        self.running = False

    # -- жизненный цикл ----------------------------------------------------- #
    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> MockPortal:
        self.lot.ensure_scheduled()
        self._server = await asyncio.start_server(
            self._client_connected,
            self.host,
            self.port,
        )
        self.running = True
        self.log.info(
            "Mock-портал запущен: %s | T0 (startDate) через %.1f с",
            self.url,
            max(0.0, self.lot.start_epoch - time.time()),
        )
        return self

    async def stop(self) -> None:
        self.running = False
        if self._server is not None:
            self._server.close()
            for task in list(self._connections):
                task.cancel()
            # 3.12+: wait_closed ждёт все соединения — idle keep-alive клиента
            # иначе держит остановку до таймаута.
            close_clients = getattr(self._server, "close_clients", None)
            if callable(close_clients):
                close_clients()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
            self._server = None
        for task in list(self._connections):
            task.cancel()
        self._connections.clear()
        self.log.info("Mock-портал остановлен")

    def count(self, name: str) -> int:
        return self.counters.get(name, 0)

    def _bump(self, name: str) -> None:
        self.counters[name] = self.counters.get(name, 0) + 1

    # -- соединения --------------------------------------------------------- #
    async def _client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = HttpConnection(reader, writer, self.log)
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
        try:
            while not conn.closed:
                request = await conn.read_request()
                if request is None:
                    break
                if self.latency_ms:
                    await asyncio.sleep(self.latency_ms / 1000.0)
                try:
                    handled = await self._dispatch(conn, request)
                except Exception as exc:  # pragma: no cover - защита мока
                    self.log.exception("Ошибка обработки %s", request.path)
                    await conn.send_json(
                        500, {"error": "mock_failure", "message": str(exc)}
                    )
                    continue
                if not handled:
                    await conn.send_json(
                        404, {"error": "not_found", "path": request.path}
                    )
        except Exception as exc:
            self.log.debug("Соединение завершено: %s", exc)
        finally:
            if task is not None:
                self._connections.discard(task)
            conn.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, conn: HttpConnection, request: HttpRequest) -> bool:
        path, method = request.path, request.method
        if path == "/v3/graphql" and method == "POST":
            await self._handle_graphql(conn, request)
            return True
        if path == "/api/auth/challenge" and method == "GET":
            await self._handle_challenge(conn, request)
            return True
        if path == "/api/auth/login" and method == "POST":
            await self._handle_login(conn, request)
            return True
        if path == "/api/session/ping" and method == "GET":
            await self._handle_ping(conn, request)
            return True
        match = re.fullmatch(r"/api/bid/(\d+)/(payload|attachments|submit)", path)
        if match and method == "POST":
            lot_id, action = int(match.group(1)), match.group(2)
            handler = {
                "payload": self._handle_payload,
                "attachments": self._handle_attachment,
                "submit": self._handle_submit,
            }[action]
            await handler(conn, request, lot_id)
            return True
        match = re.fullmatch(r"/api/bid/(\d+)/status/([A-Za-z0-9\-_]+)", path)
        if match and method == "GET":
            await self._handle_status(
                conn, request, int(match.group(1)), match.group(2)
            )
            return True
        if path.startswith("/__control/"):
            await self._handle_control(conn, request)
            return True
        return False

    # -- аутентификация ----------------------------------------------------- #
    def _token(self, request: HttpRequest) -> str:
        authorization = request.header("authorization")
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        for pair in request.header("cookie").split(";"):
            key, _, value = pair.strip().partition("=")
            if key in ("session", "SESSION", "JSESSIONID"):
                return value
        return ""

    def _session(self, request: HttpRequest) -> dict[str, Any] | None:
        return self.sessions.get(self._token(request))

    async def _require_auth(
        self, conn: HttpConnection, request: HttpRequest
    ) -> dict[str, Any] | None:
        session = self._session(request)
        if session is None:
            self._bump("unauthorized")
            await conn.send_json(
                401,
                {
                    "error": "unauthorized",
                    "message": "Сессия не найдена или истекла",
                },
            )
            return None
        return session

    # -- реестр лотов ------------------------------------------------------- #
    async def _handle_graphql(self, conn: HttpConnection, request: HttpRequest) -> None:
        self._bump("graphql")
        payload = request.json if isinstance(request.json, dict) else {}
        variables = payload.get("variables") or {}
        ids = variables.get("ids") or []
        try:
            lot_id = int(ids[0]) if ids else self.lot.id
        except (TypeError, ValueError):
            lot_id = self.lot.id
        etag = f'W/"{self.lot.fingerprint()}"'
        if request.header("if-none-match") == etag:
            self._bump("graphql_304")
            await conn.send(304, b"", extra_headers={"ETag": etag})
            return
        self.lot.refresh()
        nodes = [self.lot.to_node()] if lot_id == self.lot.id else []
        await conn.send_json(
            200,
            {"data": {"Lots": nodes}},
            extra_headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    # -- challenge ---------------------------------------------------------- #
    async def _handle_challenge(
        self, conn: HttpConnection, request: HttpRequest
    ) -> None:
        self._bump("challenge")
        challenge = secrets.token_urlsafe(24)
        self.challenges[challenge] = time.time() + 300
        await conn.send_json(
            200,
            {
                "challenge": challenge,
                "expiresIn": 300,
                "algorithm": "CMS;SHA256;RSA",
                "portal": "FastBidMock",
            },
        )

    # -- логин по подписи ЭЦП ---------------------------------------------- #
    async def _handle_login(self, conn: HttpConnection, request: HttpRequest) -> None:
        self._bump("login")
        body = request.json if isinstance(request.json, dict) else {}
        challenge = str(body.get("challenge") or "")
        signature_b64 = str(body.get("signature") or "")
        if not challenge or not signature_b64:
            await conn.send_json(
                400,
                {
                    "error": "bad_request",
                    "message": "Нужны поля challenge и signature",
                },
            )
            return
        issued_at = self.challenges.pop(challenge, None)
        if issued_at is None:
            await conn.send_json(
                400,
                {
                    "error": "bad_challenge",
                    "message": "challenge не выдан или уже использован",
                },
            )
            return
        if issued_at < time.time():
            await conn.send_json(
                400,
                {
                    "error": "expired_challenge",
                    "message": "challenge истёк",
                },
            )
            return
        try:
            der = base64.b64decode(signature_b64)
        except Exception:
            await conn.send_json(
                400,
                {
                    "error": "bad_signature",
                    "message": "Подпись не base64",
                },
            )
            return
        try:
            signed_content = cms_content(der)
        except Exception as exc:
            await conn.send_json(
                400,
                {
                    "error": "bad_cms",
                    "message": f"CMS не разобран: {exc}",
                },
            )
            return
        if signed_content != challenge.encode("utf-8"):
            self._bump("login_content_mismatch")
            await conn.send_json(
                400,
                {
                    "error": "content_mismatch",
                    "message": "Подпись не соответствует выданному challenge",
                },
            )
            return
        ok, certificate, message = cms_verify_signature(der)
        if not ok or certificate is None:
            self._bump("login_bad_signature")
            await conn.send_json(
                400,
                {
                    "error": "bad_signature",
                    "message": f"Подпись недействительна: {message}",
                },
            )
            return
        bin_iin = self._bin_from_certificate(certificate)
        token = uuid.uuid4().hex
        self.sessions[token] = {
            "bin_iin": bin_iin,
            "created": time.time(),
            "subject": certificate.subject.rfc4514_string(),
        }
        self.log.info("Mock: ЭЦП принята, БИН/ИИН=%s", bin_iin)
        await conn.send_json(
            200,
            {"status": "ok", "token": token, "binIin": bin_iin, "expiresIn": 50400},
            extra_headers={"Set-Cookie": f"session={token}; Path=/; HttpOnly"},
        )

    @staticmethod
    def _bin_from_certificate(certificate: x509.Certificate) -> str:
        subject = certificate.subject.rfc4514_string()
        # Как у НУЦ: OU=BIN… (юрлицо) приоритетнее SERIALNUMBER=IIN… (сотрудник)
        for pattern in (r"BIN(\d{12})\b", r"IIN(\d{12})\b", r"\b(\d{12})\b"):
            match = re.search(pattern, subject)
            if match:
                return match.group(1)
        return ""

    # -- сессия ------------------------------------------------------------- #
    async def _handle_ping(self, conn: HttpConnection, request: HttpRequest) -> None:
        self._bump("ping")
        if self.forced["unauthorized_pings"] > 0:
            self.forced["unauthorized_pings"] -= 1
            self._bump("ping_forced_401")
            await conn.send_json(
                401,
                {
                    "error": "unauthorized",
                    "message": "Тестовая деавторизация сессии",
                },
            )
            return
        session = await self._require_auth(conn, request)
        if session is None:
            return
        await conn.send_json(
            200,
            {
                "status": "ok",
                "binIin": session["bin_iin"],
                "sessionAgeSeconds": round(time.time() - session["created"], 1),
            },
        )

    # -- предварительный расчёт заявки -------------------------------------- #
    async def _handle_payload(
        self, conn: HttpConnection, request: HttpRequest, lot_id: int
    ) -> None:
        self._bump("payload")
        if await self._require_auth(conn, request) is None:
            return
        if lot_id != self.lot.id:
            await conn.send_json(404, {"error": "lot_not_found"})
            return
        self.lot.refresh()
        await conn.send_json(
            200,
            {
                "lotId": lot_id,
                "status": "ok",
                "prefilled": {
                    "price": self.lot.amount,
                    "deliveryDays": 30,
                    "currency": "KZT",
                    "documentsRequired": ["price_offer", "tz_signed", "supplier_app"],
                },
                "acceptsBefore": self.lot.to_node()["TrdBuy"]["startDate"],
            },
        )

    # -- загрузка вложений -------------------------------------------------- #
    async def _handle_attachment(
        self, conn: HttpConnection, request: HttpRequest, lot_id: int
    ) -> None:
        self._bump("upload")
        if await self._require_auth(conn, request) is None:
            return
        body = request.json if isinstance(request.json, dict) else {}
        sha = str(body.get("sha256") or "")
        key = str(body.get("key") or "")
        if not sha or not key:
            await conn.send_json(
                400,
                {
                    "error": "bad_request",
                    "message": "Нужны поля key и sha256",
                },
            )
            return
        record = self.attachments.get(sha)
        duplicate = record is not None
        if not duplicate:
            record = {
                "id": f"att-{sha[:8]}",
                "lotId": lot_id,
                "key": key,
                "fileName": str(body.get("fileName") or key),
                "size": int(body.get("size") or 0),
                "uploadedAt": time.time(),
            }
            self.attachments[sha] = record
        await conn.send_json(
            200,
            {
                "id": record["id"],
                "status": "stored",
                "duplicate": duplicate,
            },
        )

    # -- финальный submit --------------------------------------------------- #
    async def _handle_submit(
        self, conn: HttpConnection, request: HttpRequest, lot_id: int
    ) -> None:
        self._bump("submit")
        delay_ms = float(self.forced.get("submit_delay_ms") or 0.0)
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000.0)
        if self.forced.get("fail_next_submit", 0) > 0:
            self.forced["fail_next_submit"] -= 1
            self._bump("submit_forced_500")
            await conn.send_json(
                500,
                {
                    "error": "temporary",
                    "message": "Тестовая ошибка портала",
                },
            )
            return
        session = await self._require_auth(conn, request)
        if session is None:
            return
        if self.forced.get("reject_all_submits"):
            self._bump("submit_rejected")
            await conn.send_json(
                403,
                {
                    "error": "forbidden",
                    "message": "Подача запрещена (контроль мока)",
                },
            )
            return
        if lot_id != self.lot.id:
            await conn.send_json(404, {"error": "lot_not_found"})
            return
        self.lot.refresh()
        body = request.json if isinstance(request.json, dict) else {}
        idem_key = str(body.get("idemKey") or "")
        if not idem_key:
            await conn.send_json(
                400,
                {
                    "error": "bad_request",
                    "message": "Нужен idemKey",
                },
            )
            return
        # Идемпотентность: повтор с тем же ключом возвращает ту же заявку
        existing = self.bids.get(idem_key)
        if existing is not None:
            self._bump("idempotent_hit")
            if str(self.forced.get("idempotency_mode") or "dedupe") == "conflict":
                await conn.send_json(
                    409,
                    {
                        "error": "duplicate",
                        "message": "Заявка уже подана (идемпотентный ключ)",
                    },
                )
                return
            await conn.send_json(200, dict(existing))
            return
        if not self.lot.is_open():
            self._bump("submit_rejected_early")
            await conn.send_json(
                425,
                {
                    "error": "too_early",
                    "message": "Прием заявок еще не открыт",
                    "startDate": self.lot.to_node()["TrdBuy"]["startDate"],
                    "serverNow": http_date(),
                },
            )
            return
        attachments = body.get("attachments") or []
        signed = body.get("signedDocuments") or []
        if not attachments:
            await conn.send_json(
                400,
                {
                    "error": "no_attachments",
                    "message": "К заявке не приложены документы",
                },
            )
            return
        if not signed:
            await conn.send_json(
                400,
                {
                    "error": "no_signatures",
                    "message": "Нет подписанных документов",
                },
            )
            return
        if float(body.get("price") or 0) <= 0:
            await conn.send_json(
                400,
                {
                    "error": "bad_price",
                    "message": "Некорректная цена заявки",
                },
            )
            return
        bid = {
            "bidId": f"BID-{uuid.uuid4().hex[:8].upper()}",
            "status": "accepted",
            "lotId": lot_id,
            "idemKey": idem_key,
            "price": body.get("price"),
            "binIin": session["bin_iin"],
            "submittedAt": time.time(),
            "attachments": len(attachments),
            "documents": len(signed),
        }
        self.bids[idem_key] = bid
        self.log.info(
            "Mock: заявка принята: %s (лот %s, %s документов)",
            bid["bidId"],
            lot_id,
            len(signed),
        )
        if self.forced.get("accept_then_fail_submits", 0) > 0:
            self.forced["accept_then_fail_submits"] -= 1
            self._bump("submit_accepted_lost")
            await conn.send_json(
                500, {"error": "temporary", "message": "Ответ потерян"}
            )
            return
        await conn.send_json(200, dict(bid))

    # -- проверка факта подачи ---------------------------------------------- #
    async def _handle_status(
        self, conn: HttpConnection, request: HttpRequest, lot_id: int, idem_key: str
    ) -> None:
        self._bump("status")
        if await self._require_auth(conn, request) is None:
            return
        bid = self.bids.get(idem_key)
        if bid is None or bid.get("lotId") != lot_id:
            await conn.send_json(
                404,
                {
                    "error": "not_found",
                    "message": "Заявка не найдена по ключу идемпотентности",
                },
            )
            return
        await conn.send_json(200, dict(bid))

    # -- управление поведением мока ----------------------------------------- #
    async def _handle_control(self, conn: HttpConnection, request: HttpRequest) -> None:
        path = request.path
        body = request.json if isinstance(request.json, dict) else {}
        if path == "/__control/lot" and request.method == "POST":
            delay = float(body.get("delay_s", self.lot.open_after_s))
            self.lot.schedule(delay)
            if "status_code" in body:
                self.lot.status_code = str(body["status_code"])
            if "status_name" in body:
                self.lot.status_name = str(body["status_name"])
            if "amount" in body:
                self.lot.amount = float(body["amount"])
            if "auto_open" in body:
                self.lot.auto_open = bool(body["auto_open"])
            node = self.lot.to_node()
            await conn.send_json(
                200,
                {
                    "status": "ok",
                    "startDate": node["TrdBuy"]["startDate"],
                    "startEpoch": self.lot.start_epoch,
                    "lotId": self.lot.id,
                },
            )
            return
        if path == "/__control/fail" and request.method == "POST":
            for key in (
                "unauthorized_pings",
                "fail_next_submit",
                "accept_then_fail_submits",
                "idempotency_mode",
                "submit_delay_ms",
                "reject_all_submits",
            ):
                if key in body:
                    self.forced[key] = body[key]
            await conn.send_json(200, {"status": "ok", "forced": self.forced})
            return
        if path == "/__control/session/expire" and request.method == "POST":
            count = len(self.sessions)
            self.sessions.clear()
            await conn.send_json(200, {"status": "ok", "invalidated": count})
            return
        if path == "/__control/stats" and request.method == "GET":
            self.lot.refresh()
            await conn.send_json(
                200,
                {
                    "status": "ok",
                    "counters": self.counters,
                    "bids": len(self.bids),
                    "attachments": len(self.attachments),
                    "sessions": len(self.sessions),
                    "lot": {
                        "id": self.lot.id,
                        "status": self.lot.status_name,
                        "statusCode": self.lot.status_code,
                        "startDate": self.lot.to_node()["TrdBuy"]["startDate"],
                        "isOpen": self.lot.is_open(),
                    },
                },
            )
            return
        await conn.send_json(404, {"error": "unknown_control", "path": path})


# --------------------------------------------------------------------------- #
# Mock-NCALayer
# --------------------------------------------------------------------------- #
class _NCAFault(Exception):
    """Локальная ошибка мока (code/message/details)."""

    def __init__(self, code: str, message: str, details: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class _UserCancel(_NCAFault):
    def __init__(self) -> None:
        super().__init__("USER_CANCEL", "Операция отменена пользователем")


class MockNCALayer:
    """WebSocket-заглушка NCALayer (модуль kz.gov.pki.knca.basics).

    Подписи — настоящие CMS (PKCS#7) со встроенным сертификатом. Счётчик
    ``dialogs`` показывает число «системных диалогов»: при пакетной подписи
    он равен числу вызовов, а не числу файлов.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 13580,
        password: str = "NCAPassword123",
        delay_ms: float = 0.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password  # «правильный» пароль контейнера
        self.require_password = False  # проверять signerParams.password
        self.delay_ms = delay_ms  # задержка операций (диалог пользователя)
        self.fail_next = 0  # следующие N вызовов вернуть ошибкой
        self.cancel_next = False  # следующий sign — отмена пользователем
        self.reject_batch = False  # вести себя как старый NCALayer
        self.counters: dict[str, int] = {
            "sign": 0,
            "batch_sign": 0,
            "getKeyInfo": 0,
            "connections": 0,
            "dialogs": 0,
        }
        self.sign_requests: list[dict[str, Any]] = []
        self._key, self._cert = make_test_certificate()
        self._server: Any = None
        self.log = logger or get_logger("mock.nca")

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}/kz.gov.pki.knca.basics"

    async def start(self) -> MockNCALayer:
        self._server = await websockets.serve(
            self._handle,
            self.host,
            self.port,
            max_size=None,
        )
        self.log.info("Mock-NCALayer запущен: %s", self.url)
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        self.log.info("Mock-NCALayer остановлен")

    def certificate_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization as _ser

        return self._cert.public_bytes(_ser.Encoding.PEM).decode("ascii")

    # -- обработка соединений ----------------------------------------------- #
    async def _handle(self, websocket: Any) -> None:
        self.counters["connections"] += 1
        try:
            # Приветствие — как у настоящего NCALayer
            await websocket.send(json.dumps({"result": {"version": "1.4.0-mock"}}))
            async for raw in websocket:
                snapshot = raw[:400] if isinstance(raw, str) else raw
                self.sign_requests.append({"raw": snapshot})
                try:
                    result = await self._process(json.loads(raw))
                except _UserCancel:
                    await websocket.send(json.dumps({"status": True, "body": {}}))
                    continue
                except _NCAFault as exc:
                    await websocket.send(
                        json.dumps(
                            {
                                "status": False,
                                "code": exc.code,
                                "message": exc.message,
                                "details": exc.details,
                            }
                        )
                    )
                    continue
                except Exception as exc:  # pragma: no cover - защита мока
                    await websocket.send(
                        json.dumps(
                            {
                                "status": False,
                                "code": "500",
                                "message": "mock error",
                                "details": str(exc),
                            }
                        )
                    )
                    continue
                await websocket.send(
                    json.dumps(
                        {"status": True, "body": {"result": result}},
                    )
                )
        except Exception:
            # TCP-probe клиента открывает сокет и сразу закрывает его —
            # websockets отвечает InvalidMessage. Это нормальная ситуация,
            # а не ошибка сервиса: молча закрываем соединение.
            return


# Методы, определённые ниже, присоединяются к MockNCALayer (файл пишется
# частями, а класс удобнее читать целиком выше). Кандидат на рефакторинг:
# собрать класс единым блоком при следующей правке.
async def _mock_process(self: MockNCALayer, request: Any) -> Any:
    if self.fail_next > 0:
        self.fail_next -= 1
        raise _NCAFault("503", "Сервис временно недоступен (контроль мока)")
    if not isinstance(request, dict):
        raise _NCAFault("400", "Некорректный запрос")
    method = request.get("method", "")
    args = request.get("args") or {}
    if method == "getKeyInfo":
        self.counters["getKeyInfo"] += 1
        return self._key_info()
    if method == "sign":
        if self.cancel_next:
            self.cancel_next = False
            raise _UserCancel()
        return await self._sign(args)
    raise _NCAFault("404", f"Неизвестный метод: {method}")


async def _mock_sign(self: MockNCALayer, args: Any) -> Any:
    if not isinstance(args, dict):
        raise _NCAFault("400", "args должны быть объектом")
    if self.delay_ms:
        await asyncio.sleep(self.delay_ms / 1000.0)
    if self.require_password:
        signer_params = args.get("signerParams") or {}
        if signer_params.get("password") != self.password:
            raise _NCAFault(
                "BAD_PASSWORD",
                "Неверный пароль контейнера",
                "signerParams.password",
            )
    fmt = str(args.get("format") or "cms").lower()
    data = args.get("data")
    if isinstance(data, list):
        if self.reject_batch:
            raise _NCAFault(
                "501",
                "Массивы не поддерживаются этой версией NCALayer",
                "пакетная подпись появилась в осени 2024 года",
            )
        self.counters["batch_sign"] += 1
        self.counters["dialogs"] += 1  # один вызов = один диалог
        return [self._sign_one(item, fmt) for item in data]
    self.counters["sign"] += 1
    self.counters["dialogs"] += 1
    return self._sign_one(data, fmt)


def _mock_sign_one(self: MockNCALayer, item: Any, fmt: str) -> str:
    try:
        raw = base64.b64decode(str(item or ""))
    except Exception as exc:
        raise _NCAFault("400", "data должен быть base64", str(exc)) from exc
    if fmt == "xml":
        wrapped = f"<signed>{base64.b64encode(raw).decode('ascii')}</signed>"
        return base64.b64encode(wrapped.encode("utf-8")).decode("ascii")
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(raw)
        .add_signer(self._cert, self._key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc

    cms = builder.sign(_Enc.DER, [])
    return base64.b64encode(cms).decode("ascii")


def _mock_key_info(self: MockNCALayer) -> dict[str, Any]:
    return {
        "binIin": TEST_BIN,
        "iin": TEST_BIN,
        "serialNumber": TEST_BIN,
        "subject": self._cert.subject.rfc4514_string(),
        "owner": TEST_SUBJECT_CN,
        "issuer": self._cert.issuer.rfc4514_string(),
        "serial": str(self._cert.serial_number),
        "notBefore": self._cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "notAfter": self._cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "algorithm": "RSA/SHA256",
        "storages": ["PKCS12"],
    }


MockNCALayer._process = _mock_process  # type: ignore[attr-defined]
MockNCALayer._sign = _mock_sign  # type: ignore[attr-defined]
MockNCALayer._sign_one = _mock_sign_one  # type: ignore[attr-defined]
MockNCALayer._key_info = _mock_key_info  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Фасад: оба сервиса вместе
# --------------------------------------------------------------------------- #
class MockServers:
    """Запускает MockPortal и MockNCALayer одной командой."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        http_port: int = 8643,
        ws_port: int = 13580,
        lot: MockLot | None = None,
        open_after_s: float = 12.0,
        nca_password: str = "NCAPassword123",
        nca_delay_ms: float = 0.0,
        require_password: bool = False,
        latency_ms: float = 0.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.portal = MockPortal(
            host,
            http_port,
            lot or MockLot(open_after_s=open_after_s),
            latency_ms=latency_ms,
            logger=logger,
        )
        self.ncalayer = MockNCALayer(
            host,
            ws_port,
            password=nca_password,
            delay_ms=nca_delay_ms,
            logger=logger,
        )
        if require_password:
            self.ncalayer.require_password = True

    async def start(self) -> MockServers:
        await self.portal.start()
        await self.ncalayer.start()
        return self

    async def stop(self) -> None:
        await self.ncalayer.stop()
        await self.portal.stop()

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    def settings_for(self, settings: Any) -> Any:
        """Возвращает копию настроек, перенаправленную на моки."""
        return settings.redirect_to_mock(
            self.portal.host,
            self.portal.port,
            self.ncalayer.port,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "portal": self.portal.url,
            "ncalayer": self.ncalayer.url,
            "lotId": self.portal.lot.id,
            "startEpoch": self.portal.lot.start_epoch,
        }


async def run_servers(
    host: str = "127.0.0.1",
    http_port: int = 8643,
    ws_port: int = 13580,
    open_after_s: float = 12.0,
    **kwargs: Any,
) -> MockServers:
    """Стартует оба мока. Удобно из тестов и из ``--selftest``."""
    servers = MockServers(host, http_port, ws_port, open_after_s=open_after_s, **kwargs)
    await servers.start()
    return servers
