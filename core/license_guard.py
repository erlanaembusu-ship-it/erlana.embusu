"""Лицензирование: привязка к БИН/ИИН из ЭЦП и отпечатку железа (HWID).

Как это работает
----------------
* **HWID** — стабильный идентификатор машины: Windows ``MachineGuid`` из реестра,
  macOS ``IOPlatformUUID`` (ioreg), Linux ``/etc/machine-id``; если ничего
  недоступно, используется ``uuid.getnode()`` + параметры платформы. Значения
  хешируются SHA-256 с солью, «сырые» идентификаторы никуда не уходят.
* **Лицензия** — JSON, подписанный Ed25519-ключом вендора. В поставке лежит
  только ПУБЛИЧНЫЙ ключ, поэтому подделать лицензию нельзя. Внутри: БИН/ИИН
  лицензиата, HWID, срок действия, набор модулей.
* **Проверка** — подпись → срок (с офлайн-грейсом) → HWID → БИН/ИИН, взятый из
  сертификата ЭЦП. БИН/ИИН берётся ровно из того же сертификата, которым
  подписывается вход на портал.
* **Триал** — 14 дней, привязан к тому же HWID; факт старта хранится локально.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from config.settings import AppSettings
from utils.logger import get_logger

__all__ = [
    "License",
    "LicenseError",
    "LicenseGuard",
    "LicenseStatus",
    "canonical_payload",
    "generate_keypair",
    "get_hwid",
    "machine_facts",
    "normalize_bin_iin",
    "normalize_hwid",
    "sign_license",
    "verify_license",
]

HWID_SALT = "FastBidGosZakup/1.0/hwid"
LOG = get_logger("license")

# Допуски на неточность часов: старт триала «в будущем» и перевод часов назад.
TRIAL_FUTURE_TOLERANCE = timedelta(minutes=5)
CLOCK_ROLLBACK_TOLERANCE = timedelta(hours=1)
_BACKUP_REG_KEY = r"Software\FastBidGosZakup"


class LicenseError(RuntimeError):
    """Ошибка лицензии (подпись, привязка, срок)."""


def _parse_utc(value: Any) -> datetime | None:
    """ISO-дата → aware UTC (без смещения считается UTC); мусор → None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Запись через временный файл + os.replace: сбой не портит trial.json."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    os.replace(temp_path, path)


def normalize_bin_iin(value: str) -> str:
    """Строгий БИН/ИИН для выпуска лицензии: ровно 12 цифр.

    Пробелы и дефисы допускаются. Пустой БИН недопустим: такая лицензия
    подошла бы любому лицензиату.
    """
    cleaned = re.sub(r"[\s-]", "", str(value or ""))
    if not re.fullmatch(r"[0-9]{12}", cleaned):
        raise ValueError(f"БИН/ИИН должен состоять ровно из 12 цифр: {value!r}")
    return cleaned


# --------------------------------------------------------------------------- #
# Отпечаток железа
# --------------------------------------------------------------------------- #
def _windows_machine_guid() -> str:
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value)
    except Exception:
        return ""


def _macos_platform_uuid() -> str:
    """IOPlatformUUID из ioreg (только macOS)."""
    if sys.platform != "darwin":
        return ""
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
        return match.group(1) if match else ""
    except Exception:
        return ""


def _linux_machine_id() -> str:
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            text = Path(candidate).read_text(encoding="utf-8").strip()
            if text:
                return text
        except Exception:
            continue
    return ""


def machine_facts() -> dict[str, str]:
    """Собирает «сырые» факты о машине (в логи не пишутся целиком)."""
    return {
        "platform": sys.platform,
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "guid": _windows_machine_guid()
        or _macos_platform_uuid()
        or _linux_machine_id(),
        "node": f"{uuid.getnode():012x}",
        "hostname_hash": hashlib.sha256(
            platform.node().encode("utf-8"),
        ).hexdigest()[:16],
    }


def get_hwid(salt: str = HWID_SALT) -> str:
    """Стабильный HWID: SHA-256 от ключевых фактов машины (32 hex-символа)."""
    facts = machine_facts()
    # node (MAC) может меняться при смене сетевого адаптера — он второстепенен
    primary = facts.get("guid") or facts.get("node") or facts.get("hostname_hash", "")
    material = f"{salt}|{facts['platform']}|{facts['machine']}|{primary}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32].upper()


def format_hwid(hwid: str, group: int = 4) -> str:
    """HWID группами по 4 символа — удобно диктовать по телефону."""
    return "-".join(hwid[index : index + group] for index in range(0, len(hwid), group))


def normalize_hwid(hwid: str) -> str:
    """HWID без разделителей: форматированный с дефисами и «сырой» равны."""
    return "".join(ch for ch in str(hwid or "") if ch.isalnum()).upper()


# --------------------------------------------------------------------------- #
# Лицензия
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class License:
    """Содержимое лицензии (без подписи)."""

    licensee: str
    bin_iin: str
    hwid: str
    issued_at: str = ""
    expires_at: str = ""
    features: tuple[str, ...] = ()
    seats: int = 1
    note: str = ""
    # Дополнительно: разрешённые ниши (пусто = все)
    blueprints: tuple[str, ...] = ()
    # Тарифный лимит: максимальная сумма лота, ₸ (0 = без ограничения).
    max_lot_amount: float = 0.0

    @property
    def expires_dt(self) -> datetime | None:
        if not self.expires_at:
            return None
        try:
            parsed = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @property
    def days_left(self) -> int:
        """Дней до истечения. Отрицательное значение = лицензия просрочена.

        Значение НЕ обрезается снизу: по нему видно, насколько именно лицензия
        просрочена (нужно для корректного расчёта офлайн-грейса по дате).
        """
        expiry = self.expires_dt
        if expiry is None:
            return 0
        delta = expiry - datetime.now(timezone.utc)
        return int(delta.total_seconds() // 86400)

    @property
    def is_expired(self) -> bool:
        expiry = self.expires_dt
        return bool(expiry and expiry <= datetime.now(timezone.utc))

    def allows_blueprint(self, blueprint_id: str) -> bool:
        return not self.blueprints or blueprint_id in self.blueprints


@dataclass(slots=True)
class LicenseStatus:
    """Итог проверки лицензии для UI и логики запуска."""

    valid: bool
    mode: str  # full | trial | missing | invalid | pending
    reason: str = ""
    license: License | None = None
    days_left: int = 0
    trial_days_left: int = 0
    hwid: str = ""
    bound_bin: str = ""
    checked_at: float = 0.0

    @property
    def max_lot_amount(self) -> float:
        """Тарифный лимит суммы лота, ₸ (0 = без ограничения)."""
        lic = self.license
        return float(getattr(lic, "max_lot_amount", 0.0) or 0.0) if lic else 0.0

    @property
    def label_ru(self) -> str:
        return {
            "full": "Лицензия активна",
            "trial": "Пробный период",
            "missing": "Лицензия не найдена",
            "invalid": "Лицензия недействительна",
            "pending": "Ожидает привязки к ЭЦП",
        }.get(self.mode, self.mode)

    @property
    def color(self) -> str:
        return (
            "#43c76b"
            if self.valid
            else ("#e8b93b" if self.mode == "trial" else "#e0574b")
        )


def canonical_payload(document: dict[str, Any]) -> bytes:
    """Канонический JSON для подписи: сортировка ключей, без пробелов."""
    data = {
        key: value for key, value in document.items() if key not in {"signature", "alg"}
    }
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _normalize(license: License) -> dict[str, Any]:
    data = asdict(license)
    data["features"] = list(license.features)
    data["blueprints"] = list(license.blueprints)
    return json.loads(json.dumps(data, ensure_ascii=False))


def generate_keypair() -> tuple[str, str]:
    """Генерирует пару ключей вендора (Ed25519): (приватный PEM, публичный PEM)."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def sign_license(license: License, private_key_pem: str) -> dict[str, Any]:
    """Подписывает лицензию приватным ключом вендора (выпуск лицензий)."""
    key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"),
        password=None,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise LicenseError("Нужен приватный ключ Ed25519")
    document = _normalize(license)
    document["signature"] = base64.b64encode(
        key.sign(canonical_payload(document)),
    ).decode("ascii")
    document["alg"] = "Ed25519"
    return document


def _as_int(value: Any, default: int = 1) -> int:
    """Приводит значение к int; мусор не роняет разбор лицензии."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def verify_license(document: dict[str, Any], public_key_pem: str) -> License:
    """Проверяет подпись и возвращает объект License."""
    if not isinstance(document, dict):
        raise LicenseError("Файл лицензии должен быть JSON-объектом")
    signature_b64 = document.get("signature")
    if not signature_b64:
        raise LicenseError("В файле лицензии отсутствует подпись")
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception as exc:
        raise LicenseError("Некорректный публичный ключ лицензии") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise LicenseError("Публичный ключ должен быть Ed25519")
    try:
        key.verify(base64.b64decode(signature_b64), canonical_payload(document))
    except InvalidSignature as exc:
        raise LicenseError("Подпись лицензии недействительна") from exc
    except Exception as exc:
        raise LicenseError(f"Ошибка проверки подписи: {exc}") from exc

    features = document.get("features") or []
    if isinstance(features, str):
        features = [features]
    blueprints = document.get("blueprints") or []
    if isinstance(blueprints, str):
        blueprints = [blueprints]
    try:
        raw_amount = document.get("max_lot_amount", document.get("maxLotAmount"))
        max_lot_amount = max(0.0, float(raw_amount or 0.0))
    except (TypeError, ValueError):
        max_lot_amount = 0.0
    return License(
        licensee=str(document.get("licensee") or ""),
        bin_iin=str(document.get("bin_iin") or ""),
        hwid=str(document.get("hwid") or ""),
        issued_at=str(document.get("issued_at") or ""),
        expires_at=str(document.get("expires_at") or ""),
        features=tuple(str(item) for item in features),
        seats=_as_int(document.get("seats"), 1),
        note=str(document.get("note") or ""),
        blueprints=tuple(str(item) for item in blueprints),
        max_lot_amount=max_lot_amount,
    )


# --------------------------------------------------------------------------- #
# Проверка лицензии
# --------------------------------------------------------------------------- #
class LicenseGuard:
    """Проверяет лицензию и отдаёт статус для UI и логики запуска."""

    def __init__(
        self, settings: AppSettings, logger: logging.Logger | None = None
    ) -> None:
        self.settings = settings.license
        self.log = logger or LOG
        self.hwid = get_hwid()
        self._status: LicenseStatus | None = None
        # БИН/ИИН, уже подтверждённый ЭЦП при входе. Сохраняется между
        # проверками, чтобы refresh/force не мог «стереть» несоответствие.
        self._verified_bin: str = ""
        self.log.info("HWID: %s", format_hwid(self.hwid))

    # -- вспомогательное ---------------------------------------------------- #
    def hwid_display(self) -> str:
        return format_hwid(self.hwid)

    def public_key_pem(self) -> str:
        """Публичный ключ вендора: явная подмена в тестах или вшитый ключ.

        Env-подмен и файлов ключа больше нет: репозиторий публичный, и без
        вшитого ключа любой мог выпустить себе лицензию. Единственный
        продакшен-источник — ``core/vendor_key.py``.
        """
        if self.settings.public_key_pem.strip():
            return self.settings.public_key_pem
        from core.vendor_key import VENDOR_PUBLIC_KEY_PEM

        return VENDOR_PUBLIC_KEY_PEM

    @staticmethod
    def normalize_hwid(hwid: str) -> str:
        """HWID без разделителей: форматированный с дефисами и «сырой» равны."""
        return normalize_hwid(hwid)

    @staticmethod
    def _clean_bin(value: str) -> str:
        return "".join(ch for ch in str(value or "") if ch.isdigit())

    def _known_bin(self) -> str:
        """БИН/ИИН, уже подтверждённый ЭЦП (пусто, если вход ещё не выполнялся)."""
        return self._verified_bin

    # -- публичный API ------------------------------------------------------ #
    @property
    def status(self) -> LicenseStatus:
        return self._status or self.check()

    def check(
        self, bin_iin: str = "", *, force: bool = False, cache_seconds: float = 60.0
    ) -> LicenseStatus:
        """Проверяет лицензию (кеш на минуту, чтобы не читать файл постоянно).

        БИН/ИИН, полученный из ЭЦП, запоминается и используется во ВСЕХ
        последующих проверках (включая ``check(force=True)`` и обновление
        статуса в UI). Поэтому обновление статуса без аргумента не может
        «стереть» ранее выявленное несоответствие привязки.
        """
        cleaned = self._clean_bin(bin_iin)
        if cleaned:
            self._verified_bin = cleaned
        current = self._status
        if (
            current is not None
            and not force
            and not cleaned
            and time.time() - current.checked_at < cache_seconds
        ):
            return current
        status = self._evaluate(self._known_bin())
        self._status = status
        self.log.info(
            "Лицензия: %s%s",
            status.label_ru,
            f" — {status.reason}" if status.reason else "",
        )
        return status

    def bind_check(self, bin_iin: str) -> str | None:
        """Строгая проверка привязки к БИН/ИИН (вызывается после входа по ЭЦП)."""
        cleaned = self._clean_bin(bin_iin)
        if not cleaned:
            return "БИН/ИИН из ЭЦП пуст — привязку проверить нельзя"
        status = self.check(cleaned, force=True)
        if status.mode == "full" and status.bound_bin and status.bound_bin != cleaned:
            return (
                f"Лицензия оформлена на БИН/ИИН {status.bound_bin}, "
                f"а вход выполнен под {cleaned}"
            )
        if not status.valid:
            return status.reason or "Лицензия недействительна"
        # В действующем триале привязка к БИН не требуется
        return None

    def install_license(self, source: Path) -> LicenseStatus:
        """Устанавливает файл лицензии: СНАЧАЛА проверяет, затем атомарно заменяет.

        Проверяются подпись, HWID, срок действия и привязка к уже подтверждённому
        ЭЦП БИН/ИИН. Если проверка не прошла, действующий файл лицензии НЕ
        перезаписывается — возвращается недействительный статус с причиной.
        Замена выполняется через временный файл + ``os.replace`` (атомарно).
        """
        source = Path(source)
        target = Path(self.settings.license_path)
        if not source.is_file():
            return self._rejected_install(f"Файл лицензии не найден: {source}")
        try:
            raw = source.read_text(encoding="utf-8")
        except Exception as exc:
            return self._rejected_install(f"Не удалось прочитать лицензию: {exc}")
        try:
            document = json.loads(raw)
        except Exception as exc:
            return self._rejected_install(f"Файл лицензии повреждён: {exc}")
        if not isinstance(document, dict):
            return self._rejected_install("Файл лицензии должен быть JSON-объектом")

        rollback = self._check_clock()
        if rollback:
            return self._rejected_install(rollback)
        candidate = self._evaluate_document(document, self._known_bin())
        if not candidate.valid:
            return self._rejected_install(
                "Лицензия не принята: "
                f"{candidate.reason or 'лицензия недействительна'}",
                candidate,
            )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            temp_path = target.with_name(f".{target.name}.tmp")
            temp_path.write_text(raw, encoding="utf-8")
            os.replace(temp_path, target)
        except Exception as exc:
            return self._rejected_install(f"Не удалось установить лицензию: {exc}")
        self.log.info("Лицензия установлена: %s", target)
        return self.check(force=True)

    def _rejected_install(
        self, reason: str, status: LicenseStatus | None = None
    ) -> LicenseStatus:
        """Отказ установки лицензии: действующий файл остаётся нетронутым."""
        self.log.error("Установка лицензии отклонена: %s", reason)
        return LicenseStatus(
            valid=False,
            mode="invalid",
            reason=reason,
            license=status.license if status is not None else None,
            hwid=self.hwid,
            checked_at=time.time(),
            bound_bin=status.bound_bin if status is not None else "",
        )

    # -- выпуск лицензий (сторона вендора) ---------------------------------- #
    @staticmethod
    def issue(
        licensee: str,
        bin_iin: str,
        hwid: str,
        days: int,
        private_key_pem: str,
        *,
        features: Iterable[str] = (),
        blueprints: Iterable[str] = (),
        seats: int = 1,
        note: str = "",
        max_lot_amount: float = 0.0,
    ) -> dict[str, Any]:
        """Формирует подписанную лицензию. Приватный ключ в поставку не входит.

        БИН/ИИН обязателен (ровно 12 цифр), срок — целое число дней > 0,
        иначе ``ValueError``.
        """
        if isinstance(days, bool) or not isinstance(days, int):
            raise ValueError(f"Срок лицензии должен быть целым числом дней: {days!r}")
        if days <= 0:
            raise ValueError(f"Срок лицензии должен быть больше нуля: {days}")
        cleaned_bin = normalize_bin_iin(bin_iin)
        now = datetime.now(timezone.utc)
        license_obj = License(
            licensee=licensee,
            bin_iin=cleaned_bin,
            hwid=normalize_hwid(hwid),
            issued_at=now.isoformat(timespec="seconds"),
            expires_at=(now + timedelta(days=days)).isoformat(timespec="seconds"),
            features=tuple(features),
            seats=seats,
            note=note,
            blueprints=tuple(blueprints),
            max_lot_amount=max(0.0, float(max_lot_amount)),
        )
        return sign_license(license_obj, private_key_pem)

    # -- внутренняя логика -------------------------------------------------- #
    def _evaluate(self, bin_iin: str) -> LicenseStatus:
        """Читает файл лицензии и проверяет его; мусор → invalid без падения."""
        path = Path(self.settings.license_path)
        base = LicenseStatus(
            valid=False,
            mode="missing",
            hwid=self.hwid,
            checked_at=time.time(),
            bound_bin=self._clean_bin(bin_iin),
        )
        rollback = self._check_clock()
        if rollback:
            return replace(base, mode="invalid", reason=rollback)
        if not path.exists():
            return self._trial_status(bin_iin)

        try:
            raw = path.read_text(encoding="utf-8")
        except Exception as exc:
            return replace(
                base, mode="invalid", reason=f"Файл лицензии повреждён: {exc}"
            )
        try:
            document = json.loads(raw)
        except Exception as exc:
            return replace(
                base, mode="invalid", reason=f"Файл лицензии повреждён: {exc}"
            )
        if not isinstance(document, dict):
            return replace(
                base, mode="invalid", reason="Файл лицензии должен быть JSON-объектом"
            )
        return self._evaluate_document(document, bin_iin)

    def _evaluate_document(
        self, document: dict[str, Any], bin_iin: str
    ) -> LicenseStatus:
        """Проверка содержимого лицензии: подпись → дата → HWID → привязка."""
        base = LicenseStatus(
            valid=False,
            mode="invalid",
            hwid=self.hwid,
            checked_at=time.time(),
            bound_bin=self._clean_bin(bin_iin),
        )
        public_key = self.public_key_pem()
        if not public_key:
            return replace(
                base,
                reason="Публичный ключ лицензии не настроен — обратитесь к вендору",
            )
        try:
            license_obj = verify_license(document, public_key)
        except LicenseError as exc:
            return replace(base, reason=str(exc))
        except Exception as exc:  # защита от мусора внутри файла
            return replace(base, reason=f"Файл лицензии повреждён: {exc}")

        # Неразбираемая дата в подписанной лицензии — это ошибка, а не
        # «бессрочная» лицензия.
        if license_obj.expires_at and license_obj.expires_dt is None:
            return replace(
                base,
                reason=f"Неверная дата в лицензии: {license_obj.expires_at!r}",
            )

        bound_bin = self._clean_bin(license_obj.bin_iin)
        outcome = LicenseStatus(
            valid=True,
            mode="full",
            license=license_obj,
            days_left=license_obj.days_left,
            hwid=self.hwid,
            checked_at=time.time(),
            bound_bin=bound_bin,
        )
        expiry = license_obj.expires_dt
        now = datetime.now(timezone.utc)
        if expiry is not None and expiry <= now:
            # Офлайн-грейс считается по АБСОЛЮТНОЙ дате, а не по числу
            # «округлённых» дней: иначе граница грейса «плывёт».
            grace_end = expiry + timedelta(days=self.settings.offline_grace_days)
            if now > grace_end:
                return replace(
                    outcome,
                    valid=False,
                    mode="invalid",
                    reason=(
                        f"Лицензия истекла {license_obj.expires_at} — офлайн-грейс "
                        f"{self.settings.offline_grace_days} дн. закончился "
                        f"{grace_end.date().isoformat()}"
                    ),
                )
            outcome.reason = (
                f"Лицензия истекла {license_obj.expires_at}, действует офлайн-грейс "
                f"{self.settings.offline_grace_days} дн. (до "
                f"{grace_end.date().isoformat()})"
            )
        if (
            self.settings.require_hwid_match
            and license_obj.hwid
            and self.normalize_hwid(license_obj.hwid) != self.normalize_hwid(self.hwid)
        ):
            return replace(
                outcome,
                valid=False,
                mode="invalid",
                reason="Лицензия привязана к другому компьютеру (HWID не совпал)",
            )
        if self.settings.require_bin_match and not bound_bin:
            return replace(
                outcome,
                valid=False,
                mode="invalid",
                reason="В лицензии не указан БИН/ИИН — обратитесь к вендору",
            )
        provided = self._clean_bin(bin_iin)
        if (
            self.settings.require_bin_match
            and provided
            and bound_bin
            and provided != bound_bin
        ):
            return replace(
                outcome,
                valid=False,
                mode="invalid",
                reason=(
                    f"Лицензия оформлена на БИН/ИИН {bound_bin}, "
                    f"вход выполнен под {provided}"
                ),
            )
        if self.settings.require_bin_match and not provided:
            outcome.reason = outcome.reason or (
                "Привязка к БИН/ИИН проверится после входа по ЭЦП"
            )
        return outcome

    # -- пробный период: дублирующее хранение -------------------------------- #
    def _backup_value_name(self, name: str) -> str:
        """Физическое имя значения резерва — с привязкой к пути trial-файла
        (изоляция тестов и нестандартных конфигураций); у прод-пути стабильно."""
        digest = hashlib.md5(str(self.settings.trial_path).encode("utf-8")).hexdigest()
        return f"{name}_{digest[:10]}"

    def _backup_get(self, name: str) -> str:
        """Значение из резерва: реестр HKCU (Windows) или файл в домашней папке."""
        value_name = self._backup_value_name(name)
        try:
            if sys.platform == "win32":
                import winreg

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _BACKUP_REG_KEY) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                return str(value).strip()
            path = Path.home() / f".fastbid_{value_name}"
            return path.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    def _backup_set(self, name: str, value: str) -> None:
        value_name = self._backup_value_name(name)
        try:
            if sys.platform == "win32":
                import winreg

                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _BACKUP_REG_KEY) as key:
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)
                return
            path = Path.home() / f".fastbid_{value_name}"
            path.write_text(value, encoding="utf-8")
        except Exception as exc:  # pragma: no cover
            self.log.debug("Не удалось записать резерв %s: %s", name, exc)

    def _trial_backup_read(self) -> datetime | None:
        """Старт триала из резервного хранилища (реестр/домашний файл)."""
        return _parse_utc(self._backup_get("TrialStart"))

    def _trial_backup_write(self, started: datetime) -> None:
        self._backup_set("TrialStart", started.isoformat(timespec="seconds"))

    def _own_trial_data(self, trial_path: Path) -> dict[str, Any] | None:
        """trial.json этой машины; повреждённый или чужой файл → None."""
        try:
            data = json.loads(trial_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        if str(data.get("hwid") or "").upper() != self.hwid.upper():
            return None
        return data

    def _check_clock(self) -> str:
        """Защита от перевода часов назад (продление триала и лицензии).

        Последнее виденное время (``last_seen``) хранится там же, где старт
        триала: в trial.json и в резерве; берётся максимум. Если текущее время
        отстаёт от него больше чем на час — возвращается причина отказа,
        иначе метка обновляется и возвращается пустая строка.
        """
        now = datetime.now(timezone.utc)
        trial_path = Path(self.settings.trial_path)
        trial_data = self._own_trial_data(trial_path)
        stored = [
            value
            for value in (
                _parse_utc(trial_data.get("last_seen")) if trial_data else None,
                _parse_utc(self._backup_get("LastSeen")),
            )
            if value is not None
        ]
        last_seen = max(stored, default=None)
        if last_seen is not None and now + CLOCK_ROLLBACK_TOLERANCE < last_seen:
            return (
                "Системное время переведено назад: последний запуск был "
                f"{last_seen:%d.%m.%Y %H:%M} UTC. Установите верные дату и время"
            )
        stamp = max(now, last_seen) if last_seen is not None else now
        stamp_iso = stamp.isoformat(timespec="seconds")
        self._backup_set("LastSeen", stamp_iso)
        if trial_data is not None:
            try:
                _write_json_atomic(trial_path, {**trial_data, "last_seen": stamp_iso})
            except Exception as exc:  # pragma: no cover
                self.log.debug("Не удалось обновить last_seen: %s", exc)
        return ""

    def _trial_status(self, bin_iin: str) -> LicenseStatus:
        """Статус пробного периода.

        Повреждённый ``trial.json`` НЕ сбрасывается и НЕ запускает новый триал:
        это трактуется как недействительность (иначе триал можно было бы
        бесконечно перезапускать, испортив файл). Старт триала дублируется в
        реестре (Windows) или домашнем файле (posix): удаление/подделка одного
        из источников триал не сбрасывает и не продлевает — при расхождении
        берётся более РАННЯЯ дата и записывается в оба хранилища. Старт позже
        «сейчас + 5 мин» — подделка: триал недействителен.
        """
        trial_path = Path(self.settings.trial_path)
        started_file: datetime | None = None
        data: dict[str, Any] = {}
        if trial_path.exists():
            try:
                raw = trial_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("ожидался JSON-объект")
            except Exception as exc:
                return self._invalid_trial(
                    f"Файл пробного периода повреждён: {exc}",
                )
            existing_hwid = str(data.get("hwid") or "")
            if not existing_hwid:
                return self._invalid_trial(
                    "Файл пробного периода повреждён: отсутствует HWID",
                )
            if existing_hwid.upper() != self.hwid.upper():
                return LicenseStatus(
                    valid=False,
                    mode="invalid",
                    hwid=self.hwid,
                    checked_at=time.time(),
                    reason="Пробный период уже использован на другом компьютере",
                )
            started_iso = str(data.get("started_at") or "")
            if not started_iso:
                return self._invalid_trial(
                    "Файл пробного периода повреждён: отсутствует дата начала",
                )
            started_file = _parse_utc(started_iso)
            if started_file is None:
                return self._invalid_trial(
                    "Файл пробного периода повреждён: неверная дата начала",
                )

        backup_start = self._trial_backup_read()
        now = datetime.now(timezone.utc)
        if started_file is None and backup_start is None:
            started = now
            self.log.info(
                "Пробный период начат: %s", started.isoformat(timespec="seconds")
            )
        else:
            # Файл и резерв дополняют друг друга: расхождение — подделка.
            # Ранняя дата = меньше остатка, поэтому сдвиг одного источника
            # «в будущее» триал не продлевает.
            candidates = [d for d in (started_file, backup_start) if d is not None]
            started = min(candidates)
            if (
                started_file is not None
                and backup_start is not None
                and started_file != backup_start
            ):
                self.log.warning(
                    "Расхождение даты старта триала (файл %s / резерв %s) — "
                    "взята ранняя",
                    started_file.isoformat(timespec="seconds"),
                    backup_start.isoformat(timespec="seconds"),
                )
            if started > now + TRIAL_FUTURE_TOLERANCE:
                return self._invalid_trial(
                    "Дата начала пробного периода в будущем — данные триала "
                    "подделаны или неверно установлено системное время",
                )

        # Отсутствующий или расходящийся источник получает раннюю дату
        if started_file != started:
            record = {
                "hwid": self.hwid,
                "bin_iin": self._clean_bin(bin_iin),
                "last_seen": now.isoformat(timespec="seconds"),
                **data,
                "started_at": started.isoformat(timespec="seconds"),
            }
            try:
                _write_json_atomic(trial_path, record)
            except Exception as exc:  # pragma: no cover
                self.log.error("Не удалось сохранить состояние триала: %s", exc)
        if backup_start != started:
            self._trial_backup_write(started)

        # max(0): старт в пределах допуска «в будущем» не добавляет дней
        used_days = max(0.0, (now - started).total_seconds() / 86400.0)
        # ceil: день старта — полный день триала (иначе триал фактически 13 дн.)
        left = max(0, math.ceil(self.settings.trial_days - used_days))
        return LicenseStatus(
            valid=left > 0,
            mode="trial",
            hwid=self.hwid,
            trial_days_left=left,
            checked_at=time.time(),
            bound_bin=self._clean_bin(bin_iin),
            reason=(
                f"Осталось {left} дн. пробного периода"
                if left > 0
                else "Пробный период истёк"
            ),
        )

    def _invalid_trial(self, reason: str) -> LicenseStatus:
        self.log.error("Пробный период недоступен: %s", reason)
        return LicenseStatus(
            valid=False,
            mode="invalid",
            hwid=self.hwid,
            checked_at=time.time(),
            reason=reason,
        )
