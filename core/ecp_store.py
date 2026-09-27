"""Хранилище пароля ЭЦП директора (DPAPI Windows).

Пароль шифруется функцией CryptProtectData в контексте пользователя Windows:
расшифровать файл можно только под тем же пользователем на той же машине.
Файл живёт в каталоге пользовательских данных и НЕ попадает в репозиторий.

На POSIX-системах DPAPI нет: используется файл с правами 0600 и явное
предупреждение в журнале (защита слабее — решение осознанное, режим
«директора» рассчитан на Windows-машину с единственным пользователем).
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from utils.logger import get_logger

LOG = get_logger("ecp-store")


def _dpapi_protect(raw: bytes) -> bytes | None:
    if sys.platform != "win32":
        return None
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(raw, len(raw))
    inp = _Blob(len(raw), ctypes.cast(buf, ctypes.c_void_p))
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(inp), "FastBidECP", None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        LOG.error("CryptProtectData: код ошибки %s", ctypes.GetLastError())
        return None
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _dpapi_unprotect(blob: bytes) -> bytes | None:
    if sys.platform != "win32":
        return None
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(blob, len(blob))
    inp = _Blob(len(blob), ctypes.cast(buf, ctypes.c_void_p))
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
    )
    if not ok:
        LOG.error("CryptUnprotectData: код ошибки %s", ctypes.GetLastError())
        return None
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def save_profile(
    path: Path, alias: str, password: str, key_path: str = ""
) -> Path:
    """Шифрует и сохраняет профиль ЭЦП (алиас/путь ключа + пароль)."""
    import json

    payload = json.dumps(
        {"alias": alias, "password": password, "key_path": key_path},
        ensure_ascii=False,
    ).encode("utf-8")
    protected = _dpapi_protect(payload)
    if protected is None:
        if sys.platform == "win32":
            raise OSError("CryptProtectData не выполнен")
        LOG.warning("DPAPI недоступен — пароль ЭЦП хранится В ОТКРЫТОМ ВИДЕ (posix)")
        protected = payload
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.b64encode(protected))
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def load_profile(path: Path) -> tuple[str, str, str]:
    """Читает профиль ЭЦП. Возвращает (alias, password, key_path)."""
    path = Path(path)
    if not path.exists():
        return "", "", ""
    try:
        blob = base64.b64decode(path.read_bytes())
    except Exception as exc:
        LOG.error("Файл профиля ЭЦП повреждён: %s", exc)
        return "", ""
    plain = _dpapi_unprotect(blob)
    if plain is None:
        if sys.platform == "win32":
            LOG.error("Не удалось расшифровать профиль ЭЦП (другой пользователь?)")
            return "", ""
        plain = blob
    try:
        import json

        data = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        LOG.error("Профиль ЭЦП: некорректный формат (%s)", exc)
        return "", "", ""
    return (
        str(data.get("alias") or ""),
        str(data.get("password") or ""),
        str(data.get("key_path") or ""),
    )


def delete_profile(path: Path) -> None:
    path = Path(path)
    if path.exists():
        path.unlink()


def save_secret(path: Path, value: str) -> Path:
    """DPAPI-шифрует произвольную строку (токены, пароли)."""
    protected = _dpapi_protect(value.encode("utf-8"))
    if protected is None:
        if sys.platform == "win32":
            raise OSError("CryptProtectData не выполнен")
        LOG.warning("DPAPI недоступен — значение хранится В ОТКРЫТОМ ВИДЕ")
        protected = value.encode("utf-8")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(base64.b64encode(protected))
    if sys.platform != "win32":
        path.chmod(0o600)
    return path


def load_secret(path: Path) -> str:
    """Читает DPAPI-шифрованную строку ("" — файла нет/повреждён)."""
    path = Path(path)
    if not path.exists():
        return ""
    try:
        blob = base64.b64decode(path.read_bytes())
    except Exception as exc:
        LOG.error("Файл секрета повреждён: %s", exc)
        return ""
    plain = _dpapi_unprotect(blob)
    if plain is None:
        if sys.platform == "win32":
            LOG.error("Не удалось расшифровать секрет (другой пользователь?)")
            return ""
        plain = blob
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        LOG.error("Секрет: некорректная кодировка")
        return ""


def delete_secret(path: Path) -> None:
    path = Path(path)
    if path.exists():
        path.unlink()
