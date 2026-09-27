"""Захват сессии портала через браузер (Edge/Chrome, CDP).

Кнопка «Войти по ЭЦП» открывает отдельное окно Edge/Chrome со СВОИМ
профилем (основной профиль пользователя не затрагивается). Пользователь
входит на портал как обычно (SSO ЭЦП через NCALayer). Приложение по CDP
читает cookies этого окна, проверяет их запросом к странице кабинета и
возвращает Cookie-строку для сессии приложения.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

BROWSER_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/microsoft-edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium-browser",
)


def find_browser() -> str:
    """Возвращает путь к Edge/Chrome или "" если браузеров нет."""
    for candidate in BROWSER_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    for name in ("msedge.exe", "chrome.exe"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def capture_via_browser(
    login_url: str,
    *,
    cookie_host: str,
    check_url: str,
    timeout_s: float = 600.0,
    cancel: Callable[[], bool] | None = None,
    log: Any = None,
) -> str:
    """Открывает браузер, ждёт вход, возвращает Cookie-строку сессии.

    Блокирует до входа, таймаута или отмены ("" — отмена/таймаут).
    """
    browser_path = find_browser()
    if not browser_path:
        raise RuntimeError(
            "Не найден Edge или Chrome — установите Microsoft Edge "
            "(входит в Windows 10/11) и повторите."
        )
    port = _free_port()
    profile = tempfile.mkdtemp(prefix="fastbid_browser_")
    process = subprocess.Popen(
        [
            browser_path,
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={port}",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1180,840",
            login_url,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        cookie_string = _poll_session_cookies(
            port, cookie_host, check_url, timeout_s, cancel, log
        )
        if cancel is not None and cancel():
            return ""
        return cookie_string
    finally:
        _kill_process_tree(process)
        shutil.rmtree(profile, ignore_errors=True)


def _kill_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is None:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            process.terminate()
    process.wait(timeout=10)


def _poll_session_cookies(
    port: int,
    cookie_host: str,
    check_url: str,
    timeout_s: float,
    cancel: Callable[[], bool] | None,
    log: Any,
) -> str:
    """Опрашивает CDP, пока в окне не появится сессия портала (или таймаут)."""
    deadline = time.monotonic() + timeout_s
    announced = False
    while time.monotonic() < deadline:
        if cancel is not None and cancel():
            return ""
        cookies = _cdp_all_cookies(port)
        pairs = [
            f"{c['name']}={c['value']}"
            for c in cookies
            if cookie_host in (c.get("domain") or "")
        ]
        session_pairs = [
            p
            for p in pairs
            if p.split("=", 1)[0].upper()
            in ("SESSION", "SESSIONID", "JSESSIONID", "PHPSESSID")
        ]
        if session_pairs and _check_url_accepts(check_url, "; ".join(pairs)):
            if log is not None:
                log.info("Сессия портала захвачена из окна браузера")
            return "; ".join(sorted(set(pairs)))
        if not announced and pairs:
            announced = True
            if log is not None:
                log.info(
                    "Жду входа в окне браузера (войдите по ЭЦП — приложение "
                    "подхватит сессию автоматически)"
                )
        time.sleep(1.0)
    return ""


def _cdp_all_cookies(port: int) -> list[dict[str, Any]]:
    """Все cookies браузера через CDP Storage.getCookies."""

    try:
        version = json.loads(
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json/version", timeout=3
            ).read()
        )
    except Exception:
        return []
    ws_url = version.get("webSocketDebuggerUrl") or ""
    if not ws_url:
        return []
    try:

        return _ws_get_cookies(ws_url)
    except Exception:
        return []


def _ws_get_cookies(ws_url: str) -> list[dict[str, Any]]:
    import asyncio
    import ssl
    import websockets

    async def run() -> list[dict[str, Any]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        async with websockets.connect(
            ws_url, ssl=ctx, open_timeout=5, max_size=None
        ) as ws:
            await ws.send(
                json.dumps({"id": 1, "method": "Storage.getCookies"})
            )
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                data = json.loads(raw)
                if data.get("id") == 1:
                    result = data.get("result") or {}
                    return result.get("cookies") or []

    return asyncio.run(run())


def _check_url_accepts(check_url: str, cookie_header: str) -> bool:
    """Страница кабинета с этими cookies — кабинет, а не вход."""
    try:
        request = urllib.request.Request(
            check_url,
            headers={
                "Cookie": cookie_header,
                "User-Agent": "Mozilla/5.0 FastBid",
            },
        )
        html = urllib.request.urlopen(request, timeout=15).read().decode(
            "utf-8", "replace"
        )
    except Exception:
        return False
    return "user/login" not in html[:4000] and not re.search(
        r"<title>\s*Авторизация", html
    )
