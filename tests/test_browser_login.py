"""«Войти по ЭЦП» в LIVE: сессия кабинета забирается из браузера через CDP."""

from __future__ import annotations

import asyncio
import json
import time
from http import HTTPStatus
from typing import Any

import pytest
from websockets.asyncio.server import serve

from core.browser_login import (
    BrowserLoginError,
    _cabinet_pages,
    capture_portal_session,
    cookie_header_for_host,
)

HOST = "v3bl.goszakup.gov.kz"
LOGIN_URL = f"https://{HOST}/ru/user/sso_redirect"


def test_cookie_header_only_for_cabinet_host() -> None:
    cookies = [
        {"name": "ci_session", "value": "abc", "domain": HOST, "expires": -1},
        {"name": "shared", "value": "1", "domain": ".goszakup.gov.kz", "expires": -1},
        {"name": "idp", "value": "x", "domain": "idp.zakup.gov.kz", "expires": -1},
        {"name": "old", "value": "y", "domain": HOST, "expires": time.time() - 60},
        {"name": "evil", "value": "z", "domain": "notgoszakup.gov.kz", "expires": -1},
    ]
    assert cookie_header_for_host(cookies, HOST) == "ci_session=abc; shared=1"


def test_cabinet_pages_skip_login_and_foreign() -> None:
    targets = [
        {"type": "page", "url": LOGIN_URL},
        {"type": "page", "url": f"https://{HOST}/ru/user/login"},
        {"type": "page", "url": "https://zakup.gov.kz/ru/cabinet"},
        {"type": "service_worker", "url": f"https://{HOST}/sw.js"},
        {"type": "page", "url": f"https://{HOST}/ru/cabinet/profile"},
    ]
    assert _cabinet_pages(targets, HOST) == [f"https://{HOST}/ru/cabinet/profile"]


class FakeBrowser:
    """DevTools-эндпоинт: /json/version + websocket с Storage/Target."""

    def __init__(self, stages: list[tuple[list[dict], list[dict]]]) -> None:
        self.stages = stages
        self.polls = 0
        self.methods: list[str] = []
        self.close_after: int | None = None
        self.port = 0

    def _http(self, connection: Any, request: Any) -> Any:
        if request.path == "/json/version":
            body = json.dumps(
                {
                    "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/devtools/browser/x"
                }
            )
            response = connection.respond(HTTPStatus.OK, body)
            response.headers["Content-Type"] = "application/json"
            return response
        return None

    async def _ws(self, ws: Any) -> None:
        async for raw in ws:
            msg = json.loads(raw)
            self.methods.append(msg["method"])
            stage = self.stages[min(self.polls, len(self.stages) - 1)]
            if msg["method"] == "Storage.getCookies":
                result: dict = {"cookies": stage[0]}
            elif msg["method"] == "Target.getTargets":
                result = {"targetInfos": stage[1]}
                self.polls += 1
                if self.close_after is not None and self.polls >= self.close_after:
                    await ws.send(json.dumps({"id": msg["id"], "result": result}))
                    await ws.close()
                    return
            else:
                result = {}
            await ws.send(json.dumps({"id": msg["id"], "result": result}))

    async def __aenter__(self) -> FakeBrowser:
        self._server = await serve(self._ws, "127.0.0.1", 0, process_request=self._http)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._server.close()
        await self._server.wait_closed()


def _profile_with_port(tmp_path, port: int):
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "DevToolsActivePort").write_text(f"{port}\n/devtools/browser/x\n")
    return profile


def test_capture_waits_for_login_then_validates(tmp_path) -> None:
    session_cookie = [
        {"name": "ci_session", "value": "s1", "domain": HOST, "expires": -1}
    ]
    anon_cookie = [
        {"name": "ci_session", "value": "anon", "domain": HOST, "expires": -1}
    ]
    login_tab = [{"type": "page", "url": LOGIN_URL}]
    cabinet_tab = [{"type": "page", "url": f"https://{HOST}/ru/cabinet/profile"}]
    stages = [
        (anon_cookie, login_tab),  # вход ещё не выполнен — проверять нечего
        (anon_cookie, cabinet_tab),  # портал ещё не принял — validate → None
        (anon_cookie, cabinet_tab),  # то же состояние — повторно не проверяем
        (session_cookie, cabinet_tab),  # вход завершён
    ]
    checked: list[tuple[str, str]] = []

    async def validate(header: str, url: str) -> str | None:
        checked.append((header, url))
        return "ok" if header == "ci_session=s1" else None

    async def scenario() -> tuple[str, FakeBrowser]:
        async with FakeBrowser(stages) as fake:
            result = await capture_portal_session(
                login_url=LOGIN_URL,
                cabinet_host=HOST,
                validate=validate,
                profile_dir=_profile_with_port(tmp_path, fake.port),
                browser="unused-when-reused",
                poll_interval=0.01,
                timeout=10,
            )
            return result, fake

    result, fake = asyncio.run(scenario())
    assert result == "ok"
    assert checked == [
        ("ci_session=anon", f"https://{HOST}/ru/cabinet/profile"),
        ("ci_session=s1", f"https://{HOST}/ru/cabinet/profile"),
    ]
    # Уже открытый браузер FastBid: вход открывается новой вкладкой.
    assert fake.methods[0] == "Target.createTarget"


def test_capture_reports_closed_browser(tmp_path) -> None:
    async def validate(header: str, url: str) -> None:
        return None

    async def scenario() -> None:
        async with FakeBrowser([([], [])]) as fake:
            fake.close_after = 2
            await capture_portal_session(
                login_url=LOGIN_URL,
                cabinet_host=HOST,
                validate=validate,
                profile_dir=_profile_with_port(tmp_path, fake.port),
                browser="unused-when-reused",
                poll_interval=0.01,
                timeout=10,
            )

    with pytest.raises(BrowserLoginError) as info:
        asyncio.run(scenario())
    assert info.value.code == "BROWSER_CLOSED"


def test_capture_without_browser(tmp_path, monkeypatch) -> None:
    import core.browser_login as module

    monkeypatch.setattr(module, "find_browser", lambda override="": None)

    async def validate(header: str, url: str) -> None:
        return None

    with pytest.raises(BrowserLoginError) as info:
        asyncio.run(
            capture_portal_session(
                login_url=LOGIN_URL,
                cabinet_host=HOST,
                validate=validate,
                profile_dir=tmp_path / "profile",
            )
        )
    assert info.value.code == "BROWSER_NOT_FOUND"
