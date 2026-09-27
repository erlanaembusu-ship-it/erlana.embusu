"""Подача подготовленного черновика по протоколу из HAR (docs/PORTAL_CONTRACT.md)."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl
from zoneinfo import ZoneInfo

import httpx
import pytest

from config.settings import load_settings
from core.draft_submit import DraftRef, DraftSubmitter, parse_draft_ref
from core.ncalayer_client import NCALayerClient
from core.session_manager import PortalError, SessionManager, SessionState

ANNO, APP = 17666784, 73161291
LOGOUT = '<a href="/ru/user/sso_logout">Выход</a>'
PREVIEW = (
    f'<html><meta name="csrf-token-hash" content="tok123">{LOGOUT}'
    '<button id="next">Подать заявку</button>'
    '<button id="btn_price_agree_no_captcha">Да</button></html>'
)


def announce_html(start: datetime) -> str:
    stamp = start.astimezone(ZoneInfo("Asia/Almaty")).strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"<html>{LOGOUT}<label>Срок начала приема заявок</label>"
        f'<input class="form-control" value="{stamp}" readonly></html>'
    )


class FakePortal:
    """Кабинет v3bl: ответы без заголовка Date, поэтому часы = локальные."""

    def __init__(self, submit_replies: list[dict], preview: str = PREVIEW) -> None:
        self.submit_replies = list(submit_replies)
        self.preview = preview
        self.calls: list[tuple[str, str, float, httpx.Request]] = []
        self.start = datetime.now(ZoneInfo("Asia/Almaty"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path, time.time(), request))
        if path == "/manifest.json":
            return httpx.Response(200, json={})
        if path == f"/ru/application/preview/{ANNO}/{APP}":
            return httpx.Response(200, text=self.preview)
        if path == f"/ru/announce/index/{ANNO}":
            return httpx.Response(200, text=announce_html(self.start))
        if path == "/ru/cabinet/tax_debts":
            return httpx.Response(
                200, text=f'{LOGOUT}<input type="hidden" id="csrf" value="tax1" />'
            )
        if path == f"/ru/application/ajax_public_application/{ANNO}/{APP}":
            return httpx.Response(200, json=self.submit_replies.pop(0))
        if path == f"/ru/myapp/actionShowApp/{APP}":
            return httpx.Response(200, text=LOGOUT)
        return httpx.Response(404, text="nf")

    def posts(self, suffix: str = "") -> list[httpx.Request]:
        return [c[3] for c in self.calls if c[0] == "POST" and c[1].endswith(suffix)]


def make_submitter(portal: FakePortal) -> tuple[DraftSubmitter, SessionManager]:
    settings = load_settings(dry_run=False)
    session = SessionManager(settings, NCALayerClient(settings.ncalayer))
    session._client = httpx.AsyncClient(transport=httpx.MockTransport(portal))
    return DraftSubmitter(session, settings), session


def run_draft(portal: FakePortal, **kwargs: Any):
    async def scenario():
        submitter, session = make_submitter(portal)
        try:
            return await submitter.run(DraftRef(ANNO, APP), **kwargs)
        finally:
            await session.close()

    return asyncio.run(scenario())


def test_parse_draft_ref() -> None:
    url = f"https://v3bl.goszakup.gov.kz/ru/application/preview/{ANNO}/{APP}"
    assert parse_draft_ref(url) == DraftRef(ANNO, APP)
    assert parse_draft_ref(f" {ANNO}/{APP} ") == DraftRef(ANNO, APP)
    assert parse_draft_ref(f"{ANNO} {APP}") == DraftRef(ANNO, APP)
    with pytest.raises(ValueError):
        parse_draft_ref("17666784")


def test_dry_run_never_posts() -> None:
    portal = FakePortal([])
    result = run_draft(portal, dry_run=True, request_tax=True)
    assert result.ok and result.dry_run and result.attempts == 0
    assert portal.posts() == []
    # T0 взят со страницы объявления.
    assert result.t0_epoch == pytest.approx(
        portal.start.replace(microsecond=0).timestamp()
    )


def test_real_submit_retries_until_open_and_matches_portal_form() -> None:
    portal = FakePortal(
        [
            {"status": "error", "debtor": 0, "message": "Прием заявок еще не начался"},
            {"status": "ok", "debtor": 0},
        ]
    )
    result = run_draft(portal, dry_run=False, request_tax=True)
    assert result.ok and result.attempts == 2
    submits = portal.posts("ajax_public_application/17666784/73161291")
    assert len(submits) == 2
    form = parse_qsl(submits[0].content.decode())
    assert form == [
        ("public_app", "Y"),
        ("agree_price", "false"),
        ("agree_contract_project", "false"),
        ("agree_covid19", "false"),
        ("csrf", "tok123"),
    ]
    assert submits[0].headers["x-requested-with"] == "XMLHttpRequest"
    tax = portal.posts("/ru/cabinet/tax_debts")
    assert [dict(parse_qsl(r.content.decode()))["csrf"] for r in tax] == ["tax1"]
    assert portal.calls[-1][1] == f"/ru/myapp/actionShowApp/{APP}"


def test_tax_debt_error_is_not_retried() -> None:
    message = "Для подачи заявки необходимо иметь актуальные сведения о налоговой задолженности"
    portal = FakePortal([{"status": "error", "debtor": 0, "message": message}])
    result = run_draft(portal, dry_run=False)
    assert not result.ok and result.attempts == 1 and "налоговой" in result.message


def test_captcha_blocks_arming() -> None:
    portal = FakePortal([], preview=PREVIEW.replace("_no_captcha", ""))
    with pytest.raises(PortalError) as info:
        run_draft(portal, dry_run=False)
    assert info.value.code == "CAPTCHA_REQUIRED"
    assert portal.posts() == []


def test_fires_at_t0_not_before() -> None:
    portal = FakePortal([{"status": "ok", "debtor": 0}])
    t0 = time.time() + 0.8
    result = run_draft(portal, dry_run=False, t0_epoch=t0)
    fired = [c[2] for c in portal.calls if c[0] == "POST"][0]
    assert result.ok
    assert t0 <= fired < t0 + 0.3


def test_live_keepalive_marks_expired_session() -> None:
    settings = load_settings(dry_run=False)
    pages = {"html": LOGOUT}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=pages["html"])

    async def scenario() -> list[str]:
        session = SessionManager(settings, NCALayerClient(settings.ncalayer))
        session._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await session.apply_manual_token("ci_session=abc")
            await session._live_keepalive()
            states = [session.state.value]
            pages["html"] = "<h1>Авторизация</h1>"
            await session._live_keepalive()
            states.append(session.state.value)
            return states
        finally:
            await session.close()

    assert asyncio.run(scenario()) == ["online", SessionState.EXPIRED.value]


def test_backend_arm_draft_requires_login_and_valid_t0(tmp_path) -> None:
    from dataclasses import replace

    from ui.app import Backend, UiEventQueue

    settings = load_settings(dry_run=False)
    settings = replace(
        settings,
        license=replace(
            settings.license,
            license_path=tmp_path / "license.json",
            trial_path=tmp_path / "trial.json",
        ),
    )
    backend = Backend(settings, UiEventQueue())
    backend.bind_loop(asyncio.new_event_loop())
    with pytest.raises(ValueError, match="войдите"):
        backend.arm_draft(f"{ANNO}/{APP}", real=False)
    backend.session._state = SessionState.ONLINE
    with pytest.raises(ValueError, match="T0"):
        backend.arm_draft(f"{ANNO}/{APP}", real=False, t0_text="завтра")
    with pytest.raises(ValueError, match="адрес"):
        backend.arm_draft("abc", real=False)
