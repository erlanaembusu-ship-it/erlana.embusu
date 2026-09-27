"""Регрессии защиты LIVE-режима (v1.1.0).

Проверяют, что без подтверждённого API кабинета:
  * конвейер не подписывает, не загружает и не отправляет заявку (ядро,
    независимо от UI);
  * сессия не шлёт запросов на непроверенные адреса кабинета;
  * токен реестра OWS уходит в запросы реестра, а 401 даёт понятную ошибку;
  * NCALayer по wss разрешён только на loopback;
  * подтверждение открытия после T0 выполняется без лишней паузы.
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import load_settings
from core.bid_pipeline import BidPipeline
from core.lot_watcher import LotState, LotWatcher
from core.ncalayer_client import NCALayerClient, NCALayerError
from core.session_manager import PortalError, SessionManager
from tests.test_core_regressions import (
    _ExplodingSession,
    _NoSignNCA,
    food_request,
    make_lot,
)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture()
def live():
    """LIVE-настройки по умолчанию (реальные адреса, без DRY-RUN)."""
    return load_settings(dry_run=False)


@pytest.fixture()
def mock():
    return load_settings().redirect_to_mock()


# --------------------------------------------------------------------------- #
# Флаги конфигурации
# --------------------------------------------------------------------------- #
def test_flags_live_vs_mock(live, mock) -> None:
    assert live.cabinet_api_verified is False
    assert live.live_submit_allowed is False
    assert mock.cabinet_api_verified is True
    assert mock.live_submit_allowed is True
    # mode=mock с нелокальным адресом — НЕ mock-контракт
    fake = replace(mock, endpoints=replace(mock.endpoints, cabinet_base="https://x.kz"))
    assert fake.live_submit_allowed is False


def _pipeline(settings: Any) -> BidPipeline:
    return BidPipeline(
        _ExplodingSession(), _NoSignNCA(), LotWatcher(None, settings), settings
    )


def test_live_warmup_blocked_before_sign(live, tmp_path) -> None:
    pipeline = _pipeline(live)
    plan = pipeline.plan(make_lot(), food_request(tmp_path))
    assert plan.is_valid, plan.errors
    assert plan.dry_run is False
    with pytest.raises(PortalError) as info:
        run(pipeline.warmup(plan))
    assert info.value.code == "LIVE_SUBMIT_UNVERIFIED"
    assert plan.signed == []


def test_live_submit_blocked_without_network(live, tmp_path) -> None:
    pipeline = _pipeline(live)
    plan = pipeline.plan(make_lot(), food_request(tmp_path))
    result = run(pipeline.submit(plan))
    assert result.ok is False
    assert any("LIVE-подача заблокирована" in item for item in result.errors)
    assert pipeline.stats["submitted"] == 0


def test_live_run_cycle_stops_before_sign_and_watch(live, tmp_path) -> None:
    class _Watcher:
        clock = LotWatcher(None, live).clock
        watch_called = False

        async def sync_clock(self) -> None:
            return None

        async def fetch(self, lot_id: int, conditional: bool = True) -> LotState:
            return make_lot()

        async def watch(self, *args: Any, **kwargs: Any) -> Any:
            _Watcher.watch_called = True
            raise AssertionError("наблюдение не ожидается")

        def stop(self) -> None:
            pass

    pipeline = BidPipeline(_ExplodingSession(), _NoSignNCA(), _Watcher(), live)
    result = run(pipeline.run_cycle(food_request(tmp_path)))
    assert result.ok is False
    assert any("LIVE-подача заблокирована" in item for item in result.errors)
    assert _Watcher.watch_called is False


def test_live_dry_run_still_allowed(live, tmp_path) -> None:
    pipeline = _pipeline(live)
    plan = pipeline.plan(make_lot(), food_request(tmp_path, dry_run=True))
    plan = run(pipeline.warmup(plan))
    result = run(pipeline.submit(plan))
    assert result.ok and result.dry_run and result.bid_id == "dry-run"


# --------------------------------------------------------------------------- #
# Сессия: в LIVE нет запросов к кабинету
# --------------------------------------------------------------------------- #
def _session_with_transport(settings: Any, handler: Any) -> SessionManager:
    session = SessionManager(settings, NCALayerClient(settings.ncalayer))
    session._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return session


def test_live_session_never_calls_cabinet(live) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    async def scenario() -> None:
        session = _session_with_transport(live, handler)
        try:
            await session.start()
            assert await session.warmup() is False
            with pytest.raises(PortalError) as info:
                await session.ping()
            assert info.value.code == "LIVE_AUTH_UNVERIFIED"
            with pytest.raises(PortalError):
                await session.authenticate()
            with pytest.raises(PortalError):
                await session.apply_manual_token("Bearer abc")
        finally:
            await session.close()

    run(scenario())
    assert calls == []


def test_live_401_does_not_trigger_relogin(live) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={})

    async def scenario() -> SessionManager:
        session = _session_with_transport(live, handler)
        try:
            response = await session.request("GET", live.endpoints.graphql_url())
            assert response.status_code == 401
            return session
        finally:
            await session.close()

    session = run(scenario())
    assert session.stats.relogins == 0


# --------------------------------------------------------------------------- #
# Токен OWS
# --------------------------------------------------------------------------- #
def test_live_clock_sync_uses_ows_not_cabinet(live) -> None:
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        return httpx.Response(
            401, headers={"Date": "Fri, 25 Sep 2026 10:00:00 GMT"}, text=""
        )

    async def scenario() -> None:
        session = _session_with_transport(live, handler)
        watcher = LotWatcher(session, live)
        try:
            await watcher.sync_clock(samples=2)
            assert watcher.clock.samples == 2
        finally:
            await session.close()

    run(scenario())
    assert hosts and set(hosts) == {"ows.goszakup.gov.kz"}


# --------------------------------------------------------------------------- #
# NCALayer: wss только на loopback
# --------------------------------------------------------------------------- #
def test_ncalayer_wss_refuses_non_loopback(live) -> None:
    nca_settings = replace(live.ncalayer, host="10.0.0.5", scheme="wss")

    async def scenario() -> None:
        client = NCALayerClient(nca_settings)
        with pytest.raises(NCALayerError) as info:
            await client.connect()
        assert info.value.code == "NCA_NOT_LOOPBACK"

    run(scenario())


# --------------------------------------------------------------------------- #
# Подтверждение открытия: первая проверка сразу после T0
# --------------------------------------------------------------------------- #
def test_confirm_open_first_check_is_immediate(mock) -> None:
    opened = replace(make_lot(), status_name="Прием заявок", status_code="ACCEPTING")
    closed = make_lot()

    class _Watcher(LotWatcher):
        async def fetch(self, lot_id: int, *, conditional: bool = True) -> Any:
            return opened

    async def scenario() -> float:
        watcher = _Watcher(None, mock)
        started = time.perf_counter()
        state = await watcher.confirm_open(1, fallback=closed)
        assert state is opened
        return time.perf_counter() - started

    elapsed = run(scenario())
    # Раньше перед первой проверкой была пауза post_open_interval (300 мс).
    assert elapsed < mock.watcher.post_open_interval / 2
