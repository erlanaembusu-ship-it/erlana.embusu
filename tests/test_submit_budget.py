"""Регрессии «горячего» пути: часы, выстрел по T0 и бюджет подачи 5 с.

Моки поднимаются на собственных портах, чтобы не конфликтовать с прогоном
остальных e2e-тестов и с запущенным ``--mock``.
"""

from __future__ import annotations

import asyncio
import math
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import load_settings
from core.bid_pipeline import BidPipeline, BidRequest
from core.lot_watcher import ClockSync, LotState, LotWatcher
from core.ncalayer_client import NCALayerClient, SecretPassword
from core.session_manager import SessionManager
from utils.mock_server import MockServers

PASSWORD = "NCAPassword123"
HTTP_PORT = 18643
WS_PORT = 18680
ALMATY = timezone(timedelta(hours=5))


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture()
def settings():
    return load_settings().redirect_to_mock()


def _servers(**kwargs: Any) -> MockServers:
    return MockServers(
        http_port=HTTP_PORT, ws_port=WS_PORT, nca_password=PASSWORD, **kwargs
    )


def _food_request(tmp_path: Path, lot_id: int) -> BidRequest:
    tz = tmp_path / "tz.pdf"
    cert = tmp_path / "cert.pdf"
    tz.write_bytes(b"%PDF-1.4 fake tz document")
    cert.write_bytes(b"%PDF-1.4 fake certificate")
    return BidRequest(
        lot_id=lot_id,
        blueprint_id="food_supply",
        documents=[cert],
        lot_documents=[tz],
        fields={
            "delivery_days": 10,
            "shelf_life": 6,
            "manufacturer_country": "KZ",
            "vet_certificate": True,
            "agree_terms": True,
            "vat_included": True,
        },
    )


async def _connect(servers: MockServers, settings: Any) -> tuple[Any, Any, Any]:
    nca = NCALayerClient(settings.ncalayer)
    session = SessionManager(settings, nca)
    session.set_password(SecretPassword(PASSWORD))
    await session.start()
    await session.authenticate()
    return settings, nca, session


# --------------------------------------------------------------------------- #
# Часы
# --------------------------------------------------------------------------- #
def _sample(clock: ClockSync, true_offset: float, sent: float, rtt: float) -> None:
    """Выборка «сервера» с Date, округлённым вниз до секунды."""
    server_time = sent + rtt / 2 + true_offset
    headers = {"date": formatdate(math.floor(server_time), usegmt=True)}
    clock.update_from_headers(headers, sent, sent + rtt)


def test_clock_interval_converges_and_has_no_floor_bias() -> None:
    true_offset = -3.4567
    clock = ClockSync()
    base = 1_700_000_000.0
    # Выборки с разной фазой относительно секундной границы сервера
    # Фаза сдвигается на 41 мс за выборку — полный оборот за ~25 выборок
    for index in range(25):
        _sample(clock, true_offset, base + index * 1.041, rtt=0.02)
    assert abs(clock.offset_s - true_offset) < 0.03
    assert clock.low_s <= true_offset <= clock.high_s
    assert clock.uncertainty_ms < 40


def test_clock_single_sample_is_centered_not_floored() -> None:
    # Одна выборка: погрешность ±0.5 с вокруг истины, а не систематическое
    # занижение до −1 с (прежняя точечная оценка).
    clock = ClockSync()
    _sample(clock, 0.0, 1_700_000_000.95, rtt=0.001)
    assert clock.low_s <= 0.0 <= clock.high_s
    assert abs(clock.offset_s) <= 0.51


def test_clock_retry_inflated_sample_does_not_shift_estimate() -> None:
    clock = ClockSync()
    base = 1_700_000_000.0
    for index in range(10):
        _sample(clock, 0.25, base + index * 1.31, rtt=0.01)
    before = clock.offset_s
    # «Повтор» внутри запроса: sent зафиксирован до первой попытки
    headers = {"date": formatdate(math.floor(base + 30.9 + 0.25), usegmt=True)}
    clock.update_from_headers(headers, base + 30.0, base + 31.0)
    assert abs(clock.offset_s - before) < 1e-9


def test_clock_contradiction_resets_to_new_sample() -> None:
    clock = ClockSync()
    base = 1_700_000_000.0
    for index in range(5):
        _sample(clock, 0.0, base + index * 1.3, rtt=0.01)
    # Часы ПК переведены на 30 с: старая оценка больше не годится
    _sample(clock, 30.0, base + 10.0, rtt=0.01)
    assert clock.low_s <= 30.0 <= clock.high_s


def test_refine_clock_against_mock_reaches_rtt_precision(settings) -> None:
    async def scenario() -> ClockSync:
        async with _servers(open_after_s=60.0) as servers:
            mock, nca, session = await _connect(servers, servers.settings_for(settings))
            try:
                watcher = LotWatcher(session, mock)
                await watcher.sync_clock(samples=2)
                await watcher.refine_clock()
                return watcher.clock
            finally:
                await session.close()
                await nca.close()

    clock = run(scenario())
    # Мок на той же машине: истинное смещение 0
    assert abs(clock.offset_s) < 0.06, clock.describe()
    assert clock.uncertainty_ms < 60, clock.describe()


# --------------------------------------------------------------------------- #
# Выстрел по T0
# --------------------------------------------------------------------------- #
class _NullSession:
    def set_t0(self, value: Any) -> None:
        pass


class _SlowRegistryWatcher(LotWatcher):
    """Первый снимок — сразу, дальше реестр «висит» по 10 с."""

    def __init__(self, settings: Any, t0: float) -> None:
        super().__init__(_NullSession(), settings)
        self._t0 = t0
        self.calls = 0

    async def fetch(self, lot_id: int, *, conditional: bool = True) -> LotState:
        self.calls += 1
        if self.calls > 1:
            await asyncio.sleep(10.0)
        text = datetime.fromtimestamp(self._t0, ALMATY).strftime("%Y-%m-%d %H:%M:%S")
        return LotState(
            lot_id=lot_id, status_name="Опубликован", start_date=text, end_date=text
        )


def test_t0_timer_is_not_delayed_by_hanging_registry_poll(settings) -> None:
    async def scenario() -> tuple[float, float, int]:
        t0 = float(math.ceil(time.time()) + 1)
        watcher = _SlowRegistryWatcher(settings, t0)
        await watcher.watch(1)
        return time.time(), t0, watcher.calls

    returned_at, t0, calls = run(scenario())
    lead = settings.watcher.open_lead_ms / 1000.0
    assert calls >= 2  # опрос реально «висел» во время выстрела
    assert -lead - 0.05 <= returned_at - t0 <= 0.15


def test_watch_limit_does_not_expire_before_known_t0(settings) -> None:
    async def scenario() -> float:
        t0 = float(math.ceil(time.time()) + 2)
        short = settings.with_(watcher=replace(settings.watcher, max_watch_seconds=0.5))
        watcher = _SlowRegistryWatcher(short, t0)
        await watcher.watch(1)
        return time.time() - t0

    assert abs(run(scenario())) < 0.2


# --------------------------------------------------------------------------- #
# Бюджет подачи
# --------------------------------------------------------------------------- #
def test_early_fire_retries_425_and_lands_within_budget(settings, tmp_path) -> None:
    """Выстрел на 1.2 с раньше окна (ошибка часов): 425 → повтор → приём ≈ T0."""

    async def scenario() -> dict:
        async with _servers(open_after_s=4.0) as servers:
            tuned = servers.settings_for(settings)
            tuned = tuned.with_(
                watcher=replace(tuned.watcher, open_lead_ms=1200.0),
            )
            mock, nca, session = await _connect(servers, tuned)
            try:
                pipeline = BidPipeline(session, nca, LotWatcher(session, mock), mock)
                result = await pipeline.run_cycle(
                    _food_request(tmp_path, servers.portal.lot.id)
                )
                bid = servers.portal.bids.get(result.idem_key, {})
                return {
                    "ok": result.ok,
                    "errors": result.errors,
                    "accept_after_t0": bid.get("submittedAt", math.inf)
                    - servers.portal.lot.start_epoch,
                    "counters": dict(servers.portal.counters),
                    "bids": len(servers.portal.bids),
                }
            finally:
                await session.close()
                await nca.close()

    report = run(scenario())
    assert report["ok"], report["errors"]
    assert report["counters"].get("submit_rejected_early", 0) >= 1
    assert 0.0 <= report["accept_after_t0"] < 0.6
    assert report["bids"] == 1


def test_lost_submit_response_is_verified_without_duplicate(settings, tmp_path) -> None:
    async def scenario() -> dict:
        async with _servers(open_after_s=1.0) as servers:
            servers.portal.forced["accept_then_fail_submits"] = 1
            mock, nca, session = await _connect(servers, servers.settings_for(settings))
            try:
                pipeline = BidPipeline(session, nca, LotWatcher(session, mock), mock)
                result = await pipeline.run_cycle(
                    _food_request(tmp_path, servers.portal.lot.id)
                )
                return {
                    "ok": result.ok,
                    "errors": result.errors,
                    "counters": dict(servers.portal.counters),
                    "bids": len(servers.portal.bids),
                }
            finally:
                await session.close()
                await nca.close()

    report = run(scenario())
    assert report["ok"], report["errors"]
    assert report["counters"]["submit_accepted_lost"] == 1
    # Повтор POST с тем же ключом допустим (дубля заявки нет — bids == 1);
    # под нагрузкой первая verify-проверка может сорваться транзиентно.
    assert report["counters"]["submit"] <= 2
    assert report["bids"] == 1


class _HangingSession:
    """Кабинет не отвечает вообще."""

    password = None

    def __init__(self) -> None:
        self.calls: list[tuple[str, float]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append((method, time.monotonic()))
        await asyncio.sleep(3600)

    def set_t0(self, value: Any) -> None:
        pass


class _NoSignNCA:
    async def sign_cms_batch(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("подпись не ожидается")


def test_submit_is_bounded_by_budget_when_portal_hangs(settings, tmp_path) -> None:
    budget, read = 1.0, 0.3
    tuned = settings.with_(
        retries=replace(settings.retries, submit_budget_s=budget),
        timeouts=replace(settings.timeouts, read=read),
    )

    async def scenario() -> tuple[Any, float, list[tuple[str, float]]]:
        session = _HangingSession()
        pipeline = BidPipeline(session, _NoSignNCA(), LotWatcher(None, tuned), tuned)
        now = datetime.now(ALMATY).strftime("%Y-%m-%d %H:%M:%S")
        lot = LotState(
            lot_id=777_001,
            name="Мясо говядина — поставка продуктов питания",
            amount=4_500_000.0,
            start_date=now,
            end_date=now,
            kato=("750000000",),
            raw={"plnPointKatoList": ["750000000"], "TrdBuy": {"startDate": now}},
        )
        plan = pipeline.plan(lot, _food_request(tmp_path, lot.lot_id))
        assert plan.is_valid, plan.errors
        started = time.monotonic()
        result = await pipeline.submit(plan)
        calls = [(method, at - started) for method, at in session.calls]
        return result, time.monotonic() - started, calls

    result, elapsed, calls = run(scenario())
    assert result.ok is False
    posts = [at for method, at in calls if method == "POST"]
    assert posts and all(at < budget for at in posts)
    # бюджет + финальная проверка по ключу (таймаут чтения) + запас
    assert elapsed < budget + read + 0.3
