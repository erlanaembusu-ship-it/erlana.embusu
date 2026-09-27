"""Регрессии интерфейса и транспорта. Запуск: py -3 -m pytest tests/ -q."""

from __future__ import annotations

import asyncio
import concurrent.futures
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from config.niche_blueprints import FieldSpec, FieldType, PricingRule
from config.settings import load_settings
from core.bid_pipeline import BidRequest, BidResult
from core.ncalayer_client import KeyInfo, NCALayerClient
from core.session_manager import SessionManager


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "1.5", "word"])
def test_integer_fields_reject_invalid(value):
    with pytest.raises(ValueError):
        FieldSpec("days", "Дни", FieldType.INT).coerce(value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0])
def test_price_rejects_nonfinite(value):
    assert PricingRule().validate(value, 100)


def test_boolean_format_is_strict():
    spec = FieldSpec("vat", "НДС", FieldType.BOOL)
    assert spec.coerce("false") is False
    with pytest.raises(ValueError):
        spec.coerce("maybe")


def test_env_and_explicit_override(monkeypatch):
    monkeypatch.setenv("FASTBID_DRY_RUN", "true")
    assert load_settings(dry_run=False).dry_run is False


def test_no_transport_repost_for_submit():
    async def scenario():
        settings = load_settings().redirect_to_mock()
        nca = NCALayerClient(settings.ncalayer)
        session = SessionManager(settings, nca)
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(503, json={"error": "unavailable"})

        session._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            response = await session.request(
                "POST",
                settings.endpoints.cabinet_base,
                retry=False,
                allow_relogin=False,
            )
            assert response.status_code == 503
            assert len(calls) == 1
        finally:
            await session.close()
            await nca.close()

    asyncio.run(scenario())


@pytest.fixture()
def backend(tmp_path):
    pytest.importorskip("tkinter")
    from ui.app import Backend
    from ui.components import UiEventQueue

    settings = load_settings().redirect_to_mock()
    settings = replace(
        settings,
        license=replace(
            settings.license,
            license_path=tmp_path / "license.json",
            trial_path=tmp_path / "trial.json",
        ),
    )
    return Backend(settings, UiEventQueue())


def test_token_result_contract(backend):
    async def scenario():
        backend.session.apply_manual_token = AsyncMock(
            return_value=KeyInfo(bin_iin="test")
        )
        result = await backend.apply_token("test-token")
        assert result["key_info"].bin_iin == "test"
        assert "license_warning" in result

    asyncio.run(scenario())


def test_completed_bid_can_be_rearmed_and_stats_persist(backend):
    async def scenario():
        request = BidRequest(123, dry_run=True)
        record = backend.arm(123, "", request)
        record.pipeline = SimpleNamespace(
            run_cycle=AsyncMock(
                return_value=BidResult(ok=True, lot_id=123, dry_run=True)
            ),
            stats={"planned": 1, "warmed": 1, "submitted": 0, "failed": 0},
        )
        await backend._run_armed(record)
        assert not backend.is_armed(123)
        assert backend.ui_snapshot()["pipeline"]["planned"] == 1
        assert backend.arm(123, "", request) is not record

    asyncio.run(scenario())


def test_failed_bid_releases_record(backend):
    async def scenario():
        record = backend.arm(123, "", BidRequest(123))
        record.pipeline = SimpleNamespace(
            run_cycle=AsyncMock(side_effect=ValueError("test")), stats={}
        )
        with pytest.raises(ValueError):
            await backend._run_armed(record)
        assert not backend.is_armed(123)
        assert not backend._active_tasks

    asyncio.run(scenario())


def test_profile_update_propagates_and_active_bid_blocks(backend):
    async def scenario():
        profile = replace(backend.settings.profile, name_ru="New supplier")
        updated = await backend.update_profile(profile)
        assert backend.session.settings is updated
        assert backend.pipeline.settings is updated
        assert backend.watcher.settings is updated
        backend.arm(123, "", BidRequest(123))
        with pytest.raises(ValueError):
            await backend.update_profile(profile)

    asyncio.run(scenario())


@pytest.fixture()
def app(backend, monkeypatch):
    tkinter = pytest.importorskip("tkinter")
    from ui.app import AsyncBridge, FastBidApp
    from utils.logger import UILogSink

    bridge = AsyncBridge()
    bridge.start()
    backend.bind_loop(bridge.loop)
    # Повторное создание Tk-интерпретатора в одном процессе флакает на
    # Windows («Can't find a usable init.tcl») — даём до трёх попыток,
    # прежде чем списать всё на отсутствие дисплея.
    window = None
    for attempt in range(3):
        try:
            window = FastBidApp(
                backend.settings, bridge, backend, backend.events, UILogSink()
            )
            break
        except tkinter.TclError as exc:
            if attempt == 2:
                bridge.stop()
                pytest.skip(f"Tk display unavailable: {exc}")
            time.sleep(0.05)
    assert window is not None
    monkeypatch.setattr("ui.app.messagebox.showinfo", lambda *a, **k: None)
    monkeypatch.setattr("ui.app.messagebox.showwarning", lambda *a, **k: None)
    monkeypatch.setattr("ui.app.messagebox.showerror", lambda *a, **k: None)
    window.update()
    yield window
    window._closing = True
    bridge.submit(backend.stop_session()).result(timeout=5)
    bridge.stop()
    window.destroy()
    for after_id in window.tk.call("after", "info"):
        window.tk.call("after", "cancel", after_id)


def test_ui_theme_and_log_limit(app):
    import customtkinter as ctk

    log = app._log_console
    log._max_rows = 3
    for i in range(10):
        log.append_record(f"row-{i}", "INFO")
    assert log._box.get("1.0", "end").strip().splitlines() == [
        "row-7",
        "row-8",
        "row-9",
    ]
    assert log._box.cget("state") == "disabled"
    for mode in ("dark", "light"):
        ctk.set_appearance_mode(mode)
        app.update()
        from ui.components import COLORS

        assert (
            log._box._textbox.tag_cget("INFO", "foreground")
            == COLORS["text"][mode == "dark"]
        )


def test_ui_distinct_lot_requests_and_slots(app, tmp_path):
    app._niche_menu.set("food_supply")
    app._on_niche_changed("food_supply")
    app._doc_slots["tz_signed"] = tmp_path / "tz.pdf"
    app._entry_lot.insert(0, "123")
    app._entry_price.insert(0, "100")
    app._on_add_lot()
    app._entry_lot.delete(0, "end")
    app._entry_lot.insert(0, "456")
    app._entry_price.delete(0, "end")
    app._entry_price.insert(0, "200")
    app._on_add_lot()
    app._doc_slots.clear()
    assert app._requests[123].price == 100
    assert app._requests[456].price == 200
    assert app._requests[123].document_slots["tz_signed"].name == "tz.pdf"
    assert len(app._cards) == 2


def test_ui_rejects_id_with_text(app):
    app._entry_lot.insert(0, "lot12and34")
    app._on_add_lot()
    assert not app._cards


def test_ui_callbacks_only_queue_from_worker(app):
    future = concurrent.futures.Future()
    future.set_result({"session_label": "test", "stats": {}})
    app._snapshot_done(future)
    assert not app._callbacks.empty()
    app._tick()
    assert app._callbacks.empty()


def test_ui_dryrun_and_cancel_are_not_real_success(app):
    card = app._upsert_card(123, "123", "")
    app._on_armed_done({"lot_id": 123, "ok": True, "dry_run": True})
    assert card._pill.cget("text") == "DRY-RUN"
    assert "НЕ отправлена" in card._status_line.cget("text")
    card.set_timings({"submit": 12})
    card.set_timings({})
    assert card._stages._labels["submit"].cget("text") == "—"
    app._on_armed_done({"lot_id": 123, "cancelled": True})
    assert card._pill.cget("text") == "снята"


def test_ui_stale_event_ignored(app):
    card = app._upsert_card(123, "123", "")
    card.set_status("current")
    app._runs[123] = "new"
    app._handle_event("stage", {"lot_id": 123, "run_id": "old", "stage": "submit"})
    assert card._status_line.cget("text") == "current"


def test_live_backend_refuses_real_arm_and_allows_dry_run(tmp_path):
    pytest.importorskip("tkinter")
    from ui.app import Backend
    from ui.components import UiEventQueue

    settings = load_settings(dry_run=False)
    settings = replace(
        settings,
        license=replace(
            settings.license,
            license_path=tmp_path / "license.json",
            trial_path=tmp_path / "trial.json",
        ),
    )
    live_backend = Backend(settings, UiEventQueue())
    with pytest.raises(ValueError, match="LIVE-подача заблокирована"):
        live_backend.arm(123, "", BidRequest(123))
    assert not live_backend.is_armed(123)
    assert live_backend.arm(123, "", BidRequest(123, dry_run=True))
