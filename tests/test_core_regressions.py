"""Регрессионные тесты ядра FastBid (dry-run, документы, watcher, submit, лицензия).

Проверяют именно исправленные дефекты жизненного цикла и безопасности:
DRY-RUN, сопоставление документов и strict-режим, очистка задач/timer,
таймауты и неподтверждённое открытие, «успех» HTTP 2xx, метрики submit/verify,
а также clamp дат, офлайн-грейс, атомарную установку лицензии и триал.

Запуск (без pytest-asyncio, как и в остальном проекте)::

    pytest tests/ -q
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.niche_blueprints import (
    DocKind,
    DocumentSpec,
    NicheBlueprint,
    SignMode,
)
from config.settings import load_settings
from core.bid_pipeline import BidPipeline, BidRequest, response_problem
from core.license_guard import (
    License as LicenseDoc,
)
from core.license_guard import (
    LicenseGuard,
    generate_keypair,
    sign_license,
)
from core.lot_watcher import LotState, LotWatcher
from core.ncalayer_client import NCALayerClient, SecretPassword
from core.session_manager import PortalError, SessionManager
from utils.mock_server import TEST_BIN, MockServers

PASSWORD = "NCAPassword123"


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture()
def settings():
    return load_settings().redirect_to_mock()


# --------------------------------------------------------------------------- #
# Регрессии конфигурации и HTTP-заголовков
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("trd_buy_id, trailing_slash", [(555001, ""), ("555001", "/")])
def test_lot_view_url_uses_cabinet_not_ows(trd_buy_id, trailing_slash) -> None:
    endpoints = load_settings().endpoints
    endpoints = replace(
        endpoints,
        cabinet_base=endpoints.cabinet_base.rstrip("/") + trailing_slash,
    )
    expected = endpoints.cabinet_base.rstrip("/") + endpoints.lot_view_path.format(
        trd_buy_id=trd_buy_id
    )
    assert endpoints.lot_view_url(trd_buy_id) == expected


def test_lot_view_url_follows_mock_redirect(settings) -> None:
    endpoints = settings.endpoints
    assert endpoints.lot_view_url(555001) == endpoints.cabinet_url(
        endpoints.lot_view_path,
        trd_buy_id=555001,
    )
    assert endpoints.cabinet_base == endpoints.base


def test_default_headers_omit_connection_specific_headers(settings) -> None:
    session = SessionManager(settings, NCALayerClient(settings.ncalayer))
    headers = {name.lower(): value for name, value in session.default_headers().items()}
    assert (
        not {
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        }
        & headers.keys()
    )
    assert {"user-agent", "accept", "accept-language"} <= headers.keys()


def test_build_script_is_ascii() -> None:
    assert (ROOT / "build_exe.bat").read_bytes().isascii()


# --------------------------------------------------------------------------- #
# Заглушки: ни одно внешнее действие не должно случиться
# --------------------------------------------------------------------------- #
class _ExplodingSession:
    """Сессия-«ловушка»: любой сетевой вызов — провал теста."""

    password = None

    async def request(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"неожиданный сетевой вызов: {args} {kwargs}")

    def set_t0(self, value: Any) -> None:  # pragma: no cover - заглушка
        pass


class _StubSession:
    """Минимальная сессия для проверок watcher-а (без сети)."""

    password = None

    def __init__(self) -> None:
        self.t0_values: list[Any] = []

    async def request(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError("сеть в этом тесте не нужна")

    def set_t0(self, value: Any) -> None:
        self.t0_values.append(value)


class _NoSignNCA:
    """NCALayer-заглушка: подпись — провал теста."""

    async def sign_cms_batch(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("подпись в этом тесте не ожидается")


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("не JSON")
        return self._payload


class _FakeSession:
    """Отдаёт заранее заданные ответы и запоминает вызовы."""

    password = None

    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append((method, url, kwargs))
        if not self._responses:
            raise AssertionError("неожиданный сетевой вызов (ответы исчерпаны)")
        return self._responses.pop(0)

    def set_t0(self, value: Any) -> None:  # pragma: no cover - заглушка
        pass


# --------------------------------------------------------------------------- #
# Данные для плана
# --------------------------------------------------------------------------- #
def make_docs(tmp_path: Path, size: int = 19) -> dict[str, Path]:
    """Создаёт документы, НЕ перезаписывая уже подготовленные файлы."""
    tz = tmp_path / "tz.pdf"
    cert = tmp_path / "cert.pdf"
    if not tz.exists():
        tz.write_bytes(b"%PDF-1.4 fake tz document".ljust(size, b"."))
    if not cert.exists():
        cert.write_bytes(b"%PDF-1.4 fake certificate".ljust(size, b"."))
    return {"tz": tz, "cert": cert}


def make_lot(
    lot_id: int = 777_001, amount: float = 4_500_000.0, start_in_s: float = 3600.0
) -> LotState:
    start = datetime.now(timezone.utc) + timedelta(seconds=start_in_s)
    text = start.strftime("%Y-%m-%d %H:%M:%S")
    return LotState(
        lot_id=lot_id,
        lot_number="38876543-ОИ1",
        name="Мясо говядина — поставка продуктов питания",
        description="Поставка продуктов питания (тест)",
        amount=amount,
        count=120.0,
        status_id=210,
        status_name="Опубликован",
        status_code="PUBLISHED",
        trd_buy_id=555_001,
        trd_buy_number="12345678-1",
        start_date=text,
        end_date=text,
        kato=("750000000",),
        raw={"plnPointKatoList": ["750000000"], "TrdBuy": {"startDate": text}},
    )


def food_request(
    tmp_path: Path,
    *,
    documents: list[Path] | None = None,
    lot_documents: list[Path] | None = None,
    slots: dict[str, Path] | None = None,
    dry_run: bool = False,
    strict: bool = True,
    fields: dict[str, Any] | None = None,
) -> BidRequest:
    docs = make_docs(tmp_path)
    return BidRequest(
        lot_id=1,
        blueprint_id="food_supply",
        documents=[docs["cert"]] if documents is None else list(documents),
        lot_documents=[docs["tz"]] if lot_documents is None else list(lot_documents),
        document_slots=slots or {},
        fields=fields or {},
        dry_run=dry_run,
        strict_documents=strict,
    )


def build_pipeline(settings: Any, session: Any = None, nca: Any = None) -> BidPipeline:
    """Конвейер без сети: plan() не обращается ни к сессии, ни к NCALayer."""
    return BidPipeline(
        session if session is not None else _ExplodingSession(),
        nca if nca is not None else _NoSignNCA(),
        LotWatcher(None, settings),
        settings,
    )


# --------------------------------------------------------------------------- #
# (1) DRY-RUN
# --------------------------------------------------------------------------- #
def test_plan_dry_run_merges_request_and_settings(settings, tmp_path) -> None:
    request = food_request(tmp_path, dry_run=True)
    plan = build_pipeline(settings).plan(make_lot(), request)
    assert plan.is_valid, plan.errors
    assert plan.dry_run is True

    # request.dry_run=False, но settings.dry_run=True → тоже dry-run
    dry_settings = settings.with_(dry_run=True)
    assert dry_settings.dry_run is True
    plan2 = build_pipeline(dry_settings).plan(make_lot(), food_request(tmp_path))
    assert plan2.dry_run is True

    # И наоборот: ни задание, ни настройки не просят dry-run
    plan3 = build_pipeline(settings).plan(make_lot(), food_request(tmp_path))
    assert plan3.dry_run is False


def test_warmup_dry_run_skips_sign_and_upload(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline = build_pipeline(settings)
        plan = pipeline.plan(make_lot(), food_request(tmp_path, dry_run=True))
        assert plan.dry_run
        plan = await pipeline.warmup(plan)
        return plan, dict(pipeline.stats)

    plan, stats = run(scenario())
    assert plan.signed == []
    assert plan.attachments == []
    assert stats["warmed"] == 1


def test_submit_dry_run_sends_nothing(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline = build_pipeline(settings)
        plan = pipeline.plan(make_lot(), food_request(tmp_path, dry_run=True))
        result = await pipeline.submit(plan)
        return result, dict(pipeline.stats)

    result, stats = run(scenario())
    assert result.ok
    assert result.bid_id == "dry-run"
    assert result.status == "dry_run"
    assert result.dry_run is True
    assert stats["submitted"] == 0


def test_run_cycle_dry_run_no_upload_no_submit(settings, tmp_path) -> None:
    async def scenario() -> dict:
        servers = MockServers(open_after_s=1.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()

            request = food_request(tmp_path, dry_run=True)
            request.lot_id = servers.portal.lot.id
            pipeline = BidPipeline(
                session,
                nca,
                LotWatcher(session, mock_settings),
                mock_settings,
            )
            result = await pipeline.run_cycle(request)
            report = {
                "ok": result.ok,
                "bid_id": result.bid_id,
                "dry_run": result.dry_run,
                "errors": result.errors,
                "portal": dict(servers.portal.counters),
                "nca": dict(nca.stats),
                "submitted": pipeline.stats["submitted"],
            }
            await session.close()
            await nca.close()
            return report
        finally:
            await servers.stop()

    report = run(scenario())
    assert report["ok"], report["errors"]
    assert report["bid_id"] == "dry-run"
    assert report["dry_run"] is True
    assert report["portal"].get("upload", 0) == 0
    assert report["portal"].get("submit", 0) == 0
    assert report["nca"].get("batches", 0) == 0
    assert report["submitted"] == 0


def test_run_cycle_stops_on_invalid_plan_before_sign_and_watch(
    settings, tmp_path
) -> None:
    async def scenario() -> dict:
        servers = MockServers(open_after_s=1.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()

            # Нет документа закупки (LOT_DOC) → план недействителен
            request = food_request(tmp_path, lot_documents=[])
            request.lot_id = servers.portal.lot.id
            pipeline = BidPipeline(
                session,
                nca,
                LotWatcher(session, mock_settings),
                mock_settings,
            )
            result = await pipeline.run_cycle(request)
            report = {
                "ok": result.ok,
                "errors": result.errors,
                "portal": dict(servers.portal.counters),
                "nca": dict(nca.stats),
            }
            await session.close()
            await nca.close()
            return report
        finally:
            await servers.stop()

    report = run(scenario())
    assert report["ok"] is False
    assert any("План недействителен" in item for item in report["errors"])
    assert report["portal"].get("upload", 0) == 0
    assert report["portal"].get("submit", 0) == 0
    assert report["nca"].get("batches", 0) == 0


# --------------------------------------------------------------------------- #
# (2) Документы: strict, пулы LOT_DOC/USER_DOC, слоты, имена, лимиты
# --------------------------------------------------------------------------- #
def test_strict_documents_blocks_missing_required(settings, tmp_path) -> None:
    plan = build_pipeline(settings).plan(
        make_lot(),
        food_request(tmp_path, lot_documents=[]),
    )
    assert plan.is_valid is False
    assert any("Техническая спецификация" in item for item in plan.errors)
    assert any("обязательный документ" in item for item in plan.errors)


def test_non_strict_reports_missing_as_warning(settings, tmp_path) -> None:
    plan = build_pipeline(settings).plan(
        make_lot(),
        food_request(tmp_path, lot_documents=[], strict=False),
    )
    assert plan.is_valid is True, plan.errors
    assert any("Техническая спецификация" in item for item in plan.warnings)


def test_lot_doc_from_lot_pool_user_doc_from_user_pool(settings, tmp_path) -> None:
    """LOT_DOC берётся только из lot_documents, USER_DOC — только из documents."""
    docs = make_docs(tmp_path)
    # Намеренно «перепутанные» пулы: файлы лежат не там, где ожидались.
    request = food_request(
        tmp_path,
        documents=[docs["tz"]],
        lot_documents=[docs["cert"]],
        fields={},
    )
    plan = build_pipeline(settings).plan(make_lot(), request)
    assert plan.is_valid, plan.errors
    by_key = {item.key: item for item in plan.sign_items}
    assert by_key["tz_signed"].file_name == "cert.pdf"
    assert by_key["food_cert"].file_name == "tz.pdf"


def test_ambiguous_user_doc_not_guessed_requires_slots(settings, tmp_path) -> None:
    lic = tmp_path / "lic.pdf"
    ref = tmp_path / "ref.pdf"
    lic.write_bytes(b"%PDF-1.4 gask license")
    ref.write_bytes(b"%PDF-1.4 experience reference")
    tz = tmp_path / "tz.pdf"
    tz.write_bytes(b"%PDF-1.4 tz")
    request = BidRequest(
        lot_id=1,
        blueprint_id="construction",
        documents=[lic, ref],
        lot_documents=[tz],
        fields={"license_no": "GA-0001"},
    )
    plan = build_pipeline(settings).plan(make_lot(), request)
    assert plan.is_valid is False
    assert any("Лицензия ГАСК" in item for item in plan.errors)
    assert any("Неоднозначное соответствие" in item for item in plan.warnings)
    assert any("document_slots" in item for item in plan.warnings)


def test_document_slots_resolve_ambiguous_user_docs(settings, tmp_path) -> None:
    lic = tmp_path / "lic.pdf"
    ref = tmp_path / "ref.pdf"
    lic.write_bytes(b"%PDF-1.4 gask license")
    ref.write_bytes(b"%PDF-1.4 experience reference")
    tz = tmp_path / "tz.pdf"
    tz.write_bytes(b"%PDF-1.4 tz")
    request = BidRequest(
        lot_id=1,
        blueprint_id="construction",
        documents=[lic, ref],
        lot_documents=[tz],
        document_slots={"gask_license": lic, "experience_ref": ref},
        fields={"license_no": "GA-0001"},
    )
    plan = build_pipeline(settings).plan(make_lot(), request)
    assert plan.is_valid, plan.errors
    by_key = {item.key: item for item in plan.sign_items}
    assert by_key["gask_license"].file_name == "lic.pdf"
    assert by_key["experience_ref"].file_name == "ref.pdf"


def test_same_basename_different_files_not_deduped(settings, tmp_path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    first = dir_a / "doc.pdf"
    second = dir_b / "doc.pdf"
    first.write_bytes(b"%PDF-1.4 first document")
    second.write_bytes(b"%PDF-1.4 second DIFFERENT document")
    tz = tmp_path / "tz.pdf"
    tz.write_bytes(b"%PDF-1.4 tz")
    request = BidRequest(
        lot_id=1,
        blueprint_id="construction",
        documents=[],
        lot_documents=[tz],
        document_slots={"gask_license": first, "experience_ref": second},
        fields={"license_no": "GA-0002"},
    )
    # Дедупликация — по полному пути, а не по basename
    assert len(request.document_paths()) == 3
    plan = build_pipeline(settings).plan(make_lot(), request)
    assert plan.is_valid, plan.errors
    same_name = [item for item in plan.sign_items if item.file_name == "doc.pdf"]
    assert len(same_name) == 2
    assert same_name[0].data != same_name[1].data
    assert same_name[0].data and same_name[1].data


def test_max_documents_limit_blocks_plan(settings, tmp_path) -> None:
    small = settings.with_(
        pipeline=replace(settings.pipeline, max_documents=2),
    )
    plan = build_pipeline(small).plan(make_lot(), food_request(tmp_path))
    assert plan.is_valid is False
    assert any("max_documents" in item for item in plan.errors)


def test_pipeline_max_document_mb_is_enforced(settings, tmp_path) -> None:
    tiny = settings.with_(
        pipeline=replace(settings.pipeline, max_document_mb=0.0005),
    )
    docs = make_docs(tmp_path, size=2000)
    request = food_request(
        tmp_path,
        documents=[docs["cert"]],
        lot_documents=[docs["tz"]],
    )
    plan = build_pipeline(tiny).plan(make_lot(), request)
    assert plan.is_valid is False
    assert any("больше лимита" in item for item in plan.errors)


def test_spec_max_mb_is_enforced(settings, tmp_path) -> None:
    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.4".ljust(2 * 1024 * 1024, b"."))
    blueprint = NicheBlueprint(
        id="custom",
        title_ru="Кастомный шаблон",
        keywords=(),
        fields=(),
        documents=(
            DocumentSpec(
                key="limited",
                label="Ограниченный документ",
                kind=DocKind.USER_DOC,
                required=True,
                sign=SignMode.CMS,
                patterns=("*.pdf",),
                max_mb=1.0,
            ),
        ),
    )
    request = BidRequest(lot_id=1, documents=[big])
    warnings: list[str] = []
    errors: list[str] = []
    pipeline = build_pipeline(settings)
    items = pipeline._collect_documents(blueprint, request, {}, warnings, errors)
    assert items == []
    assert any("больше лимита" in item for item in errors)

    # Тот же файл проходит, если лимит документа увеличен
    blueprint_ok = NicheBlueprint(
        id="custom",
        title_ru="Кастомный шаблон",
        keywords=(),
        fields=(),
        documents=(
            DocumentSpec(
                key="limited",
                label="Ограниченный документ",
                kind=DocKind.USER_DOC,
                required=True,
                sign=SignMode.CMS,
                patterns=("*.pdf",),
                max_mb=50.0,
            ),
        ),
    )
    warnings2: list[str] = []
    errors2: list[str] = []
    items2 = pipeline._collect_documents(
        blueprint_ok,
        request,
        {},
        warnings2,
        errors2,
    )
    assert errors2 == []
    assert len(items2) == 1 and items2[0].file_name == "big.pdf"


# --------------------------------------------------------------------------- #
# (3) Наблюдение за лотом: интервалы, таймер, timeout, неподтверждённый старт
# --------------------------------------------------------------------------- #
def test_interval_for_none_and_far_t0_is_rarest(settings) -> None:
    watcher = LotWatcher(None, settings)
    # Нет даты начала / очень далёкий T0 → самый РЕДКИЙ интервал (3 ч → 180 с)
    assert watcher.interval_for(None) == 180.0
    assert watcher.interval_for(10**9) == 180.0
    assert watcher.interval_for(3 * 3600.0) == 180.0
    # Чем ближе T0, тем чаще опрос
    assert watcher.interval_for(1800.0) == 60.0
    assert watcher.interval_for(120.0) == 5.0
    assert watcher.interval_for(4.0) == 0.35
    assert watcher.interval_for(0.0) == 0.20
    # T0 уже прошёл — опрашиваем максимально часто
    assert watcher.interval_for(-10.0) == 0.20


def test_arm_timer_reschedules_on_t0_change_and_stop_cleans(settings) -> None:
    async def scenario() -> dict:
        stub = _StubSession()
        watcher = LotWatcher(stub, settings)
        first = datetime.now(timezone.utc) + timedelta(hours=1)
        watcher._arm_timer(first.timestamp())
        task1 = watcher._timer_task
        assert task1 is not None and not task1.done()
        assert watcher.stats["t0_epoch"] == pytest.approx(first.timestamp())

        # Портал сдвинул T0 → таймер обязан быть перепланирован
        state = make_lot(start_in_s=1800.0)
        new_t0 = watcher._t0_epoch(state)
        assert new_t0 is not None
        moved = watcher._reschedule_if_t0_changed(state, first.timestamp())
        assert moved == pytest.approx(new_t0)
        assert watcher._timer_task is not task1
        assert watcher.stats["t0_epoch"] == pytest.approx(new_t0)

        # Изменение в пределах эпсилона — таймер НЕ трогаем
        same = watcher._reschedule_if_t0_changed(state, new_t0 + 0.01)
        assert same == pytest.approx(new_t0)

        await asyncio.sleep(0)
        assert task1.cancelled() or task1.done()
        watcher.stop()
        assert watcher._timer_task is None
        watcher.stop()  # повторный stop безопасен
        return {"t0_values": list(stub.t0_values)}

    state = run(scenario())
    assert state["t0_values"]


def test_watch_returns_at_t0_without_status_confirmation(settings) -> None:
    """Подача не должна зависеть от подтверждения статуса OWS.

    Раньше watch() ждал confirm_open и срывался с OPEN_NOT_CONFIRMED, если
    реестр запаздывал, — подача уходила на секунды позже T0 или не уходила
    вовсе. Теперь watch() возвращается по таймеру T0, а подтверждение —
    фоновая забота вызывающего кода.
    """

    async def scenario() -> dict:
        servers = MockServers(open_after_s=1.0, nca_password=PASSWORD)
        await servers.start()
        # Портал НЕ переводит лот в «приём заявок»
        servers.portal.lot.auto_open = False
        try:
            mock_settings = servers.settings_for(settings)
            mock_settings = mock_settings.with_(
                watcher=replace(
                    mock_settings.watcher,
                    post_open_interval=0.02,
                    max_watch_seconds=30.0,
                ),
            )
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()
            watcher = LotWatcher(session, mock_settings)
            error: PortalError | None = None
            state = None
            try:
                state = await watcher.watch(servers.portal.lot.id)
            except PortalError as exc:
                error = exc
            # подтверждение отдельным вызовом по-прежнему сигнализирует об ошибке
            confirm_error: PortalError | None = None
            if state is not None:
                try:
                    await watcher.confirm_open(
                        servers.portal.lot.id, fallback=state, attempts=1
                    )
                except PortalError as exc:
                    confirm_error = exc
            report = {
                "error": error,
                "state": state,
                "confirm_error": confirm_error,
                "open_confirmed": watcher.stats["open_confirmed"],
                "timer": watcher._timer_task,
            }
            await session.close()
            await nca.close()
            return report
        finally:
            await servers.stop()

    report = run(scenario())
    assert report["error"] is None  # watch вернулся по T0 без блокировки
    assert report["state"] is not None
    assert report["confirm_error"] is not None
    assert report["confirm_error"].code == "OPEN_NOT_CONFIRMED"
    assert report["open_confirmed"] is False
    assert report["timer"] is None


def test_watch_timeout_stops_cycle_without_submit(settings, tmp_path) -> None:
    async def scenario() -> dict:
        servers = MockServers(open_after_s=3600.0, nca_password=PASSWORD)
        await servers.start()
        # T0 неизвестен (портал не отдал startDate) и окно не открывается:
        # при известном T0 лимит наблюдения продлевается до T0.
        servers.portal.lot.hide_start_date = True
        try:
            mock_settings = servers.settings_for(settings)
            mock_settings = mock_settings.with_(
                watcher=replace(mock_settings.watcher, max_watch_seconds=2.0),
            )
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()

            request = food_request(tmp_path)
            request.lot_id = servers.portal.lot.id
            watcher = LotWatcher(session, mock_settings)
            pipeline = BidPipeline(session, nca, watcher, mock_settings)
            result = await pipeline.run_cycle(request)
            report = {
                "ok": result.ok,
                "errors": result.errors,
                "portal": dict(servers.portal.counters),
                "watch_timeout": watcher.stats.get("watch_timeout"),
                "timer": watcher._timer_task,
            }
            await session.close()
            await nca.close()
            return report
        finally:
            await servers.stop()

    report = run(scenario())
    assert report["ok"] is False
    assert any("Истёк лимит наблюдения" in item for item in report["errors"])
    # После таймаута подачи быть не должно
    assert report["portal"].get("submit", 0) == 0
    assert report["watch_timeout"] is True
    assert report["timer"] is None


# --------------------------------------------------------------------------- #
# (5) Submit/verify: «успех» только по подтверждённому ответу, метрики
# --------------------------------------------------------------------------- #
def _prepared_submit(
    settings, tmp_path, responses, *, verify_after_submit: bool
) -> tuple[BidPipeline, Any, _FakeSession]:
    tuned = settings.with_(
        pipeline=replace(
            settings.pipeline,
            verify_after_submit=verify_after_submit,
        ),
    )
    session = _FakeSession(responses)
    pipeline = BidPipeline(session, _NoSignNCA(), LotWatcher(None, tuned), tuned)
    plan = pipeline.plan(make_lot(), food_request(tmp_path))
    assert plan.is_valid, plan.errors
    return pipeline, plan, session


def test_http_2xx_html_is_not_success(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline, plan, _session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, payload=None, text="<html>maintenance</html>")],
            verify_after_submit=False,
        )
        return await pipeline.submit(plan), dict(pipeline.stats)

    result, stats = run(scenario())
    assert result.ok is False
    assert any("не подтверждена" in item for item in result.errors)
    assert stats["submitted"] == 0


def test_http_2xx_empty_json_is_not_success(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline, plan, _session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, payload={})],
            verify_after_submit=False,
        )
        return await pipeline.submit(plan)

    result = run(scenario())
    assert result.ok is False
    assert any("пустой или нечитаемый" in item for item in result.errors)


def test_http_2xx_rejected_status_is_not_success(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline, plan, _session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, {"status": "rejected", "bidId": "BID-9"})],
            verify_after_submit=False,
        )
        return await pipeline.submit(plan)

    result = run(scenario())
    assert result.ok is False
    assert any("отклонил заявку" in item for item in result.errors)

    # Прямая проверка общего правила
    assert response_problem({}) is not None
    assert response_problem({"status": "ok", "bidId": "1"}) is None


def test_verify_after_submit_counts_submitted_once(settings, tmp_path) -> None:
    async def scenario() -> dict:
        payload = {"bidId": "BID-1", "status": "accepted"}
        pipeline, plan, session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, dict(payload)), _FakeResponse(200, dict(payload))],
            verify_after_submit=True,
        )
        result = await pipeline.submit(plan)
        return {
            "ok": result.ok,
            "bid_id": result.bid_id,
            "submitted": pipeline.stats["submitted"],
            "calls": [call[0] for call in session.calls],
        }

    report = run(scenario())
    assert report["ok"] is True
    assert report["bid_id"] == "BID-1"
    # POST submit + GET verify, но засчитана ОДНА поданная заявка
    assert report["calls"] == ["POST", "GET"]
    assert report["submitted"] == 1


def test_verify_after_submit_disabled_skips_second_call(settings, tmp_path) -> None:
    async def scenario() -> dict:
        pipeline, plan, session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, {"bidId": "BID-2", "status": "accepted"})],
            verify_after_submit=False,
        )
        result = await pipeline.submit(plan)
        return {
            "ok": result.ok,
            "submitted": pipeline.stats["submitted"],
            "calls": len(session.calls),
        }

    report = run(scenario())
    assert report["ok"] is True
    assert report["calls"] == 1
    assert report["submitted"] == 1


def test_verify_rejects_html_and_counts_nothing(settings, tmp_path) -> None:
    async def scenario() -> Any:
        pipeline, plan, _session = _prepared_submit(
            settings,
            tmp_path,
            [_FakeResponse(200, payload=None, text="<html>error</html>")],
            verify_after_submit=False,
        )
        return await pipeline.verify(plan), dict(pipeline.stats)

    result, stats = run(scenario())
    assert result.ok is False
    assert any("Проверка статуса" in item for item in result.errors)
    assert stats["submitted"] == 0


# --------------------------------------------------------------------------- #
# (6) Лицензия: даты, грейс, повреждённые файлы, атомарная установка
# --------------------------------------------------------------------------- #
def make_license_guard(
    tmp_path: Path, *, grace: int = 7, trial_days: int = 14
) -> tuple[LicenseGuard, str, str, Any]:
    private_pem, public_pem = generate_keypair()
    base = load_settings()
    isolated = replace(
        base.license,
        public_key_pem=public_pem,
        license_path=tmp_path / "license.json",
        trial_path=tmp_path / "trial.json",
        offline_grace_days=grace,
        trial_days=trial_days,
    )
    guard = LicenseGuard(base.with_(license=isolated))
    # Резерв триала (реестр / домашний файл) — в памяти: тесты не должны
    # трогать реальные хранилища машины разработчика.
    backup: dict[str, str] = {}
    guard._backup_get = lambda name: backup.get(name, "")  # type: ignore[method-assign]
    guard._backup_set = backup.__setitem__  # type: ignore[method-assign]
    return guard, private_pem, public_pem, isolated


def _dump(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def test_license_days_left_not_clamped() -> None:
    now = datetime.now(timezone.utc)
    long_expired = LicenseDoc(
        licensee="X",
        bin_iin=TEST_BIN,
        hwid="A" * 32,
        expires_at=(now - timedelta(days=30)).isoformat(),
    )
    assert long_expired.is_expired
    assert long_expired.days_left <= -30

    slightly_expired = LicenseDoc(
        licensee="X",
        bin_iin=TEST_BIN,
        hwid="A" * 32,
        expires_at=(now - timedelta(hours=2)).isoformat(),
    )
    assert slightly_expired.days_left == -1

    valid = LicenseDoc(
        licensee="X",
        bin_iin=TEST_BIN,
        hwid="A" * 32,
        expires_at=(now + timedelta(days=5)).isoformat(),
    )
    assert 4 <= valid.days_left <= 5


def test_license_grace_uses_absolute_date(tmp_path) -> None:
    guard, private_pem, _public, isolated = make_license_guard(tmp_path, grace=7)

    def expired_days_ago(days: int) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        return sign_license(
            LicenseDoc(
                licensee="TOO",
                bin_iin=TEST_BIN,
                hwid=guard.hwid,
                issued_at=(now - timedelta(days=days + 365)).isoformat(),
                expires_at=(now - timedelta(days=days)).isoformat(),
            ),
            private_pem,
        )

    in_grace = expired_days_ago(3)
    _dump(isolated.license_path, in_grace)
    status = guard.check(force=True)
    assert status.valid is True
    assert status.mode == "full"
    assert "грейс" in status.reason
    assert status.days_left < 0

    beyond_grace = expired_days_ago(30)
    _dump(isolated.license_path, beyond_grace)
    expired = guard.check(force=True)
    assert expired.valid is False
    assert expired.mode == "invalid"
    assert "истекла" in expired.reason


def test_license_malformed_file_and_date_are_invalid(tmp_path) -> None:
    guard, private_pem, _public, isolated = make_license_guard(tmp_path)

    isolated.license_path.write_text("{ это не JSON", encoding="utf-8")
    broken = guard.check(force=True)
    assert broken.valid is False and broken.mode == "invalid"
    assert "повреждён" in broken.reason

    bad_date = sign_license(
        LicenseDoc(
            licensee="X",
            bin_iin=TEST_BIN,
            hwid=guard.hwid,
            expires_at="2026-99-99T00:00:00+00:00",
        ),
        private_pem,
    )
    _dump(isolated.license_path, bad_date)
    wrong_date = guard.check(force=True)
    assert wrong_date.valid is False and wrong_date.mode == "invalid"
    assert "дата" in wrong_date.reason.lower()


def test_install_license_keeps_existing_on_bad_input(tmp_path) -> None:
    guard, private_pem, _public, isolated = make_license_guard(tmp_path)
    good = LicenseGuard.issue("TOO Good", TEST_BIN, guard.hwid, 365, private_pem)
    guard.install_license(_dump(tmp_path / "good.json", good))
    assert guard.check(force=True).valid
    original = isolated.license_path.read_text(encoding="utf-8")

    # 1) повреждённый JSON
    broken = tmp_path / "broken.json"
    broken.write_text("{oops", encoding="utf-8")
    status = guard.install_license(broken)
    assert status.valid is False and status.mode == "invalid"
    assert isolated.license_path.read_text(encoding="utf-8") == original

    # 2) подпись чужим ключом
    other_private, _other_public = generate_keypair()
    forged = sign_license(
        LicenseDoc(
            licensee="HACKER",
            bin_iin=TEST_BIN,
            hwid=guard.hwid,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        ),
        other_private,
    )
    status2 = guard.install_license(_dump(tmp_path / "forged.json", forged))
    assert status2.valid is False
    assert isolated.license_path.read_text(encoding="utf-8") == original

    # 3) лицензия на другое железо
    stranger = LicenseGuard.issue("TOO", TEST_BIN, "0" * 32, 365, private_pem)
    status3 = guard.install_license(_dump(tmp_path / "stranger.json", stranger))
    assert status3.valid is False
    assert "HWID" in status3.reason
    assert isolated.license_path.read_text(encoding="utf-8") == original

    # 4) корректная лицензия — заменяет файл
    fresh = LicenseGuard.issue("TOO New", TEST_BIN, guard.hwid, 30, private_pem)
    status4 = guard.install_license(_dump(tmp_path / "fresh.json", fresh))
    assert status4.valid is True and status4.mode == "full"
    assert isolated.license_path.read_text(encoding="utf-8") != original


def test_install_license_validates_binding(tmp_path) -> None:
    guard, private_pem, _public, isolated = make_license_guard(tmp_path)
    assert not isolated.license_path.exists()
    # Вход по ЭЦП под TEST_BIN (триал) — БИН запоминается
    guard.bind_check(TEST_BIN)
    assert guard._verified_bin == TEST_BIN

    foreign = LicenseGuard.issue(
        "TOO Other", "999999999999", guard.hwid, 365, private_pem
    )
    status = guard.install_license(_dump(tmp_path / "foreign.json", foreign))
    assert status.valid is False and status.mode == "invalid"
    assert "999999999999" in status.reason
    # Файл лицензии не создан/не испорчен
    assert not isolated.license_path.exists()


def test_check_force_keeps_verified_bin_mismatch(tmp_path) -> None:
    guard, private_pem, _public, isolated = make_license_guard(tmp_path)
    mine = LicenseGuard.issue("TOO Mine", TEST_BIN, guard.hwid, 365, private_pem)
    _dump(isolated.license_path, mine)
    assert guard.check(TEST_BIN, force=True).valid is True

    # Лицензия другого БИН на том же железе
    foreign = LicenseGuard.issue(
        "TOO Other", "999999999999", guard.hwid, 365, private_pem
    )
    _dump(isolated.license_path, foreign)

    # Обновление статуса БЕЗ аргумента не должно «стереть» несоответствие
    refreshed = guard.check(force=True)
    assert refreshed.valid is False and refreshed.mode == "invalid"
    assert "999999999999" in refreshed.reason
    assert guard.status.valid is False
    assert guard.check().valid is False


def test_corrupted_trial_is_invalid_and_not_reset(tmp_path) -> None:
    guard, _private, _public, isolated = make_license_guard(tmp_path)
    isolated.trial_path.write_text("{broken trial", encoding="utf-8")
    before = isolated.trial_path.read_text(encoding="utf-8")

    status = guard.check(force=True)
    assert status.valid is False and status.mode == "invalid"
    assert "повреждён" in status.reason
    # Файл триала НЕ сброшен и не перезаписан
    assert isolated.trial_path.read_text(encoding="utf-8") == before

    isolated.trial_path.write_text(
        json.dumps({"hwid": guard.hwid}),
        encoding="utf-8",
    )
    no_date = guard.check(force=True)
    assert no_date.valid is False and "повреждён" in no_date.reason

    isolated.trial_path.write_text(
        json.dumps(
            {"hwid": "0" * 32, "started_at": datetime.now(timezone.utc).isoformat()}
        ),
        encoding="utf-8",
    )
    stranger = guard.check(force=True)
    assert stranger.valid is False
    assert "другом компьютере" in stranger.reason

    # Чистое отсутствие файла — новый триал (и он снова не «ломается»)
    isolated.trial_path.unlink()
    fresh = guard.check(force=True)
    assert fresh.valid is True and fresh.mode == "trial"
    assert fresh.trial_days_left >= 13


def test_license_tariff_max_lot_amount_roundtrip(tmp_path) -> None:
    """Тарифный лимит: выпуск → файл → проверка (roundtrip)."""
    guard, private_pem, _public, _isolated = make_license_guard(tmp_path)
    document = LicenseGuard.issue(
        "ТОО Тариф",
        TEST_BIN,
        guard.hwid,
        365,
        private_pem,
        max_lot_amount=10_000_000.0,
    )
    guard.install_license(_dump(tmp_path / "license.json", document))
    status = guard.check(force=True)
    assert status.valid
    assert status.mode == "full"
    assert status.max_lot_amount == 10_000_000.0

    # Без лимита — 0 (без ограничения)
    plain = LicenseGuard.issue("ТОО", TEST_BIN, guard.hwid, 30, private_pem)
    guard.install_license(_dump(tmp_path / "license2.json", plain))
    assert guard.check(force=True).max_lot_amount == 0.0


def test_plan_blocks_lot_above_tariff_limit(tmp_path, settings, monkeypatch) -> None:
    """Сумма лота выше тарифа → план недействителен, подача блокируется."""
    guard, private_pem, _public, isolated = make_license_guard(tmp_path)
    document = LicenseGuard.issue(
        "ТОО Тариф",
        TEST_BIN,
        guard.hwid,
        365,
        private_pem,
        max_lot_amount=5_000_000.0,
    )
    guard.install_license(_dump(isolated.license_path, document))
    monkeypatch.setenv("FASTBID_LICENSE_ENFORCE", "0")

    pipeline = BidPipeline(
        _ExplodingSession(),
        _NoSignNCA(),
        LotWatcher(None, settings),
        settings,
        license_guard=guard,
    )
    # Сумма лота 47 344 048 ≫ лимит 5 000 000
    plan = pipeline.plan(make_lot(amount=47_344_048.0), food_request(tmp_path))
    assert not plan.is_valid
    assert any("превышает лимит" in item for item in plan.errors)

    # В пределах тарифа — план строится
    plan_ok = pipeline.plan(make_lot(amount=4_500_000.0), food_request(tmp_path))
    assert plan_ok.is_valid


def test_plan_without_license_guard_has_no_tariff_check(tmp_path, settings) -> None:
    """Без LicenseGuard (утилиты/тесты) тарифная проверка не выполняется."""
    pipeline = BidPipeline(
        _ExplodingSession(),
        _NoSignNCA(),
        LotWatcher(None, settings),
        settings,
    )
    assert pipeline.license_guard is None
    plan = pipeline.plan(make_lot(amount=999_999_999.0), food_request(tmp_path))
    assert plan.is_valid


def test_ecp_store_profile_roundtrip(tmp_path) -> None:
    """Режим директора: профиль ЭЦП (алиас+пароль) шифруется и читается."""
    from core import ecp_store

    path = tmp_path / "ecp_secret.bin"
    assert ecp_store.load_profile(path) == ("", "")  # файла нет

    ecp_store.save_profile(path, "910103351659", "СекретПароль123")
    alias, password = ecp_store.load_profile(path)
    assert alias == "910103351659"
    assert password == "СекретПароль123"

    # файл не содержит открытого пароля
    assert "СекретПароль123".encode("utf-8") not in path.read_bytes()

    ecp_store.delete_profile(path)
    assert ecp_store.load_profile(path) == ("", "")


def test_sign_args_include_key_alias_in_director_mode(settings) -> None:
    """Режим директора: алиас ключа уходит в args.sign (без диалога выбора)."""
    nca = NCALayerClient(settings.ncalayer)
    args = nca._build_sign_args(["Zm9v"], "cms", SecretPassword("pw"))
    assert "keyAlias" not in args  # режим выключен по умолчанию

    tuned = replace(settings.ncalayer, auto_sign=True, key_alias="910103351659")
    nca2 = NCALayerClient(tuned)
    args2 = nca2._build_sign_args(["Zm9v"], "cms", SecretPassword("pw"))
    assert args2["keyAlias"] == "910103351659"
    # пароль ЭЦП пробрасывается в signerParams (диалог пароля не нужен)
    assert args2["signerParams"]["password"] == "pw"


def test_resolve_reference_by_announcement(settings) -> None:
    """Автопилот: номер объявления → единственный лот этого объявления."""
    import asyncio

    from core.lot_watcher import LotWatcher

    async def scenario() -> dict:
        servers = MockServers(open_after_s=3600.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            await session.start()
            watcher = LotWatcher(session, mock_settings)
            try:
                state, via_announcement = await watcher.resolve_reference(
                    servers.portal.lot.trd_buy_id
                )
                return {
                    "lot_id": state.lot_id,
                    "mock_lot_id": servers.portal.lot.id,
                    "via": via_announcement,
                }
            finally:
                await session.close()
                await nca.close()
        finally:
            await servers.stop()

    report = asyncio.run(scenario())
    assert report["via"] is True
    assert report["lot_id"] == report["mock_lot_id"]


def test_backend_autopilot_arms_from_announcement(tmp_path, settings) -> None:
    """Автопилот: номер объявления → ниша, документы из doc_dir, взвод."""
    import asyncio

    from ui.app import Backend, UiEventQueue

    async def scenario() -> dict:
        servers = MockServers(open_after_s=3600.0, nca_password=PASSWORD)
        await servers.start()
        backend = None
        try:
            mock = servers.settings_for(settings)
            docs = tmp_path / "docs"
            docs.mkdir()
            (docs / "cert_supplier.pdf").write_bytes(b"%PDF cert")
            (docs / "tz_project.pdf").write_bytes(b"%PDF tz")
            mock = mock.with_(
                profile=replace(mock.profile, doc_dir=docs),
            )
            backend = Backend(mock, UiEventQueue())
            await backend.start_session()
            backend.bind_loop(asyncio.get_running_loop())
            report = await backend.autopilot(servers.portal.lot.trd_buy_id)
            armed = backend.is_armed(report["lot_id"])
            await backend.lock_session()
            return {"armed": armed, **report}
        finally:
            if backend is not None:
                await backend.ncalayer.close()
            await servers.stop()

    report = asyncio.run(scenario())
    assert report["armed"] is True
    assert report["via_announcement"] is True
    assert report["docs_missing"] == []
    assert "cert" in " ".join(report["docs_matched"])
    assert report["dry_run"] is False  # mock: подача разрешена
