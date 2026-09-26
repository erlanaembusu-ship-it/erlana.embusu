"""Сквозные тесты FastBid против локальных заглушек (без pytest-asyncio).

Запуск::

    pytest tests/ -x -q

Каждый тест поднимает свои моки, поэтому они независимы.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.niche_blueprints import get_blueprint, resolve_blueprint
from config.settings import load_settings
from core.bid_pipeline import BidPipeline, BidRequest
from core.license_guard import License as LicenseDoc
from core.license_guard import (
    LicenseError,
    LicenseGuard,
    format_hwid,
    generate_keypair,
    get_hwid,
    sign_license,
    verify_license,
)
from core.lot_watcher import LotWatcher, parse_portal_datetime
from core.ncalayer_client import (
    KeyInfo,
    NCALayerClient,
    NCALayerError,
    SecretPassword,
    SignItem,
    b64decode,
    extract_bin_iin_from_certificate,
)
from core.session_manager import PortalError, SessionManager
from utils.mock_server import (
    TEST_BIN,
    MockServers,
    cms_content,
    cms_verify_signature,
    make_test_certificate,
)

PASSWORD = "NCAPassword123"


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture()
def settings():
    return load_settings().redirect_to_mock()


def make_docs(tmp_path: Path) -> dict[str, Path]:
    tz = tmp_path / "tz.pdf"
    cert = tmp_path / "cert.pdf"
    tz.write_bytes(b"%PDF-1.4 fake tz document")
    cert.write_bytes(b"%PDF-1.4 fake certificate")
    return {"tz": tz, "cert": cert}


# --------------------------------------------------------------------------- #
# Криптография: CMS, сертификаты, БИН
# --------------------------------------------------------------------------- #
def test_cms_roundtrip_and_bin_extraction() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    key, certificate = make_test_certificate(TEST_BIN)
    data = b"some-challenge-bytes"
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(Encoding.DER, [])
    )
    assert cms_content(der) == data
    ok, parsed, _message = cms_verify_signature(der)
    assert ok and parsed is not None
    assert extract_bin_iin_from_certificate(parsed) == TEST_BIN


def test_corrupted_cms_is_rejected() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    key, certificate = make_test_certificate()
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"data")
        .add_signer(certificate, key, hashes.SHA256())
        .sign(Encoding.DER, [])
    )
    broken = bytearray(der)
    broken[-20] ^= 0xFF
    ok, _cert, message = cms_verify_signature(bytes(broken))
    assert not ok and message


def test_key_info_from_mock_certificate() -> None:
    _key, certificate = make_test_certificate()
    info = KeyInfo.from_certificate(certificate)
    assert info.available and info.bin_iin == TEST_BIN


# --------------------------------------------------------------------------- #
# NCALayer: пакетная подпись одним вызовом
# --------------------------------------------------------------------------- #
def test_ncalayer_batch_sign_one_call(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=60.0)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            client = NCALayerClient(mock_settings.ncalayer)
            password = SecretPassword(PASSWORD)
            items = [
                SignItem(key=f"doc{i}", label=f"doc{i}", data=f"content-{i}".encode())
                for i in range(3)
            ]
            signed = await client.sign_cms_batch(items, password=password)
            assert len(signed) == 3
            assert all(doc.from_batch for doc in signed)
            for index, doc in enumerate(signed):
                der = b64decode(doc.signature_b64)
                assert cms_content(der) == f"content-{index}".encode()
                ok, _cert, _msg = cms_verify_signature(der)
                assert ok
            assert client.stats["batches"] == 1
            # Пачка в три документа = ровно один «диалог»
            assert servers.ncalayer.counters["batch_sign"] == 1
            assert servers.ncalayer.counters["dialogs"] == 1
            info = await client.get_key_info()
            assert info.bin_iin == TEST_BIN
            await client.close()
        finally:
            await servers.stop()

    run(scenario())


def test_ncalayer_fallback_sequential_when_batch_rejected(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=60.0)
        await servers.start()
        servers.ncalayer.reject_batch = True
        try:
            mock_settings = servers.settings_for(settings)
            client = NCALayerClient(mock_settings.ncalayer)
            items = [SignItem(key="a", data=b"alpha"), SignItem(key="b", data=b"beta")]
            signed = await client.sign_cms_batch(
                items,
                password=SecretPassword(PASSWORD),
            )
            assert len(signed) == 2
            assert all(not doc.from_batch for doc in signed)
            assert servers.ncalayer.counters["sign"] == 2
            await client.close()
        finally:
            await servers.stop()

    run(scenario())


def test_ncalayer_user_cancel(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=60.0)
        await servers.start()
        servers.ncalayer.cancel_next = True
        try:
            mock_settings = servers.settings_for(settings)
            client = NCALayerClient(mock_settings.ncalayer)
            with pytest.raises(NCALayerError) as exc_info:
                await client.sign_cms_batch([SignItem(key="a", data=b"x")])
            assert exc_info.value.is_user_cancel
            await client.close()
        finally:
            await servers.stop()

    run(scenario())


def test_mock_password_passthrough(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=60.0)
        servers.ncalayer.require_password = True
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            client = NCALayerClient(mock_settings.ncalayer)
            good = await client.sign_cms_batch(
                [SignItem(key="a", data=b"x")],
                password=SecretPassword(PASSWORD),
            )
            assert len(good) == 1
            with pytest.raises(NCALayerError):
                await client.sign_cms_batch(
                    [SignItem(key="a", data=b"x")],
                    password=SecretPassword("wrong"),
                )
            await client.close()
        finally:
            await servers.stop()

    run(scenario())


# --------------------------------------------------------------------------- #
# Полный цикл подачи заявки
# --------------------------------------------------------------------------- #
def test_full_cycle_success_and_timings(settings, tmp_path) -> None:
    async def scenario() -> dict:
        servers = MockServers(open_after_s=5.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            key_info = await session.authenticate()
            assert key_info.bin_iin == TEST_BIN

            watcher = LotWatcher(session, mock_settings)
            pipeline = BidPipeline(session, nca, watcher, mock_settings)
            docs = make_docs(tmp_path)
            request = BidRequest(
                lot_id=servers.portal.lot.id,
                blueprint_id="food_supply",
                documents=[docs["cert"]],
                lot_documents=[docs["tz"]],
                fields={
                    "delivery_days": 10,
                    "shelf_life": 6,
                    "manufacturer_country": "KZ",
                    "vet_certificate": True,
                    "agree_terms": True,
                    "vat_included": True,
                },
            )
            started = time.perf_counter()
            result = await pipeline.run_cycle(request)
            elapsed = time.perf_counter() - started
            report = {
                "ok": result.ok,
                "bid_id": result.bid_id,
                "stages": result.stages,
                "elapsed_s": round(elapsed, 2),
                "t0_delta_ms": result.t0_delta_ms,
                "errors": result.errors,
                "nca": dict(nca.stats),
                "portal": dict(servers.portal.counters),
            }
            await session.close()
            await nca.close()
            return report
        finally:
            await servers.stop()

    report = run(scenario())
    assert report["ok"], report["errors"]
    assert report["bid_id"]
    # Полный цикл обязан укладываться в целевой бюджет 20–50 с
    assert report["elapsed_s"] < 50.0
    # Подача — в считаных секундах от T0 (не минутах). Нижняя граница
    # допускает выстрел по таймеру с опережением (open_lead_ms) при
    # нагрузке прогона: ранняя подача безопасна (425 → retry по ключу).
    assert report["t0_delta_ms"] is not None
    assert -2000.0 < report["t0_delta_ms"] < 5000.0
    # Пакетная подпись: один вызов NCALayer на все документы
    assert report["nca"]["batches"] == 1
    # Предзагрузка вложений прошла до финального submit
    assert report["portal"]["upload"] == 4
    assert report["portal"]["submit"] >= 1


def test_early_submit_is_rejected_before_t0(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=3600.0)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()
            url = mock_settings.endpoints.cabinet_url(
                mock_settings.endpoints.bid_submit_path,
                lot_id=servers.portal.lot.id,
            )
            response = await session.request(
                "POST",
                url,
                json={
                    "idemKey": "x" * 32,
                    "lotId": servers.portal.lot.id,
                    "price": 100.0,
                    "attachments": [{"id": "a"}],
                    "signedDocuments": [{"signature": "s"}],
                },
            )
            assert response.status_code == 425
            await session.close()
            await nca.close()
        finally:
            await servers.stop()

    run(scenario())


def test_auto_relogin_on_forced_401(settings) -> None:
    async def scenario() -> None:
        servers = MockServers(open_after_s=60.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()
            before = session.stats.relogins
            servers.portal.forced["unauthorized_pings"] = 2
            latency = await session.ping()  # 401 → auto-relogin → OK
            assert latency > 0
            # Каждый 401 внутри ретраев порождает свой relogin — их ≥ 1
            assert session.stats.relogins >= before + 1
            assert session.is_online
            await session.close()
            await nca.close()
        finally:
            await servers.stop()

    run(scenario())


# --------------------------------------------------------------------------- #
# Идемпотентность, лицензия, ниши, даты, часы
# --------------------------------------------------------------------------- #
def test_idempotent_double_submit(settings, tmp_path) -> None:
    async def scenario() -> tuple:
        servers = MockServers(open_after_s=1.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()
            docs = make_docs(tmp_path)
            request = BidRequest(
                lot_id=servers.portal.lot.id,
                blueprint_id="food_supply",
                documents=[docs["cert"]],
                lot_documents=[docs["tz"]],
                fields={
                    "delivery_days": 10,
                    "shelf_life": 6,
                    "manufacturer_country": "KZ",
                    "vet_certificate": True,
                    "agree_terms": True,
                    "vat_included": True,
                },
            )
            # Первая подача — полноценный цикл
            first = await BidPipeline(
                session,
                nca,
                LotWatcher(session, mock_settings),
                mock_settings,
            ).run_cycle(request)
            assert first.ok
            # Повторная подача ТОГО ЖЕ пакета (те же байты документов → тот же
            # idemKey): портал обязан вернуть ту же заявку, а не создать дубль
            second = await BidPipeline(
                session,
                nca,
                LotWatcher(session, mock_settings),
                mock_settings,
            ).run_cycle(request)
            await session.close()
            await nca.close()
            return first.bid_id, second.bid_id, dict(servers.portal.counters)
        finally:
            await servers.stop()

    first_bid, second_bid, counters = run(scenario())
    assert first_bid and second_bid == first_bid
    assert counters.get("idempotent_hit", 0) >= 1
    assert counters.get("submit", 0) >= 2


def test_hwid_is_stable_and_formatted() -> None:
    first, second = get_hwid(), get_hwid()
    assert first == second and len(first) == 32
    assert "-" in format_hwid(first)


def test_license_issue_verify_and_tamper(tmp_path) -> None:
    import dataclasses as _dc
    import json as _json

    from config.settings import load_settings as _load

    private_pem, public_pem = generate_keypair()
    base = _load()
    isolated = _dc.replace(
        base.license,
        public_key_pem=public_pem,
        license_path=tmp_path / "lic.json",
        trial_path=tmp_path / "trial.json",
    )
    guard = LicenseGuard(base.with_(license=isolated))
    backup: dict[str, str] = {}  # резерв триала в памяти, не в реальном $HOME
    guard._backup_get = lambda name: backup.get(name, "")  # type: ignore[method-assign]
    guard._backup_set = backup.__setitem__  # type: ignore[method-assign]
    assert guard.check().mode == "trial"
    document = LicenseGuard.issue(
        "TOO Test", TEST_BIN, guard.hwid, 365, private_pem, features=["bid"]
    )
    (tmp_path / "lic.json").write_text(
        _json.dumps(document, ensure_ascii=False),
        encoding="utf-8",
    )
    status = guard.check(force=True)
    assert status.valid and status.mode == "full" and status.bound_bin == TEST_BIN
    assert guard.bind_check(TEST_BIN) is None
    assert "оформлена на БИН" in (guard.bind_check("999999999999") or "")
    tampered = dict(document)
    tampered["licensee"] = "HACKER"
    try:
        verify_license(tampered, public_pem)
        raise AssertionError("подделка прошла проверку")
    except LicenseError:
        pass
    expired_doc = sign_license(
        LicenseDoc(
            licensee="X",
            bin_iin=TEST_BIN,
            hwid=guard.hwid,
            expires_at="2000-01-01T00:00:00+00:00",
        ),
        private_pem,
    )
    expired = verify_license(expired_doc, public_pem)
    assert expired.is_expired


def test_blueprint_resolution_and_validation() -> None:
    assert resolve_blueprint("Поставка мяса и молока").id == "food_supply"
    assert resolve_blueprint("Капитальный ремонт кровли").id == "construction"
    assert resolve_blueprint("Неизвестная абракадабра").id == "generic"
    food = get_blueprint("food_supply")
    values = {
        "price": 4500000.0,
        "vat_included": True,
        "delivery_days": 10,
        "delivery_place": "750000000",
        "shelf_life": 6,
        "manufacturer_country": "KZ",
        "vet_certificate": True,
        "agree_terms": True,
        "comment": "test",
    }
    assert food.validate(values, 4500000.0, 4500000.0) == []
    assert "KZ" in food.build_comment({**values, "manufacturer_country": "KZ"})
    bad = food.validate({**values, "price": -1.0}, 4500000.0, -1.0)
    assert bad


def test_portal_datetime_parsing() -> None:
    parsed = parse_portal_datetime("2026-09-21 10:00:00")
    assert parsed is not None and parsed.utcoffset() is not None
    assert parse_portal_datetime("") is None
    assert parse_portal_datetime("not-a-date") is None
    assert parse_portal_datetime(None) is None


def test_server_clock_offset_is_small(settings) -> None:
    async def scenario() -> float:
        servers = MockServers(open_after_s=30.0)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(PASSWORD))
            await session.start()
            await session.authenticate()
            watcher = LotWatcher(session, mock_settings)
            await watcher.sync_clock(samples=3)
            clock = watcher.clock
            assert clock.samples >= 2
            await session.close()
            await nca.close()
            return abs(clock.offset_s)
        finally:
            await servers.stop()

    assert run(scenario()) < 5.0


# --------------------------------------------------------------------------- #
# Вход по токену (мост из браузера)
# --------------------------------------------------------------------------- #
def test_parse_credential_formats() -> None:
    from core.session_manager import SessionManager as SM

    assert SM.parse_credential("abc123")[0] == "abc123"
    assert SM.parse_credential("Bearer abc123")[0] == "abc123"
    assert SM.parse_credential("Authorization: Bearer abc123")[0] == "abc123"
    token, cookie = SM.parse_credential("SESSION=xyz; XSRF=1")
    assert cookie == "SESSION=xyz; XSRF=1" and token == "xyz"
    token, cookie = SM.parse_credential("Cookie: SESSION=xyz")
    assert token == "xyz" and cookie == "SESSION=xyz"
    assert SM.parse_credential("   ")[0] == ""


def test_token_login_rejected_by_portal(settings) -> None:
    async def scenario() -> str:
        servers = MockServers(open_after_s=30.0)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            await session.start()
            with pytest.raises(PortalError) as exc_info:
                await session.apply_manual_token("definitely-wrong-token")
            code = exc_info.value.code
            assert session.state.value in {"offline"}
            await session.close()
            await nca.close()
            return code
        finally:
            await servers.stop()

    assert run(scenario()) == "TOKEN_REJECTED"


def test_token_login_success_via_mock(settings) -> None:
    """Токен-мост сквозь mock: логин ЭЦП → cookie → apply_manual_token."""

    async def scenario() -> tuple:
        servers = MockServers(open_after_s=30.0, nca_password=PASSWORD)
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            await session.start()
            # Получаем настоящий cookie сессии обычным ЭЦП-входом
            from core.ncalayer_client import SecretPassword as SP

            session.set_password(SP(PASSWORD))
            await session.authenticate()
            cookie_header = "; ".join(
                f"{name}={value}" for name, value in session.client.cookies.items()
            )
            # Теперь «другой клиент» входит по этому cookie (мост из браузера)
            fresh = SessionManager(mock_settings, nca)
            await fresh.start()
            await fresh.apply_manual_token(cookie_header)
            assert fresh.token_only is True
            assert fresh.is_online
            state = fresh.state.value
            await fresh.close()
            await session.close()
            await nca.close()
            return state
        finally:
            await servers.stop()

    assert run(scenario()) == "online"
