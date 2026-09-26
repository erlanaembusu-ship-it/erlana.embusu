"""Регрессии аудита NCALayer-клиента.

Порты моков уникальные (187xx/0): 8643/13580 заняты параллельными прогонами.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
from dataclasses import replace
from typing import Any

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
from websockets.exceptions import ConnectionClosed

from config.settings import NCALayerSettings
from core.ncalayer_client import (
    KeyInfo,
    NCALayerClient,
    NCALayerError,
    SecretPassword,
    SignItem,
    b64decode,
    cms_encapsulated_content,
    extract_bin_iin_from_certificate,
)
from utils.mock_server import TEST_BIN, MockNCALayer, make_test_certificate

COMPANY_BIN = "123456789012"
EMPLOYEE_IIN = "880101300123"
# Серийный номер сертификата (hex, 40 знаков) — не БИН
HEX_SERIAL = "3a0f" + "12345678" * 4 + "abcd"


def nca_settings(port: int) -> NCALayerSettings:
    return replace(NCALayerSettings(), host="127.0.0.1", port=port, scheme="ws")


def fake_signature(data: str | list[str]) -> str | list[str]:
    if isinstance(data, list):
        return [fake_signature(item) for item in data]  # type: ignore[misc]
    return base64.b64encode(b"SIG:" + base64.b64decode(data)).decode("ascii")


def build_cert(attrs: list[tuple[ObjectIdentifier, str]]) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(oid, value) for oid, value in attrs])
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


# --------------------------------------------------------------------------- #
# C1: запоздавшее приветствие / ответ без status / чужая CMS
# --------------------------------------------------------------------------- #
def test_late_greeting_does_not_swap_signatures() -> None:
    async def handler(ws: Any) -> None:
        await asyncio.sleep(0.4)  # приветствие позже, чем клиент его ждёт
        await ws.send(json.dumps({"result": {"version": "1.4"}}))
        async for raw in ws:
            data = json.loads(raw)["args"]["data"]
            reply = {"status": True, "body": {"result": fake_signature(data)}}
            await ws.send(json.dumps(reply))

    async def scenario() -> None:
        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            client = NCALayerClient(nca_settings(port))
            client.greeting_timeout = 0.1
            try:
                a = await client.sign_cms_batch(
                    [SignItem(key="A", data=b"AAAA")], batch=False, timeout=5
                )
                b = await client.sign_cms_batch(
                    [SignItem(key="B", data=b"BBBB")], batch=False, timeout=5
                )
            finally:
                await client.close()
        assert b64decode(a[0].signature_b64) == b"SIG:AAAA"
        assert b64decode(b[0].signature_b64) == b"SIG:BBBB"
        assert client.greeting == {"result": {"version": "1.4"}}

    asyncio.run(scenario())


def test_basics_reply_without_status_is_rejected_and_socket_reset() -> None:
    replies = iter([{"result": "c3RhbGU="}])

    async def handler(ws: Any) -> None:
        await ws.send(json.dumps({"result": {"version": "1.4"}}))
        async for raw in ws:
            reply = next(replies, None)
            if reply is None:
                data = json.loads(raw)["args"]["data"]
                reply = {"status": True, "body": {"result": fake_signature(data)}}
            await ws.send(json.dumps(reply))

    async def scenario() -> None:
        async with websockets.serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            client = NCALayerClient(nca_settings(port))
            try:
                with pytest.raises(NCALayerError) as info:
                    await client.sign_cms_batch([SignItem(key="A", data=b"AAAA")])
                assert info.value.code == "NCA_BAD_REPLY"
                assert not client.connected  # сокет сброшен
                doc = await client.sign_cms_batch([SignItem(key="B", data=b"BBBB")])
            finally:
                await client.close()
        assert b64decode(doc[0].signature_b64) == b"SIG:BBBB"

    asyncio.run(scenario())


def test_cms_content_mismatch_is_rejected_without_fallback() -> None:
    async def scenario() -> None:
        nca = await MockNCALayer(port=18784).start()
        original = nca._sign_one  # type: ignore[attr-defined]
        other = base64.b64encode(b"other document").decode("ascii")
        nca._sign_one = lambda _item, fmt: original(other, fmt)  # type: ignore[attr-defined]
        client = NCALayerClient(nca_settings(nca.port))
        try:
            with pytest.raises(NCALayerError) as info:
                await client.sign_cms_batch(
                    [SignItem(key="a", data=b"alpha"), SignItem(key="b", data=b"beta")]
                )
            assert info.value.code == "NCA_SIGNATURE_MISMATCH"
            assert len(nca.sign_requests) == 1
            assert not client.connected
        finally:
            await client.close()
            await nca.stop()

    asyncio.run(scenario())


def test_cms_encapsulated_content_parses_mock_signature() -> None:
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    key, cert = make_test_certificate()
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"payload")
        .add_signer(cert, key, hashes.SHA256())
    )
    assert cms_encapsulated_content(builder.sign(Encoding.DER, [])) == b"payload"
    detached = builder.sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    assert cms_encapsulated_content(detached) is None
    assert cms_encapsulated_content(b"SIG:not-cms") is None

    # Текстовый режим S/MIME меняет LF→CRLF — это тот же документ.
    text = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"line1\nline2")
        .add_signer(cert, key, hashes.SHA256())
        .sign(Encoding.DER, [])
    )
    signature = base64.b64encode(text).decode("ascii")
    client = NCALayerClient(nca_settings(18786))
    client._check_cms_content("doc", b"line1\nline2", signature)
    with pytest.raises(NCALayerError):
        client._check_cms_content("doc", b"line1\nline3", signature)


# --------------------------------------------------------------------------- #
# H1: переподключение и узкий fallback
# --------------------------------------------------------------------------- #
def test_dropped_socket_reconnects_with_single_batch_call() -> None:
    async def scenario() -> None:
        nca = await MockNCALayer(port=18781).start()
        client = NCALayerClient(nca_settings(nca.port))
        try:
            await client.connect()
            await nca.stop()  # перезапуск NCALayer рвёт соединение
            await nca.start()
            await asyncio.sleep(0.05)
            items = [SignItem(key=f"d{i}", data=f"doc{i}".encode()) for i in range(3)]
            docs = await client.sign_cms_batch(items)
            assert all(doc.from_batch for doc in docs)
            assert nca.counters["batch_sign"] == 1
            assert nca.counters["sign"] == 0
            assert nca.counters["dialogs"] == 1
            assert client.stats["reconnects"] >= 1
        finally:
            await client.close()
            await nca.stop()

    asyncio.run(scenario())


def test_send_on_dead_socket_is_retried_once_after_reconnect() -> None:
    async def scenario() -> None:
        nca = await MockNCALayer(port=18785).start()
        client = NCALayerClient(nca_settings(nca.port))
        try:
            ws = await client.connect()

            async def dead_send(*_args: Any, **_kwargs: Any) -> None:
                raise ConnectionClosed(None, None)

            ws.send = dead_send  # type: ignore[method-assign]
            items = [SignItem(key="a", data=b"alpha"), SignItem(key="b", data=b"beta")]
            docs = await client.sign_cms_batch(items)
            assert [doc.from_batch for doc in docs] == [True, True]
            assert nca.counters["batch_sign"] == 1
            assert nca.counters["connections"] == 2
        finally:
            await client.close()
            await nca.stop()

    asyncio.run(scenario())


def test_bad_password_is_not_retried_sequentially() -> None:
    async def scenario() -> None:
        nca = MockNCALayer(port=18782)
        nca.require_password = True
        await nca.start()
        client = NCALayerClient(nca_settings(nca.port))
        try:
            items = [SignItem(key="a", data=b"alpha"), SignItem(key="b", data=b"beta")]
            with pytest.raises(NCALayerError) as info:
                await client.sign_cms_batch(items, password=SecretPassword("wrong"))
            assert info.value.code == "BAD_PASSWORD"
            assert len(nca.sign_requests) == 1  # ни одного поштучного повтора
            assert nca.counters["sign"] == 0
        finally:
            await client.close()
            await nca.stop()

    asyncio.run(scenario())


def test_timeout_is_not_retried_sequentially() -> None:
    async def scenario() -> None:
        nca = await MockNCALayer(port=18783, delay_ms=800).start()
        client = NCALayerClient(nca_settings(nca.port))
        try:
            items = [SignItem(key="a", data=b"alpha"), SignItem(key="b", data=b"beta")]
            with pytest.raises(NCALayerError) as info:
                await client.sign_cms_batch(items, timeout=0.3)
            assert info.value.code == "NCA_TIMEOUT"
            await asyncio.sleep(0.2)
            assert len(nca.sign_requests) == 1
        finally:
            await client.close()
            await nca.stop()

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# H3/M1: БИН/ИИН из сертификата и getKeyInfo
# --------------------------------------------------------------------------- #
def test_company_certificate_yields_bin_not_employee_iin() -> None:
    cert = build_cert(
        [
            (NameOID.COMMON_NAME, "ИВАНОВ ИВАН"),
            (NameOID.SURNAME, "ИВАНОВ"),
            (NameOID.SERIAL_NUMBER, f"IIN{EMPLOYEE_IIN}"),
            (NameOID.COUNTRY_NAME, "KZ"),
            (NameOID.ORGANIZATION_NAME, "ТОО X"),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, f"BIN{COMPANY_BIN}"),
        ]
    )
    assert extract_bin_iin_from_certificate(cert) == COMPANY_BIN
    assert KeyInfo.from_certificate(cert).bin_iin == COMPANY_BIN

    individual = build_cert(
        [
            (NameOID.COMMON_NAME, "ИВАНОВ ИВАН"),
            (NameOID.SERIAL_NUMBER, f"IIN{EMPLOYEE_IIN}"),
        ]
    )
    assert extract_bin_iin_from_certificate(individual) == EMPLOYEE_IIN


def test_phone_in_cn_is_never_taken_as_bin() -> None:
    phone_only = build_cert([(NameOID.COMMON_NAME, "Tel 777123456789")])
    assert extract_bin_iin_from_certificate(phone_only) == ""

    with_oid = build_cert(
        [
            (NameOID.COMMON_NAME, "Tel 777123456789"),
            (ObjectIdentifier("1.2.398.3.3.4.1.1"), COMPANY_BIN),
        ]
    )
    assert extract_bin_iin_from_certificate(with_oid) == COMPANY_BIN


def test_key_info_from_raw_ignores_certificate_serial() -> None:
    legacy = {
        "alias": "a",
        "algorithm": "ECGOST34310",
        "subjectDn": (
            f"CN=ИВАНОВ ИВАН,SERIALNUMBER=IIN{EMPLOYEE_IIN},O=ТОО X,OU=BIN{COMPANY_BIN}"
        ),
        "serialNumber": HEX_SERIAL,
    }
    assert KeyInfo.from_raw(legacy).bin_iin == COMPANY_BIN
    assert KeyInfo.from_raw({"serialNumber": HEX_SERIAL}).bin_iin == ""
    assert KeyInfo.from_raw({"serialNumber": "9" * 30}).bin_iin == ""
    assert KeyInfo.from_raw({"binIin": TEST_BIN}).bin_iin == TEST_BIN


def test_mock_certificate_matches_nuc_layout() -> None:
    _key, cert = make_test_certificate()
    serial = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
    unit = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0]
    assert str(serial).startswith("IIN") and str(serial)[3:] != TEST_BIN
    assert unit.value == f"BIN{TEST_BIN}"
    assert extract_bin_iin_from_certificate(cert) == TEST_BIN


# --------------------------------------------------------------------------- #
# L2: IPv6 loopback
# --------------------------------------------------------------------------- #
def test_ipv6_loopback_urls_are_bracketed() -> None:
    v6 = replace(NCALayerSettings(), host="::1", port=13579, scheme="wss")
    assert v6.basics_url == "wss://[::1]:13579/kz.gov.pki.knca.basics"
    assert v6.legacy_url == "wss://[::1]:13579/kz.gov.pki.knca"
    v4 = replace(v6, host="127.0.0.1")
    assert v4.basics_url == "wss://127.0.0.1:13579/kz.gov.pki.knca.basics"
