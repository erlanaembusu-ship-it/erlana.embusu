"""Регрессии аудита лицензирования: подделка/будущая дата триала, naive-даты,
перевод часов назад, bind_check на истёкшем триале, выпуск без БИН/срока.

Резервное хранилище триала (реестр HKCU / домашний файл) подменяется словарём
на экземпляре guard — реальные реестр и домашняя папка не затрагиваются.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import load_settings
from core.license_guard import License as LicenseDoc
from core.license_guard import LicenseGuard, generate_keypair, sign_license
from utils.mock_server import TEST_BIN


def _iso(delta: timedelta, *, naive: bool = False) -> str:
    moment = datetime.now(timezone.utc) + delta
    if naive:
        moment = moment.replace(tzinfo=None)
    return moment.isoformat(timespec="seconds")


@pytest.fixture
def lic(tmp_path, monkeypatch) -> SimpleNamespace:
    private_pem, public_pem = generate_keypair()
    base = load_settings()
    isolated = replace(
        base.license,
        public_key_pem=public_pem,
        license_path=tmp_path / "license.json",
        trial_path=tmp_path / "trial.json",
        trial_days=14,
        offline_grace_days=7,
        require_bin_match=True,
    )
    guard = LicenseGuard(base.with_(license=isolated))
    backup: dict[str, str] = {}
    monkeypatch.setattr(guard, "_backup_get", lambda name: backup.get(name, ""))
    monkeypatch.setattr(guard, "_backup_set", backup.__setitem__)
    return SimpleNamespace(
        guard=guard, private_pem=private_pem, settings=isolated, backup=backup
    )


def _write_trial(lic: SimpleNamespace, started_at: str, **extra: str) -> None:
    lic.settings.trial_path.write_text(
        json.dumps({"hwid": lic.guard.hwid, "started_at": started_at, **extra}),
        encoding="utf-8",
    )


def _trial_file(lic: SimpleNamespace) -> dict:
    return json.loads(lic.settings.trial_path.read_text(encoding="utf-8"))


def test_tampered_trial_store_does_not_extend_trial(lic) -> None:
    old = _iso(timedelta(days=-30))
    _write_trial(lic, old)
    lic.backup["TrialStart"] = old
    expired = lic.guard.check(force=True)
    assert expired.valid is False and expired.trial_days_left == 0

    # Подделка только trial.json: дата «в будущее»
    _write_trial(lic, "2099-01-01T00:00:00+00:00")
    after_file = lic.guard.check(force=True)
    assert after_file.valid is False and after_file.trial_days_left == 0
    # Ранняя дата записана обратно в оба хранилища
    assert lic.backup["TrialStart"] == old
    assert _trial_file(lic)["started_at"] == old

    # Подделка только резерва
    lic.backup["TrialStart"] = _iso(timedelta(days=-1))
    after_backup = lic.guard.check(force=True)
    assert after_backup.valid is False and after_backup.trial_days_left == 0
    assert lic.backup["TrialStart"] == old


def test_future_trial_start_is_rejected(lic) -> None:
    future = _iso(timedelta(days=2))
    _write_trial(lic, future)
    lic.backup["TrialStart"] = future
    status = lic.guard.check(force=True)
    assert status.valid is False and status.mode == "invalid"
    assert "будущем" in status.reason
    assert lic.backup["TrialStart"] == future  # подделка не «узаконена»

    # Небольшой уход часов (в пределах 5 мин) — не подделка
    near = _iso(timedelta(minutes=2))
    _write_trial(lic, near)
    lic.backup["TrialStart"] = near
    ok = lic.guard.check(force=True)
    assert ok.valid is True and ok.mode == "trial" and ok.trial_days_left == 14


def test_naive_trial_dates_do_not_crash(lic) -> None:
    lic.backup["TrialStart"] = _iso(timedelta(days=-3), naive=True)
    lic.backup["LastSeen"] = _iso(timedelta(minutes=-5), naive=True)
    status = lic.guard.check(force=True)
    assert status.mode == "trial" and status.valid is True
    assert status.trial_days_left == 11

    _write_trial(
        lic,
        _iso(timedelta(days=-3), naive=True),
        last_seen=_iso(timedelta(minutes=-1), naive=True),
    )
    again = lic.guard.check(force=True)
    assert again.valid is True and again.trial_days_left == 11


@pytest.mark.skipif(sys.platform == "win32", reason="на Windows резерв в реестре")
@pytest.mark.real_backup_store
def test_naive_home_backup_file_does_not_crash(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    _private, public_pem = generate_keypair()
    base = load_settings()
    guard = LicenseGuard(
        base.with_(
            license=replace(
                base.license,
                public_key_pem=public_pem,
                license_path=tmp_path / "license.json",
                trial_path=tmp_path / "trial.json",
                trial_days=14,
            )
        )
    )
    (home / f".fastbid_{guard._backup_value_name('TrialStart')}").write_text(
        _iso(timedelta(days=-3), naive=True), encoding="utf-8"
    )
    status = guard.check(force=True)
    assert status.valid is True and status.trial_days_left == 11
    assert (home / f".fastbid_{guard._backup_value_name('LastSeen')}").read_text(
        encoding="utf-8"
    )


def test_clock_rollback_is_detected(lic) -> None:
    first = lic.guard.check(force=True)
    assert first.valid is True and first.mode == "trial"
    assert lic.backup["LastSeen"] and _trial_file(lic)["last_seen"]

    # Часы «переведены» на 3 дня назад относительно последнего запуска
    lic.backup["LastSeen"] = _iso(timedelta(days=3))
    rolled = lic.guard.check(force=True)
    assert rolled.valid is False and rolled.mode == "invalid"
    assert "время" in rolled.reason.lower()
    assert lic.guard.bind_check(TEST_BIN)

    # Та же метка только в trial.json (резерв удалён)
    del lic.backup["LastSeen"]
    data = _trial_file(lic)
    data["last_seen"] = _iso(timedelta(days=3))
    lic.settings.trial_path.write_text(json.dumps(data), encoding="utf-8")
    assert lic.guard.check(force=True).valid is False

    # Уход часов меньше часа допустим; метка при этом не уменьшается
    ahead = _iso(timedelta(minutes=30))
    data["last_seen"] = ahead
    lic.settings.trial_path.write_text(json.dumps(data), encoding="utf-8")
    assert lic.guard.check(force=True).valid is True
    assert lic.backup["LastSeen"] == ahead

    # Мусор в метках не роняет проверку
    data["last_seen"] = 12345
    lic.settings.trial_path.write_text(json.dumps(data), encoding="utf-8")
    lic.backup["LastSeen"] = "not-a-date"
    assert lic.guard.check(force=True).valid is True


def test_clock_rollback_blocks_full_license(lic) -> None:
    document = LicenseGuard.issue("TOO", TEST_BIN, lic.guard.hwid, 30, lic.private_pem)
    lic.settings.license_path.write_text(json.dumps(document), encoding="utf-8")
    assert lic.guard.check(TEST_BIN, force=True).valid is True

    lic.backup["LastSeen"] = _iso(timedelta(days=60))
    status = lic.guard.check(force=True)
    assert status.valid is False and "время" in status.reason.lower()


def test_bind_check_rejects_expired_trial(lic) -> None:
    active = lic.guard.check(force=True)
    assert active.valid is True and lic.guard.bind_check(TEST_BIN) is None

    old = _iso(timedelta(days=-30))
    _write_trial(lic, old)
    lic.backup["TrialStart"] = old
    problem = lic.guard.bind_check(TEST_BIN)
    assert problem and "истёк" in problem


@pytest.mark.parametrize(
    "bad_bin", ["", "abc", "12345", "1234567890123", "12345678901a", "١٢٣٤٥٦٧٨٩٠١٢"]
)
def test_issue_rejects_bad_bin(lic, bad_bin: str) -> None:
    with pytest.raises(ValueError, match="12 цифр"):
        LicenseGuard.issue("TOO", bad_bin, lic.guard.hwid, 30, lic.private_pem)


@pytest.mark.parametrize("bad_days", ["30", 1.5, True, None])
def test_issue_rejects_non_integer_days(lic, bad_days) -> None:
    with pytest.raises(ValueError, match="Срок"):
        LicenseGuard.issue("TOO", TEST_BIN, lic.guard.hwid, bad_days, lic.private_pem)


def test_issue_accepts_formatted_bin(lic) -> None:
    document = LicenseGuard.issue(
        "TOO", "1234 5678-9012", lic.guard.hwid, 30, lic.private_pem
    )
    assert document["bin_iin"] == "123456789012"


def test_license_with_empty_bin_is_rejected(lic) -> None:
    unbound = sign_license(
        LicenseDoc(
            licensee="X",
            bin_iin="",
            hwid=lic.guard.hwid,
            expires_at=_iso(timedelta(days=365)),
        ),
        lic.private_pem,
    )
    lic.settings.license_path.write_text(json.dumps(unbound), encoding="utf-8")
    status = lic.guard.check(force=True)
    assert status.valid is False and status.mode == "invalid"
    assert "БИН" in status.reason
    assert lic.guard.bind_check("999999999999")

    lic.guard.settings = replace(lic.settings, require_bin_match=False)
    assert lic.guard.check("999999999999", force=True).valid is True


def test_cli_issue_license_validation(tmp_path, capsys) -> None:
    import main as app_main

    private_pem, _public = generate_keypair()
    key = tmp_path / "vendor.pem"
    key.write_text(private_pem, encoding="utf-8")
    out = tmp_path / "issued.json"
    common = ["--issue-license", "--target-hwid", "A" * 32, "--to", str(out)]

    def run(*extra: str) -> tuple[int, str]:
        code = app_main.main([*common, *extra])
        return code, capsys.readouterr().out

    code, text = run("--private-key", str(key), "--bin", "abc", "--days", "30")
    assert code == 2 and "12 цифр" in text
    code, text = run("--private-key", str(key), "--bin", TEST_BIN, "--days", "-5")
    assert code == 2 and "--days" in text
    code, _text = run("--private-key", str(key), "--bin", TEST_BIN, "--days", "0")
    assert code == 2
    missing = str(tmp_path / "missing.pem")
    code, text = run("--private-key", missing, "--bin", TEST_BIN)
    assert code == 2 and "приватный ключ" in text
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("not a key", encoding="utf-8")
    code, text = run("--private-key", str(garbage), "--bin", TEST_BIN)
    assert code == 2 and "недействителен" in text
    assert not out.exists()

    code, _text = run("--private-key", str(key), "--bin", TEST_BIN, "--days", "30")
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["bin_iin"] == TEST_BIN
