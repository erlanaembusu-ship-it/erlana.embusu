"""Общие фикстуры тестов."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.license_guard import LicenseGuard


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "real_backup_store: не подменять резерв триала (реестр/домашний файл)",
    )


@pytest.fixture(autouse=True)
def _isolated_trial_backup(request, monkeypatch) -> None:
    """Резерв триала в памяти: тесты не пишут в реестр HKCU и ``$HOME``.

    Иначе прогон тестов на машине разработчика сдвигал бы триал и отметку
    «последний запуск» настоящего приложения.
    """
    if request.node.get_closest_marker("real_backup_store"):
        return
    store: dict[str, str] = {}
    monkeypatch.setattr(
        LicenseGuard, "_backup_get", lambda self, name: store.get(name, "")
    )
    monkeypatch.setattr(
        LicenseGuard,
        "_backup_set",
        lambda self, name, value: store.update({name: value}),
    )
