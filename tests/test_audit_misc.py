"""Регрессии аудита: подбор ниши, автоцена, устойчивость журнала."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.niche_blueprints import PricingRule, resolve_blueprint
from utils.logger import UILogSink, get_logger, setup_logging


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Лекарственные средства для отделения реанимации", "medical_supply"),
        ("СМР по объекту школы", "construction"),
        ("Поставка крупы гречневой", "food_supply"),
        # подстрока внутри слова больше не определяет нишу
        ("Игровая консоль", "generic"),
        ("Кабель высоковольтный", "generic"),
        ("Специальная одежда", "generic"),
        # ничья между нишами → универсальный шаблон
        ("ИБП источник бесперебойного питания для серверной", "generic"),
    ],
)
def test_resolve_blueprint_word_start_and_ties(text: str, expected: str) -> None:
    assert resolve_blueprint(text).id == expected


@pytest.mark.parametrize("amount", [1000.006, 333.335, 4_500_000.0, 0.015])
def test_suggested_price_never_fails_own_validation(amount: float) -> None:
    rule = PricingRule()
    price = rule.suggest(amount)
    assert price is not None
    assert rule.validate(price, amount) is None


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), -1.0, 0.0, None])
def test_suggested_price_rejects_bad_lot_amount(amount: float | None) -> None:
    assert PricingRule().suggest(amount) is None


def test_logging_setup_is_robust(monkeypatch) -> None:
    monkeypatch.setattr(logging, "raiseExceptions", False)
    sink = UILogSink()
    for _ in range(3):
        setup_logging(None, "НЕТ_ТАКОГО_УРОВНЯ", console=False, ui_sink=sink)
    assert logging.getLogger().level == logging.DEBUG
    assert len(sink.filters) == 1  # фильтр секретов не копится
    # ошибка форматирования не долетает до вызывающего кода
    get_logger("audit").info("%.1f", None)
    get_logger("audit").info("Authorization: Bearer abc+def/ghi=jkl123")
    messages = [record.message for record in sink.drain()]
    assert any("Bearer ***" in item for item in messages)
    assert not any("abc+def" in item for item in messages)
