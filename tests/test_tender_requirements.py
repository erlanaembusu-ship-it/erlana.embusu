"""Чек-лист требований тендера из реального рендера страницы заявки.

Фикстура — фрагмент реального шага «Документы» заявки 17630537/73154497
(снято 2026-09-28): включает обязательное невыполненное (Прил.4, лицензии),
обязательное выполненное (Прил.15, 19), необязательное и строку без ссылки
(НДС).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.tender_requirements import (
    format_checklist,
    parse_requirements,
    requirement_source,
)

DOCS_HTML = """
<table>
<tr><th>Наименование документа</th><th>Обязательность</th></tr>
<tr><td>
 <span style="color: #5cb85c;font-size: 1.5em" class="glyphicon glyphicon-ok-circle"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/1253">Приложение 1 (Перечень лотов и условия поставки товаров)</a>
</td><td>Обязателен </td></tr>
<tr><td>
 <span style="color: #5cb85c;font-size: 1.5em" class="glyphicon glyphicon-ok-circle"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/3334">Приложение 15 (Техническая спецификация)</a>
</td><td>Обязателен </td></tr>
<tr><td>
 <span style="color: #d9534f;font-size: 1.5em" class="glyphicon glyphicon-remove-circle"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/3359">Приложение 4 (Информация о бенефициарном владении потенциального поставщика)</a>
</td><td>Обязателен </td></tr>
<tr><td>
 <span style="color: #5cb85c;font-size: 1.5em" class="glyphicon glyphicon-ok-circle"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/3328">Приложение 19 (Обеспечение заявки)</a>
</td><td>Обязателен </td></tr>
<tr><td>
 <span style="color: #f0ad4e;font-size: 1.5em" class="glyphicon glyphicon-exclamation-sign"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/19">Разрешения первой категории (Лицензии)</a>
</td><td>Обязателен </td></tr>
<tr><td>
 <span style="color: #777;font-size: 1.5em" class="glyphicon glyphicon-remove-circle"></span>
 <a href="https://v3bl.goszakup.gov.kz/ru/application/show_doc/17630537/73154497/3336">Приложение 20 (Сведения о субподрядчиках)</a>
</td><td>Не Обязателен </td></tr>
<tr><td>Свидетельство о постановке на учет по НДС</td><td>Не Обязателен </td></tr>
</table>
"""


def test_parse_rows_with_link_and_status() -> None:
    reqs = parse_requirements(DOCS_HTML)
    by_id = {r.doc_id: r for r in reqs if r.doc_id is not None}
    assert by_id[3359].required and not by_id[3359].done
    assert by_id[3328].required and by_id[3328].done
    assert by_id[19].required and not by_id[19].done
    assert by_id[3336].name.startswith("Приложение 20")
    assert not by_id[3336].required and not by_id[3336].done
    assert by_id[1253].done and by_id[1253].required


def test_parse_row_without_link() -> None:
    reqs = parse_requirements(DOCS_HTML)
    nds = [r for r in reqs if r.doc_id is None]
    assert len(nds) == 1
    assert nds[0].name == "Свидетельство о постановке на учет по НДС"
    assert nds[0].required is False and nds[0].done is False


def test_sources_map_to_actions() -> None:
    assert "Сформировать документ" in requirement_source(
        "Приложение 4 (Информация о бенефициарном владении потенциального поставщика)"
    )
    assert "ГБД ЕЛ" in requirement_source("Разрешения первой категории (Лицензии)")
    assert "кошел" in requirement_source("Приложение 19 (Обеспечение заявки)").lower()
    assert "портал" in requirement_source("Приложение 2 (Соглашение об участии)")


def test_checklist_puts_required_todo_first() -> None:
    text = format_checklist(parse_requirements(DOCS_HTML))
    lines = text.splitlines()
    assert lines[0] == "ОБЯЗАТЕЛЬНОЕ, НЕ ГОТОВО:"
    joined = "\n".join(lines)
    # Порядок: сначала обязательное неготовое, потом необязательное, потом готово.
    assert joined.index("✗ Приложение 4") < joined.index("· Приложение 20")
    assert "Готово (3): Приложение 1" in joined
    assert "✗ Разрешения первой категории" in joined
