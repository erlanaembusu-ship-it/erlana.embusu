"""Требования тендера к поставщику: разбор страницы заявки (шаг «Документы»).

У каждого тендера свой набор обязательных документов — универсального
шаблона нет. Перед подготовкой заявки FastBid читает страницу
``/ru/application/docs/{anno}/{app}`` и собирает чек-лист: название
документа, обязательность и отметку о выполненности (зелёная галочка
``glyphicon-ok-circle`` — документ принят порталом в ЭТОЙ заявке).

Источник знаний «кто готовит документ» — ``requirement_source``: правила
по названию документа (формирует портал / форма заявки / файл поставщика /
банк-гарантия / профиль участника). Правила дополняются по мере изучения
поданных заявок — см. docs/PORTAL_CONTRACT.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["DocRequirement", "parse_requirements", "requirement_source", "format_checklist"]

_ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S)
_LINK_RE = re.compile(
    r'href="[^"]*/application/show_doc/\d+/\d+/(\d+)[^"]*"[^>]*>([^<]+)'
)
_PLAIN_NAME_RE = re.compile(r"<td[^>]*>([^<]{8,200})</td>")
_REQUIRED_RE = re.compile(r"<td[^>]*>\s*Обязателен")


@dataclass(frozen=True, slots=True)
class DocRequirement:
    """Одно требование тендера: документ + обязательность + выполненность."""

    name: str
    required: bool
    done: bool
    doc_id: int | None  # None для строк без своей страницы (например, НДС)

    @property
    def source(self) -> str:
        return requirement_source(self.name)


def parse_requirements(docs_html: str) -> list[DocRequirement]:
    """Чек-лист из HTML шага «Документы» (реальный рендер портала)."""
    out: list[DocRequirement] = []
    for row in _ROW_RE.findall(docs_html):
        link = _LINK_RE.search(row)
        required = bool(_REQUIRED_RE.search(row))
        done = "glyphicon-ok-circle" in row
        if link:
            name = re.sub(r"\s+", " ", link.group(2)).strip()
            doc_id = int(link.group(1))
        else:
            # Строка без страницы (свидетельства, НДС): имя — из первой ячейки.
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            if len(cells) < 2:
                continue
            text = re.sub(r"<[^>]+>", " ", cells[0])
            name = re.sub(r"\s+", " ", text).strip()
            doc_id = None
            if not name:
                continue
        if not name:
            continue
        out.append(DocRequirement(name=name, required=required, done=done, doc_id=doc_id))
    return out


# -- Кто готовит документ (знания по поданным заявкам) ---------------------- #
_SOURCE_RULES: tuple[tuple[str, str], ...] = (
    ("Приложение 1 (", "формирует портал автоматически"),
    ("Приложение 2 (", "формирует портал автоматически"),
    ("Приложение 4 (", "форма заявки: заполнить бенефициаров → "
                      "«Сформировать документ» → подписать ЭЦП"),
    ("Приложение 15 (", "файл поставщика (техспецификация) + подпись ЭЦП"),
    ("Приложение 11 (", "квалификация (eDepository / данные участника)"),
    ("Приложение 19 (", "обеспечение: ЭБГ из банка (криптосокет) "
                        "или деньги с электронного кошелька"),
    ("Приложение 20 (", "субподрядчики: их квалификационные документы"),
    ("Разрешения", "профиль участника: перезапрос лицензий/разрешений (ГБД ЕЛ)"),
    ("Свидетельство о постановке на учет по НДС", "профиль участника"),
    ("Свидетельства, сертификаты", "диск поставщика (папка docs)"),
)


def requirement_source(name: str) -> str:
    """Подсказка: где взять/что сделать для документа с таким названием."""
    for marker, hint in _SOURCE_RULES:
        if marker.lower() in name.lower():
            return hint
    return "уточните на странице документа заявки"


def format_checklist(requirements: list[DocRequirement]) -> str:
    """Человекочитаемый чек-лист: сначала критичное (обязательное не готово)."""
    todo_req = [r for r in requirements if r.required and not r.done]
    todo_opt = [r for r in requirements if not r.required and not r.done]
    done = [r for r in requirements if r.done]
    lines: list[str] = []
    if todo_req:
        lines.append("ОБЯЗАТЕЛЬНОЕ, НЕ ГОТОВО:")
        for r in todo_req:
            lines.append(f"  ✗ {r.name} — {r.source}")
    if todo_opt:
        lines.append("Необязательное, не готово:")
        for r in todo_opt:
            lines.append(f"  · {r.name} — {r.source}")
    if done:
        lines.append(f"Готово ({len(done)}): " + "; ".join(r.name.split(" (")[0] for r in done))
    if not todo_req and not todo_opt:
        lines.append("Все требования тендера выполнены.")
    return "\n".join(lines)
