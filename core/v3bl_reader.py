"""Чтение данных лотов со страниц кабинета v3bl (вместо OWS).

Реестр OWS требует доступа к унифицированным сервисам (выдаёт ЦЭФ).
Страницы кабинета (v3bl) отдают те же данные серверным HTML в сессии
поставщика — этот модуль их парсит. Структура страницы «Просмотр
объявления»: подписанные readonly-поля (Номер объявления, Срок начала
приема заявок, …) и вкладка «Лоты» с таблицей.
"""

from __future__ import annotations

import re
from typing import Any

from config.settings import WatcherSettings
from core.lot_watcher import LotState

_LABEL_RE = r'([^<>"]{4,70}?)\s*</(?:th|td|label|span|b|strong)>'
_VALUE_RE = r'value="([^"]*)"'
_TEXT_RE = r">([^<>]{2,120})<"


def _field_after(html: str, label: str) -> str:
    """Значение input'а, следующего за подписью поля (Yii-рендер)."""
    match = re.search(
        re.escape(label) + r"[\s\S]{0,400}?value=\"([^\"]*)\"", html
    )
    return match.group(1).strip() if match else ""


def _text_after(html: str, label: str, span: int = 400) -> str:
    match = re.search(re.escape(label) + r"[\s\S]{0,%d}" % span, html)
    if not match:
        return ""
    chunk = re.sub(r"<[^>]+>", " ", match.group(0))
    return re.sub(r"\s+", " ", chunk).strip()


def parse_announce_page(html: str) -> dict[str, Any]:
    """Разбирает страницу «Просмотр объявления № …»."""
    return {
        "anno_number": _field_after(html, "Номер объявления"),
        "anno_name": _field_after(html, "Наименование объявления"),
        "status": _field_after(html, "Статус объявления"),
        "start_date": _field_after(html, "Срок начала приема заявок"),
        "end_date": _field_after(html, "Срок окончания приема заявок"),
        "publish_date": _field_after(html, "Дата публикации объявления"),
    }


def parse_lots_tab(html: str) -> list[dict[str, Any]]:
    """Разбирает вкладку «Лоты»: строки таблицы с номерами лотов."""
    lots: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"(\d{6,12}-[А-ЯA-Z0-9]{1,4})", html
    ):
        lot_number = match.group(1)
        if lot_number in seen:
            continue
        seen.add(lot_number)
        tail = html[match.start() : match.start() + 3000]
        name_m = re.search(
            r"Наименование и описание лота</td>\s*<td[^>]*>([^<]{5,200})<", tail
        ) or re.search(r"<td[^>]*>(Работы по[^<]{5,200})<", tail)
        amount_m = re.search(r'amount["\s>:]{1,10}([\d\s]{3,15}\d)\.00', tail) or (
            re.search(r"([\d\s]{7,15})\.00", tail)
        )
        lots.append(
            {
                "lot_number": lot_number,
                "name": (name_m.group(1).strip() if name_m else ""),
                "amount_text": (amount_m.group(1).replace(" ", "") if amount_m else ""),
            }
        )
    # Ложные срабатывания (номер объявления без данных лота) — вон.
    return [lot for lot in lots if lot["name"] and lot["amount_text"]]


def lot_state_from_announce(
    anno: dict[str, Any],
    lot: dict[str, Any],
    settings: WatcherSettings,
) -> LotState:
    """Собирает LotState из разобранной страницы объявления."""
    from core.lot_watcher import parse_portal_datetime

    start = parse_portal_datetime(anno.get("start_date") or "")
    end = parse_portal_datetime(anno.get("end_date") or "")
    amount_text = lot.get("amount_text") or "0"
    try:
        amount = float(amount_text)
    except ValueError:
        amount = 0.0
    tz = settings.watcher.portal_tz
    return LotState(
        lot_id=int(re.sub(r"\D", "", lot.get("lot_number") or "") or 0),
        lot_number=lot.get("lot_number") or "",
        name=lot.get("name") or anno.get("anno_name") or "",
        description=lot.get("name") or "",
        amount=amount,
        count=1.0,
        status_id=220 if "прием заявок" in (anno.get("status") or "").lower() else 210,
        status_name=anno.get("status") or "",
        status_code="ACCEPTING"
        if "прием заявок" in (anno.get("status") or "").lower()
        else "PUBLISHED",
        trd_buy_id=int(re.sub(r"\D", "", anno.get("anno_number") or "") or 0),
        trd_buy_number=anno.get("anno_number") or "",
        start_date=start.strftime("%Y-%m-%d %H:%M:%S")
        if start
        else anno.get("start_date") or "",
        end_date=end.strftime("%Y-%m-%d %H:%M:%S") if end else anno.get("end_date") or "",
        kato=(),
        raw={
            "source": "v3bl_html",
            "start_dt": start.timestamp() if start else None,
            "portal_tz": tz,
        },
    )
