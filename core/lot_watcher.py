"""Адаптивный наблюдатель лота: T0-триггер открытия приёма заявок.

Что важно
---------
* **T0 берётся из данных портала, а не «на глаз».** Приём заявок открывается в
  ``TrdBuy.startDate`` (подтверждено схемой API v3:
  https://ows.goszakup.gov.kz/help/v3/schema/trdbuy.doc.html — «Дата начала
  приема заявок»). Для повторных закупок портал публикует ``repeatStartDate``.
* **Часы синхронизируются с сервером.** Смещение считается по заголовку
  ``Date`` ответа: каждая выборка задаёт интервал допустимых смещений, интервалы
  пересекаются, а зонды на смене секунды сужают погрешность до уровня RTT
  (``refine_clock``), поэтому локальные кривые часы не сдвигают выстрел.
* **Расписание адаптивное.** Чем ближе T0, тем чаще опрос: от 180 с за три
  часа до 200 мс у самого открытия. Жёсткий пол — ``min_interval_hard``,
  чтобы не «долбить» портал.
* **Двойное срабатывание.** Точный локальный таймер, привязанный к часам
  сервера, плюс подтверждение реальным статусом лота: заявка не уйдёт ни
  раньше окна, ни с опозданием из-за лишнего сетевого раунда.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from zoneinfo import ZoneInfo

from config.settings import AppSettings
from core.session_manager import PortalError, SessionManager
from utils.logger import BUS, get_logger

__all__ = ["LOT_QUERY", "ClockSync", "LotState", "LotWatcher", "parse_portal_datetime"]

# Насколько должен «уехать» T0, чтобы таймер был перепланирован (секунды).
T0_RESCHEDULE_EPSILON = 0.5


# Запрос лота: только поля, реально существующие в схеме v3 (Lots + TrdBuy).
LOT_QUERY = """
query LotState($ids: [Int!], $limit: Int!) {
  Lots(filter: {id: $ids}, limit: $limit) {
    id
    lotNumber
    nameRu
    descriptionRu
    amount
    count
    refLotStatusId
    trdBuyId
    trdBuyNumberAnno
    customerBin
    customerNameRu
    lastUpdateDate
    unionLots
    dumping
    isConstructionWork
    plnPointKatoList
    RefLotsStatus { id nameRu nameKz code }
    TrdBuy {
      id
      numberAnno
      nameRu
      totalSum
      countLots
      refBuyStatusId
      refTradeMethodsId
      startDate
      endDate
      repeatStartDate
      repeatEndDate
      publishDate
      customerBin
      customerNameRu
      RefBuyStatus { id nameRu nameKz code }
    }
  }
}
"""

_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y %H:%M",
)


def parse_portal_datetime(value: Any, tz_name: str = "Asia/Almaty") -> datetime | None:
    """Разбирает дату портала в aware-datetime.

    Портал отдаёт даты строками без зоны (например ``2026-09-21 10:00:00``),
    подразумевая казахстанское время. Если строка содержит зону — она
    уважается как есть.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=_zone(tz_name))
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=_zone(tz_name))
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=_zone(tz_name))
        except ValueError:
            continue
    return None


def _zone(tz_name: str) -> timezone | ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except Exception:  # pragma: no cover - отсутствует tzdata
        return timezone(timedelta(hours=5))


@dataclass(slots=True)
class ClockSync:
    """Смещение локальных часов относительно часов портала.

    Заголовок ``Date`` имеет разрешение 1 с и округляется ВНИЗ, поэтому одна
    выборка задаёт не точку, а интервал ``[D − received, D + 1 − sent]``.
    Интервалы всех выборок пересекаются, оценка — середина пересечения.
    Точечная оценка (min-RTT или max) занижала смещение на 0…1 с, и T0
    срабатывал с опозданием до секунды. Повтор запроса лишь расширяет
    интервал своей выборки и оценку не сдвигает. Системные часы не трогаем.
    """

    offset_s: float = 0.0
    best_rtt_ms: float = float("inf")
    samples: int = 0
    last_sync_at: float = 0.0
    low_s: float = float("-inf")
    high_s: float = float("inf")

    @property
    def uncertainty_ms(self) -> float:
        """Полуширина интервала смещения (inf — выборок ещё не было)."""
        if not self.samples:
            return float("inf")
        return (self.high_s - self.low_s) * 500.0

    def update_from_headers(
        self, headers: Mapping[str, str], sent_at: float, received_at: float
    ) -> bool:
        """Сужает интервал смещения по заголовку ``Date``; True — оценка изменилась."""
        raw_date = headers.get("date") or headers.get("Date")
        if not raw_date:
            return False
        try:
            server_dt = parsedate_to_datetime(raw_date)
        except (TypeError, ValueError):
            return False
        if server_dt is None:
            return False
        if server_dt.tzinfo is None:
            server_dt = server_dt.replace(tzinfo=timezone.utc)
        server_s = server_dt.timestamp()
        rtt_ms = (received_at - sent_at) * 1000.0
        self.samples += 1
        self.best_rtt_ms = min(self.best_rtt_ms, rtt_ms)
        self.last_sync_at = time.time()
        low = server_s - received_at
        high = server_s + 1.0 - sent_at
        new_low = max(self.low_s, low)
        new_high = min(self.high_s, high)
        if new_low > new_high:
            # Выборка противоречит накопленной оценке: часы (локальные или
            # серверные) переведены — начинаем с этой выборки.
            new_low, new_high = low, high
        changed = (new_low, new_high) != (self.low_s, self.high_s)
        self.low_s, self.high_s = new_low, new_high
        self.offset_s = (new_low + new_high) / 2.0
        return changed

    def server_now(self) -> float:
        """Текущее время сервера (epoch-секунды)."""
        return time.time() + self.offset_s

    def server_datetime(self, tz_name: str = "Asia/Almaty") -> datetime:
        return datetime.fromtimestamp(self.server_now(), tz=_zone(tz_name))

    def describe(self) -> str:
        return (
            f"смещение {self.offset_s * 1000:+.0f} ±{self.uncertainty_ms:.0f} мс "
            f"(RTT {self.best_rtt_ms:.0f} мс, проб {self.samples})"
        )


@dataclass(slots=True)
class LotState:
    """Снимок состояния лота (поля из схемы GraphQL v3)."""

    lot_id: int
    lot_number: str = ""
    name: str = ""
    description: str = ""
    amount: float = 0.0
    count: float = 0.0
    status_id: int = 0
    status_name: str = ""
    status_code: str = ""
    trd_buy_id: int = 0
    trd_buy_number: str = ""
    buy_status_id: int = 0
    buy_status_name: str = ""
    start_date: str = ""
    end_date: str = ""
    repeat_start_date: str = ""
    repeat_end_date: str = ""
    publish_date: str = ""
    customer_bin: str = ""
    customer_name: str = ""
    kato: tuple[str, ...] = ()
    is_construction: bool = False
    dumping: bool = False
    last_update: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    fetched_at: float = 0.0
    rtt_ms: float = 0.0

    # -- разбор ------------------------------------------------------------- #
    @classmethod
    def from_node(cls, node: Mapping[str, Any]) -> LotState:
        """Собирает LotState из узла ``Lots`` GraphQL."""
        trd_buy = node.get("TrdBuy") or {}
        lot_status = node.get("RefLotsStatus") or {}
        buy_status = trd_buy.get("RefBuyStatus") or {}
        kato_raw = node.get("plnPointKatoList") or []
        if isinstance(kato_raw, str):
            kato_raw = [kato_raw]
        return cls(
            lot_id=int(node.get("id") or 0),
            lot_number=str(node.get("lotNumber") or ""),
            name=str(node.get("nameRu") or node.get("nameKz") or ""),
            description=str(node.get("descriptionRu") or ""),
            amount=float(node.get("amount") or 0.0),
            count=float(node.get("count") or 0.0),
            status_id=int(node.get("refLotStatusId") or 0),
            status_name=str(lot_status.get("nameRu") or ""),
            status_code=str(lot_status.get("code") or ""),
            trd_buy_id=int(node.get("trdBuyId") or trd_buy.get("id") or 0),
            trd_buy_number=str(
                node.get("trdBuyNumberAnno") or trd_buy.get("numberAnno") or "",
            ),
            buy_status_id=int(trd_buy.get("refBuyStatusId") or 0),
            buy_status_name=str(buy_status.get("nameRu") or ""),
            start_date=str(trd_buy.get("startDate") or ""),
            end_date=str(trd_buy.get("endDate") or ""),
            repeat_start_date=str(trd_buy.get("repeatStartDate") or ""),
            repeat_end_date=str(trd_buy.get("repeatEndDate") or ""),
            publish_date=str(trd_buy.get("publishDate") or ""),
            customer_bin=str(
                node.get("customerBin") or trd_buy.get("customerBin") or "",
            ),
            customer_name=str(
                node.get("customerNameRu") or trd_buy.get("customerNameRu") or "",
            ),
            kato=tuple(str(item) for item in kato_raw),
            is_construction=bool(node.get("isConstructionWork")),
            dumping=bool(node.get("dumping")),
            last_update=str(node.get("lastUpdateDate") or ""),
            raw=dict(node),
        )

    # -- время -------------------------------------------------------------- #
    def start_dt(self, tz_name: str = "Asia/Almaty") -> datetime | None:
        """Момент открытия приёма заявок (T0).

        По схеме OWS v3 приём заявок открывается в ``startDate``.
        ``repeatStartDate`` — срок начала ДОПОЛНЕНИЯ заявок (не открытие
        окна): использование его как T0 приводило к пропуску окна подачи.
        Fallback на ``repeatStartDate`` — только если ``startDate`` пуст.
        """
        return parse_portal_datetime(self.start_date, tz_name) or parse_portal_datetime(
            self.repeat_start_date, tz_name
        )

    def end_dt(self, tz_name: str = "Asia/Almaty") -> datetime | None:
        return parse_portal_datetime(
            self.repeat_end_date, tz_name
        ) or parse_portal_datetime(self.end_date, tz_name)

    def fingerprint(self) -> tuple[str, str, str]:
        """Отпечаток состояния: изменился — значит есть что сообщить подписчикам."""
        return (str(self.status_id), self.last_update, str(self.buy_status_id))

    def is_open(
        self,
        open_codes: tuple[str, ...] = (),
        open_names: tuple[str, ...] = (),
        closed_names: tuple[str, ...] = (),
    ) -> bool:
        """Открыт ли приём заявок по данным статуса лота.

        Сравнение ТОЧНОЕ: подстрока ловила ложные срабатывания —
        «NOT_ACCEPTING» содержит «ACCEPTING», а «Прием заявок окончен» —
        «прием заявок». closed_names остаются подстрокой (закрытое состояние
        приоритетно и формулируется устойчиво).
        """
        code = self.status_code.strip().upper()
        name = self.status_name.strip().lower()
        if any(item in name for item in closed_names):
            return False
        if code and any(item.upper() == code for item in open_codes):
            return True
        return any(item == name for item in open_names)

    def describe(self) -> str:
        return (
            f"Лот {self.lot_number} (id={self.lot_id}) «{self.name[:60]}» "
            f"{self.amount:,.2f} ₸, статус: {self.status_name or self.status_id}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "lot_id": self.lot_id,
            "lot_number": self.lot_number,
            "name": self.name,
            "amount": self.amount,
            "status_id": self.status_id,
            "status_name": self.status_name,
            "status_code": self.status_code,
            "trd_buy_id": self.trd_buy_id,
            "trd_buy_number": self.trd_buy_number,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "customer_bin": self.customer_bin,
            "customer_name": self.customer_name,
            "kato": list(self.kato),
        }


class LotWatcher:
    """Адаптивный поллер лота с T0-триггером и синхронизацией часов."""

    def __init__(
        self,
        session: SessionManager,
        settings: AppSettings,
        logger: logging.Logger | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.log = logger or get_logger("watcher")
        self.clock = ClockSync()
        self.stats: dict[str, Any] = {
            "polls": 0,
            "errors": 0,
            "not_modified": 0,
            "last_rtt_ms": 0.0,
            "t0_epoch": 0.0,
            "last_status": "",
        }
        self._etag = ""
        self._last_fingerprint: tuple[str, str, str] | None = None
        self._t0_hit = asyncio.Event()
        self._timer_task: asyncio.Task[None] | None = None
        self._refine_task: asyncio.Task[Any] | None = None
        self.last_state: LotState | None = None

    # -- расписание --------------------------------------------------------- #
    def interval_for(self, seconds_to_t0: float | None) -> float:
        """Интервал опроса для текущего приближения к T0 (адаптивно).

        ``None`` (портал не отдал дату начала) и очень далёкий T0 дают САМЫЙ
        РЕДКИЙ интервал: пока время открытия окна неизвестно, «долбить» портал
        частыми запросами нельзя. Чем ближе T0, тем чаще опрос.
        """
        schedule = self.settings.watcher.schedule
        if not schedule:
            return self.settings.watcher.min_interval_hard
        rarest = max(schedule, key=lambda item: item.to_t0_s)
        if seconds_to_t0 is None or seconds_to_t0 > rarest.to_t0_s:
            step = rarest
        else:
            candidates = [item for item in schedule if item.to_t0_s >= seconds_to_t0]
            step = (
                min(candidates, key=lambda item: item.to_t0_s) if candidates else rarest
            )
        return max(step.interval_s, self.settings.watcher.min_interval_hard)

    def _t0_epoch(self, state: LotState) -> float | None:
        """T0 как epoch-секунды (None, если портал не отдал дату начала)."""
        start = state.start_dt(self.settings.watcher.portal_tz)
        return start.timestamp() if start else None

    # -- запрос состояния --------------------------------------------------- #
    def _ows_headers(self) -> dict[str, str]:
        """Заголовки реестра OWS (токен); сессия-заглушка без метода → пусто."""
        getter = getattr(self.session, "ows_headers", None)
        return dict(getter()) if callable(getter) else {}

    async def fetch(self, lot_id: int, *, conditional: bool = True) -> LotState | None:
        """Читает лот. ``None`` означает «данные не изменились» (HTTP 304)."""
        endpoint = self.settings.endpoints
        headers: dict[str, str] = self._ows_headers()
        if conditional and self.settings.watcher.conditional_requests and self._etag:
            headers["If-None-Match"] = self._etag
        payload = {
            "query": LOT_QUERY,
            "variables": {"ids": [int(lot_id)], "limit": 1},
        }
        sent_at = time.time()
        response = await self.session.request(
            "POST",
            endpoint.graphql_url(),
            json=payload,
            headers=headers,
            allow_relogin=False,
            timeout=self.settings.timeouts.lot_query,
        )
        received_at = time.time()
        self.clock.update_from_headers(response.headers, sent_at, received_at)
        self.stats["last_rtt_ms"] = round((received_at - sent_at) * 1000.0, 1)

        if response.status_code == 304:
            self.stats["not_modified"] += 1
            return None
        if response.status_code in (401, 403):
            self.stats["errors"] += 1
            raise SessionManager.ows_unauthorized(response.status_code)
        if response.status_code >= 400:
            self.stats["errors"] += 1
            raise PortalError(
                f"Опрос лота: HTTP {response.status_code}",
                status=response.status_code,
                body=response.text,
                retryable=response.status_code in self.settings.retries.retry_statuses,
            )
        try:
            body = response.json()
        except Exception as exc:
            self.stats["errors"] += 1
            raise PortalError("Опрос лота: некорректный JSON") from exc
        if isinstance(body, dict) and body.get("errors"):
            errors = body["errors"]
            first = errors[0] if isinstance(errors, list) and errors else errors
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise PortalError(f"Опрос лота: {message}", code="GRAPHQL_ERROR")

        nodes = ((body or {}).get("data") or {}).get("Lots") or []
        if not nodes:
            raise PortalError(
                f"Лот {lot_id} не найден в реестре",
                status=404,
                code="LOT_NOT_FOUND",
            )
        state = LotState.from_node(nodes[0])
        state.fetched_at = received_at
        state.rtt_ms = self.stats["last_rtt_ms"]
        self.stats["polls"] += 1
        self.stats["last_status"] = state.status_name or str(state.status_id)
        etag = response.headers.get("etag")
        if etag:
            self._etag = etag
        self.last_state = state
        return state

    async def resolve_reference(self, ref: int) -> tuple[LotState, bool]:
        """Автопилот: ID — это лот или объявление? Возвращает (лот, признак).

        1. Пробуем ID как номер лота в реестре OWS.
        2. Если лота нет — как номер объявления (TrdBuy): берём его лоты.
           Один лот → берём его; несколько → ошибка со списком номеров
           (выбрать лот — единственное, что не автоматизируется).
        3. Без доступа к OWS (401) — парсим страницы кабинета в сессии
           поставщика (нужен импорт Cookie: «Войти по токену»).
        """
        try:
            return await self.fetch(int(ref), conditional=False), False
        except PortalError as exc:
            if getattr(exc, "status", 0) == 401:
                # Доступа к OWS нет — страницы кабинета отдают те же данные.
                return await self._resolve_via_cabinet_html(int(ref)), True
            if getattr(exc, "status", 0) != 404:
                raise
        result = await self.session.graphql(
            "query LotsByAnno($anno: [Int!], $limit: Int!) {"
            "  Lots(filter: {trdBuyId: $anno}, limit: $limit) {"
            "    id lotNumber nameRu refLotStatusId"
            "  }"
            "}",
            variables={"anno": [int(ref)], "limit": 50},
        )
        # session.graphql возвращает уже развёрнутый "data" — Lots на верхнем
        # уровне.
        lots = result.get("Lots") or []
        if not lots:
            raise PortalError(
                f"ID {ref}: не найдено ни лота, ни объявления в реестре",
                status=404,
                code="REF_NOT_FOUND",
            )
        if len(lots) > 1:
            numbers = ", ".join(
                str(item.get("lotNumber") or item.get("id")) for item in lots
            )
            raise PortalError(
                f"Объявление {ref} содержит {len(lots)} лотов ({numbers}) — "
                "укажите номер конкретного лота",
                code="REF_AMBIGUOUS",
            )
        lot_id = int(lots[0].get("id") or 0)
        state = await self.fetch(lot_id, conditional=False)
        if state is None:
            raise PortalError(
                f"Лот объявления {ref} (id={lot_id}) недоступен в реестре",
                status=404,
            )
        return state, True

    async def _resolve_via_cabinet_html(self, ref: int) -> LotState:
        """Читает объявление со страниц кабинета (HTML вместо OWS).

        Нужна живая сессия портала (импорт Cookie из браузера). Без неё
        портал отвечает страницей входа — поднимаем понятную ошибку.
        """
        from core import v3bl_reader

        base = self.settings.endpoints.cabinet_base.rstrip("/")
        page_url = f"{base}/ru/announce/index/{ref}"

        async def get(url: str) -> tuple[str, str]:
            response = await self.session.request(
                "GET",
                url,
                allow_relogin=False,
                timeout=self.settings.timeouts.read,
            )
            html = response.text
            final_url = str(getattr(response, "url", url))
            if "/user/login" in final_url or "Авторизация" in html[:2000]:
                raise PortalError(
                    "Сессия портала истекла — войдите на портал и импортируйте "
                    "Cookie заново («Войти по токену»)",
                    code="PORTAL_SESSION_EXPIRED",
                )
            return html, final_url

        announce_html, _ = await get(page_url)
        anno = v3bl_reader.parse_announce_page(announce_html)
        lots_html, _ = await get(page_url + "?tab=lots")
        lots = v3bl_reader.parse_lots_tab(lots_html)
        if not lots:
            raise PortalError(
                f"Объявление {ref}: лоты на странице не найдены",
                code="REF_NOT_FOUND",
            )
        if len(lots) > 1:
            numbers = ", ".join(lot.get("lot_number") or "" for lot in lots)
            raise PortalError(
                f"Объявление {ref} содержит {len(lots)} лотов ({numbers}) — "
                "укажите номер конкретного лота",
                code="REF_AMBIGUOUS",
            )
        return v3bl_reader.lot_state_from_announce(anno, lots[0], self.settings)

    async def sync_clock(self, samples: int | None = None) -> ClockSync:
        """Оценка смещения часов сервера (вызывать при взводе заявки).

        Часы обновляются по заголовку ``Date`` ЛЮБОГО ответа — в том числе
        ошибочного: для измерения времени аутентификация не нужна и relogin
        не запускается (``allow_relogin=False``).
        """
        count = samples or self.settings.watcher.clock_sync_samples
        targets = self._clock_targets()
        for index in range(max(1, count)):
            await self._clock_probe(*targets[index % len(targets)])
            await asyncio.sleep(0.05)
        if self.clock.samples:
            self.log.info("Часы синхронизированы: %s", self.clock.describe())
        else:
            self.log.warning("Часы сервера не синхронизированы — работаем по локальным")
        return self.clock

    def _clock_targets(self) -> list[tuple[str, str, dict[str, Any] | None]]:
        endpoints = self.settings.endpoints
        if self.settings.cabinet_api_verified:
            return [
                ("GET", endpoints.cabinet_url(endpoints.session_ping_path), None),
                ("GET", endpoints.cabinet_url(endpoints.auth_challenge_path), None),
            ]
        # LIVE: пути кабинета не подтверждены — меряем по реестру OWS.
        # Заголовок Date есть и в ответе 401, токен для часов не обязателен.
        return [("POST", endpoints.graphql_url(), {"query": "{ __typename }"})]

    async def _clock_probe(
        self, method: str, url: str, body: dict[str, Any] | None
    ) -> None:
        try:
            sent_at = time.time()
            response = await self.session.request(
                method,
                url,
                json=body,
                headers=self._ows_headers() if body is not None else None,
                allow_relogin=False,
                timeout=self.settings.timeouts.read,
            )
            received_at = time.time()
            self.clock.update_from_headers(response.headers, sent_at, received_at)
        except Exception as exc:
            self.log.debug("Синхронизация часов: %s", exc)

    async def refine_clock(
        self, target_ms: float | None = None, max_probes: int | None = None
    ) -> ClockSync:
        """Сужает погрешность часов зондами на смене секунды сервера.

        Зонд отправляется так, чтобы по текущей оценке сервер обработал его
        ровно на границе секунды: пришедший ``Date`` отсекает половину
        интервала. ~6 зондов (по одному в секунду) дают точность порядка
        RTT/2 вместо «до ±0.5 с» у разовых выборок.
        """
        cfg = self.settings.watcher
        target = cfg.clock_target_ms if target_ms is None else target_ms
        probes = cfg.clock_refine_probes if max_probes is None else max_probes
        targets = self._clock_targets()
        if not self.clock.samples:
            await self._clock_probe(*targets[0])
        for index in range(max(0, probes)):
            clock = self.clock
            if not clock.samples:
                break
            rtt_s = (
                clock.best_rtt_ms / 1000.0 if math.isfinite(clock.best_rtt_ms) else 0
            )
            # Уже ниже RTT/2 интервал заметно не сузить.
            if clock.uncertainty_ms <= max(target, rtt_s * 500.0 + 5.0):
                break
            boundary = math.ceil(time.time() + 0.05 + rtt_s / 2.0 + clock.offset_s)
            send_at = boundary - clock.offset_s - rtt_s / 2.0
            await asyncio.sleep(max(0.0, send_at - time.time()))
            await self._clock_probe(*targets[index % len(targets)])
        if self.clock.samples:
            self.log.info("Часы уточнены: %s", self.clock.describe())
        return self.clock

    # -- таймер T0 ---------------------------------------------------------- #
    def _arm_timer(self, t0_epoch: float | None) -> None:
        """Ставит локальный таймер на момент (T0 − open_lead_ms).

        Повторный вызов ПЕРЕПЛАНИРУЕТ таймер: портал может изменить дату
        открытия приёма заявок, и старый таймер обязан быть снят.
        """
        self._cancel_timer()
        if t0_epoch is None:
            self.stats["t0_epoch"] = 0.0
            return
        target = t0_epoch - self.settings.watcher.open_lead_ms / 1000.0
        self._timer_task = asyncio.create_task(self._timer(target), name="lot-t0-timer")
        self.stats["t0_epoch"] = t0_epoch
        left_s = target - self.clock.server_now()
        self.log.info("Таймер T0 взведён: срабатывание через %.1f с", left_s)

    def _cancel_timer(self) -> None:
        """Снимает таймер T0 (если он был) — без «висящих» задач."""
        task, self._timer_task = self._timer_task, None
        if task is not None and not task.done():
            task.cancel()

    def _reschedule_if_t0_changed(
        self, state: LotState, current_t0: float | None
    ) -> float | None:
        """Перепланирует таймер, если портал изменил момент открытия приёма."""
        fresh_t0 = self._t0_epoch(state)
        if fresh_t0 is None:
            return current_t0
        if (
            current_t0 is not None
            and abs(fresh_t0 - current_t0) < T0_RESCHEDULE_EPSILON
        ):
            return current_t0
        self.log.warning(
            "Портал изменил T0 (%s → %s) — таймер перепланирован",
            current_t0,
            state.start_dt(self.settings.watcher.portal_tz),
        )
        self._arm_timer(fresh_t0)
        left = fresh_t0 - self.clock.server_now()
        self.session.set_t0(time.monotonic() + max(0.0, left))
        return fresh_t0

    async def _timer(self, target_epoch: float) -> None:
        """Ждёт точный момент по часам сервера: грубые шаги → точные."""
        while True:
            left = target_epoch - self.clock.server_now()
            if left <= 0:
                break
            if left > 2.0:
                await asyncio.sleep(min(left / 2.0, 1.0))
            elif left > 0.2:
                await asyncio.sleep(left / 2.0)
            else:
                await asyncio.sleep(max(left / 4.0, 0.01))
        self._t0_hit.set()
        BUS.publish(
            "t0_hit",
            t0_epoch=target_epoch,
            server_now=self.clock.server_now(),
        )

    def stop(self) -> None:
        """Останавливает таймер и уточнение часов (например, при отмене заявки)."""
        self._cancel_timer()
        task, self._refine_task = self._refine_task, None
        if task is not None and not task.done():
            task.cancel()

    async def _sleep(
        self,
        interval: float,
        t0_epoch: float | None,
        deadline_monotonic: float | None = None,
    ) -> None:
        """Спит, но никогда «не проспит» T0 и общий дедлайн наблюдения."""
        if deadline_monotonic is not None:
            # Иначе далёкий T0 (интервал 180 с) «съел» бы дедлайн, и лимит
            # наблюдения срабатывал бы с опозданием на минуты.
            left_deadline = deadline_monotonic - time.monotonic()
            interval = min(interval, max(0.01, left_deadline))
        if t0_epoch is None:
            await self._wait_t0_hit(max(0.01, interval))
            return
        left = t0_epoch - self.clock.server_now()
        # Минимум 10 мс: без него у самого T0 получается «холостое» вращение,
        # выжигающее CPU в ожидании срабатывания локального таймера.
        await self._wait_t0_hit(max(0.01, min(interval, left)))

    async def _wait_t0_hit(self, seconds: float) -> None:
        """Сон, который прерывает таймер T0 (уточнение часов может сдвинуть его)."""
        if self._t0_hit.is_set():
            return
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(seconds):
                await self._t0_hit.wait()

    async def _fetch_or_t0(self, lot_id: int) -> tuple[bool, LotState | None]:
        """Опрос лота, который не задерживает выстрел: T0 важнее ответа реестра.

        Возвращает ``(True, None)``, если таймер T0 сработал раньше ответа.
        """
        if self._t0_hit.is_set():
            return True, None
        fetch = asyncio.ensure_future(self.fetch(lot_id))
        hit = asyncio.ensure_future(self._t0_hit.wait())
        try:
            done, _ = await asyncio.wait(
                {fetch, hit}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            hit.cancel()
            if not fetch.done():
                fetch.cancel()
        if fetch in done:
            return False, fetch.result()
        await asyncio.gather(fetch, return_exceptions=True)
        return True, None

    def _emit_state(
        self, state: LotState, callback: Callable[[LotState], None] | None
    ) -> None:
        """Уведомляет UI только при реальном изменении состояния лота."""
        fingerprint = state.fingerprint()
        if self._last_fingerprint == fingerprint:
            return
        self._last_fingerprint = fingerprint
        if callback is not None:
            callback(state)

    # -- основной цикл ------------------------------------------------------ #
    async def watch(
        self,
        lot_id: int,
        *,
        on_state: Callable[[LotState], None] | None = None,
        on_open: Callable[[LotState], None] | None = None,
        on_tick: Callable[[LotState], None] | None = None,
        deadline_monotonic: float | None = None,
    ) -> LotState:
        """Ждёт открытия приёма заявок и возвращает финальное состояние лота.

        Срабатывает по любому из двух сигналов:
          1. локальный таймер по часам сервера (T0 − ``open_lead_ms``);
          2. реальный статус лота перешёл в «приём заявок».
        """
        cfg = self.settings.watcher
        hard_deadline = deadline_monotonic or (time.monotonic() + cfg.max_watch_seconds)
        self._t0_hit = asyncio.Event()
        self._last_fingerprint = None
        self.stats["open_confirmed"] = False
        self.stats["watch_timeout"] = False

        try:
            state = await self.fetch(lot_id)
            if state is None:  # условный запрос не должен мешать первому снимку
                state = await self.fetch(lot_id, conditional=False)
            if state is None:
                raise PortalError(f"Лот {lot_id} недоступен", status=404)
            self._emit_state(state, on_state)
            self.log.info("Взят под наблюдение: %s", state.describe())

            t0_epoch = self._t0_epoch(state)
            if t0_epoch is None:
                self.log.warning(
                    "Портал не отдал дату начала приёма заявок — работаю по статусу",
                )
            else:
                self._arm_timer(t0_epoch)
                left = t0_epoch - self.clock.server_now()
                self.session.set_t0(time.monotonic() + max(0.0, left))
                if deadline_monotonic is None:
                    # Лимит наблюдения не должен истечь раньше T0 (взвод с вечера).
                    hard_deadline = max(hard_deadline, time.monotonic() + left + 60.0)
                # Уточнение часов в фоне: таймер перечитывает server_now() на
                # каждом шаге и подхватит новую оценку сам.
                if left > cfg.clock_refine_min_lead_s and cfg.clock_refine_probes > 0:
                    self._refine_task = asyncio.create_task(
                        self.refine_clock(), name="clock-refine"
                    )
                self.log.info(
                    "T0: %s (через %.1f с). %s",
                    state.start_dt(cfg.portal_tz),
                    max(left, 0.0),
                    self.clock.describe(),
                )

            while True:
                if self._t0_hit.is_set():
                    self.log.success(
                        "T0 достигнут по часам сервера — выходим на подачу",
                    )
                    break
                if state.is_open(
                    cfg.open_status_codes,
                    cfg.open_status_names,
                    cfg.closed_status_names,
                ):
                    self.log.success("Портал открыл приём заявок (статус лота)")
                    break
                if time.monotonic() >= hard_deadline:
                    # Дедлайн — это ОШИБКА: подача «вслепую» после таймаута
                    # недопустима, цикл должен завершиться без submit.
                    self.stats["watch_timeout"] = True
                    raise PortalError(
                        "Истёк лимит наблюдения за лотом "
                        f"({cfg.max_watch_seconds:.0f} с) — окно приёма заявок "
                        "не открылось",
                        code="WATCH_TIMEOUT",
                    )

                seconds_to_t0 = t0_epoch - self.clock.server_now() if t0_epoch else None
                interval = self.interval_for(seconds_to_t0)
                sleep_target = (
                    t0_epoch - cfg.open_lead_ms / 1000.0 if t0_epoch else None
                )
                await self._sleep(interval, sleep_target, hard_deadline)

                try:
                    t0_hit, fresh = await self._fetch_or_t0(lot_id)
                except PortalError as exc:
                    self.log.warning("Сбой опроса лота: %s", exc)
                    await self._wait_t0_hit(min(interval * 2, 2.0))
                    continue
                if t0_hit or fresh is None:
                    continue
                state = fresh
                self._emit_state(state, on_state)
                if on_tick is not None:
                    on_tick(state)
                t0_epoch = self._reschedule_if_t0_changed(state, t0_epoch)

            # T0 (или статус) достигнуты — выходим на подачу НЕМЕДЛЕННО.
            # Подтверждение реальным статусом выполняет вызывающий код В ФОНЕ:
            # запаздывание OWS раньше сдвигало submit на секунды после T0 или
            # срывало подачу с OPEN_NOT_CONFIRMED.
            if on_open is not None:
                on_open(state)
            return state
        finally:
            # Открытие не подтверждено, отмена или ошибка — «висящих» таймеров
            # и привязки сессии к T0 остаться не должно.
            self.session.set_t0(None)
            self.stop()

    async def confirm_open(
        self, lot_id: int, *, fallback: LotState, attempts: int = 10
    ) -> LotState:
        """Подтверждает открытие реальным статусом (частые короткие опросы).

        Первый опрос — сразу, без паузы: таймер T0 уже сработал, и лишние
        ``post_open_interval`` мс перед первой проверкой означали бы опоздание
        подачи. Паузы между повторами растут 50 → 100 → 200 мс → потолок
        ``post_open_interval``, чтобы не «долбить» портал.

        Если портал так и не отдал статус «приём заявок», открытие считается
        НЕПОДТВЕРЖДЁННЫМ и поднимается ``PortalError`` — подавать заявку
        «на удачу» после истечения окна подтверждения нельзя.
        """
        cfg = self.settings.watcher
        state = fallback
        for attempt in range(1, attempts + 1):
            if state.is_open(
                cfg.open_status_codes, cfg.open_status_names, cfg.closed_status_names
            ):
                return state
            if attempt % 4 == 0:
                self.log.debug("Подтверждение открытия: попытка %d", attempt)
            if attempt > 1:
                delay = min(cfg.post_open_interval, 0.05 * (2 ** (attempt - 2)))
                # Пол опроса — min_interval_hard, единый для всего поллера
                # (нарушение пола в 150 мс = лишняя нагрузка на реестр).
                await asyncio.sleep(max(cfg.min_interval_hard, delay))
            try:
                fresh = await self.fetch(lot_id, conditional=False)
            except PortalError:
                continue
            if fresh is not None:
                state = fresh
        raise PortalError(
            "Портал не подтвердил открытие приёма заявок "
            f"(статус лота: {state.status_name or state.status_id}) — "
            "подача отменена",
            code="OPEN_NOT_CONFIRMED",
        )
