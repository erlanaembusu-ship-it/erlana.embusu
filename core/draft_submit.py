"""Подача заранее подготовленной заявки (черновика) в момент открытия приёма.

Протокол сверен по HAR реальной подачи (см. ``docs/PORTAL_CONTRACT.md``).
Пользователь готовит заявку в браузере до шага «Предварительный просмотр»:
документы, подписи и цены (цену шифрует TumarCSP — её вводит человек).
FastBid держит сессию, при необходимости запрашивает налоговые сведения и в
T0 (по часам сервера) выполняет «Подать» — ``ajax_public_application``.

Капча не обходится: если портал показывает её на предпросмотре, взвод
отклоняется и подать нужно вручную.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from config.settings import AppSettings
from core import v3bl_reader
from core.lot_watcher import ClockSync, parse_portal_datetime
from core.session_manager import PortalError, SessionManager, is_cabinet_page
from utils.logger import BUS, get_logger

__all__ = [
    "DraftRef",
    "DraftResult",
    "DraftSubmitter",
    "extract_csrf",
    "parse_draft_ref",
]

_REF_URL_RE = re.compile(r"/application/[a-z_]+/(\d{5,12})/(\d{5,12})")
_REF_PAIR_RE = re.compile(r"^\s*(\d{5,12})\s*[/\s,;]\s*(\d{5,12})\s*$")
_CSRF_RES = (
    re.compile(r'<meta[^>]+name="csrf-token-hash"[^>]+content="([^"]+)"'),
    re.compile(r'<input[^>]+id="csrf"[^>]+value="([^"]+)"'),
    re.compile(r'<input[^>]+name="csrf"[^>]+value="([^"]+)"'),
)
# Ответы «Подать», после которых повтор бессмыслен.
_FATAL_MARKERS = ("налогов", "задолженност", "капч", "captcha")


@dataclass(frozen=True, slots=True)
class DraftRef:
    anno_id: int
    app_id: int

    def __str__(self) -> str:
        return f"{self.anno_id}/{self.app_id}"


@dataclass(slots=True)
class DraftResult:
    ok: bool
    dry_run: bool
    ref: DraftRef
    message: str = ""
    attempts: int = 0
    t0_epoch: float | None = None
    # Отклонение отправки удачной попытки от T0 по часам сервера (мс).
    t0_delta_ms: float | None = None
    responses: list[dict[str, Any]] = field(default_factory=list)


def parse_draft_ref(text: str) -> DraftRef:
    """Адрес страницы заявки или «объявление/заявка» → DraftRef."""
    raw = (text or "").strip()
    match = _REF_URL_RE.search(raw) or _REF_PAIR_RE.match(raw)
    if not match:
        raise ValueError(
            "Укажите адрес страницы заявки (…/application/preview/<объявление>/"
            "<заявка>) или два номера: «объявление/заявка»"
        )
    return DraftRef(int(match.group(1)), int(match.group(2)))


def extract_csrf(html: str) -> str:
    for pattern in _CSRF_RES:
        match = pattern.search(html)
        if match:
            return match.group(1)
    return ""


def captcha_required(preview_html: str) -> bool:
    """Предпросмотр требует капчу (в варианте без неё кнопка «Да» — *_no_captcha)."""
    if "g-recaptcha" in preview_html or "data-sitekey" in preview_html:
        return True
    return "btn_price_agree_no_captcha" not in preview_html


class DraftSubmitter:
    """Взвод одной подготовленной заявки: подготовка → ожидание T0 → «Подать»."""

    def __init__(
        self,
        session: SessionManager,
        settings: AppSettings,
        clock: ClockSync | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.clock = clock or ClockSync()
        self.log = get_logger("draft")
        self._csrf = ""

    # -- HTTP ------------------------------------------------------------- #
    def _url(self, template: str, **params: Any) -> str:
        return self.settings.endpoints.cabinet_url(template, **params)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        sent = time.time()
        response = await self.session.request(
            method,
            url,
            allow_relogin=False,
            retry=method == "GET",
            timeout=kwargs.pop("timeout", self.settings.timeouts.read),
            **kwargs,
        )
        self.clock.update_from_headers(response.headers, sent, time.time())
        return response

    async def _get_cabinet_html(self, url: str) -> str:
        response = await self._request(
            "GET", url, headers={"Accept": "text/html,application/xhtml+xml"}
        )
        html = response.text
        if response.status_code in (401, 403) or not is_cabinet_page(html):
            raise PortalError(
                "Сессия портала не активна — войдите заново («Войти по ЭЦП»)",
                status=401,
                code="PORTAL_SESSION_EXPIRED",
            )
        if response.status_code >= 400:
            raise PortalError(
                f"{url}: HTTP {response.status_code}", status=response.status_code
            )
        return html

    def _ajax_headers(self, referer: str) -> dict[str, str]:
        return {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.settings.endpoints.cabinet_base.rstrip("/"),
            "Referer": referer,
        }

    # -- шаги --------------------------------------------------------------- #
    async def sync_clock(self, samples: int = 5) -> ClockSync:
        url = self._url(self.settings.endpoints.clock_probe_path)
        for _ in range(max(1, samples)):
            try:
                await self._request("GET", url, timeout=5.0)
            except PortalError as exc:
                self.log.debug("Часы сервера: %s", exc)
            await asyncio.sleep(0.05)
        return self.clock

    async def fetch_t0(self, ref: DraftRef) -> float | None:
        """Срок начала приёма заявок со страницы объявления (epoch) или None."""
        endpoints = self.settings.endpoints
        html = await self._get_cabinet_html(
            self._url(endpoints.announce_page_path, anno_id=ref.anno_id)
        )
        anno = v3bl_reader.parse_announce_page(html)
        start = parse_portal_datetime(
            anno.get("start_date") or "", self.settings.watcher.portal_tz
        )
        return start.timestamp() if start else None

    async def prepare(self, ref: DraftRef) -> str:
        """Проверяет, что черновик на шаге предпросмотра, и берёт csrf."""
        endpoints = self.settings.endpoints
        html = await self._get_cabinet_html(
            self._url(
                endpoints.app_preview_path, anno_id=ref.anno_id, app_id=ref.app_id
            )
        )
        csrf = extract_csrf(html)
        if not csrf:
            raise PortalError(
                f"Заявка {ref}: на странице предпросмотра нет csrf — "
                "проверьте адрес и что заявка доведена до «Предварительного просмотра»",
                code="DRAFT_NOT_READY",
            )
        if 'id="next"' not in html:
            raise PortalError(
                f"Заявка {ref}: на предпросмотре нет кнопки «Подать заявку» — "
                "заявка уже подана или не заполнена до конца",
                code="DRAFT_NOT_READY",
            )
        if captcha_required(html):
            raise PortalError(
                f"Заявка {ref}: портал требует капчу при подаче — автоподача "
                "невозможна, подайте вручную",
                code="CAPTCHA_REQUIRED",
            )
        self._csrf = csrf
        return csrf

    async def request_tax_debts(self) -> None:
        """«Получить новые сведения» о налоговой задолженности (ответ ИС — позже)."""
        url = self._url(self.settings.endpoints.tax_debts_path)
        csrf = extract_csrf(await self._get_cabinet_html(url))
        if not csrf:
            raise PortalError("Страница налоговых сведений без csrf", code="NO_CSRF")
        response = await self._request(
            "POST",
            url,
            data={"csrf": csrf, "send_request": "Получить новые сведения"},
            headers={"Referer": url},
        )
        if response.status_code >= 400:
            raise PortalError(
                f"Запрос налоговых сведений: HTTP {response.status_code}",
                status=response.status_code,
            )
        self.log.info("Запрошены сведения о налоговой задолженности (ответ ИС — позже)")

    async def submit_once(self, ref: DraftRef) -> dict[str, Any]:
        """Одно нажатие «Подать»: ответ портала как dict (status ok|error)."""
        endpoints = self.settings.endpoints
        referer = self._url(
            endpoints.app_preview_path, anno_id=ref.anno_id, app_id=ref.app_id
        )
        # Порядок и значения полей — как у JS портала (send_application).
        data = {
            "public_app": "Y",
            "agree_price": "false",
            "agree_contract_project": "false",
            "agree_covid19": "false",
            "csrf": self._csrf,
        }
        response = await self._request(
            "POST",
            self._url(
                endpoints.app_submit_path, anno_id=ref.anno_id, app_id=ref.app_id
            ),
            data=data,
            headers=self._ajax_headers(referer),
        )
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if not isinstance(payload, dict):
            if response.status_code in (401, 403) or not is_cabinet_page(response.text):
                raise PortalError(
                    "«Подать»: портал вернул не JSON — сессия истекла",
                    status=response.status_code,
                    code="PORTAL_SESSION_EXPIRED",
                )
            raise PortalError(
                f"«Подать»: неожиданный ответ HTTP {response.status_code}",
                status=response.status_code,
            )
        return payload

    async def _wait_until(self, target_epoch: float) -> None:
        while True:
            left = target_epoch - self.clock.server_now()
            if left <= 0:
                return
            if left > 2.0:
                await asyncio.sleep(min(left - 1.0, 5.0))
            elif left > 0.05:
                await asyncio.sleep(left / 2.0)
            else:
                await asyncio.sleep(max(left, 0.001))

    async def run(
        self,
        ref: DraftRef,
        *,
        dry_run: bool,
        t0_epoch: float | None = None,
        request_tax: bool = False,
        on_stage: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> DraftResult:
        def stage(name: str, **info: Any) -> None:
            if on_stage is not None:
                on_stage(name, info)
            BUS.publish("draft_stage", ref=str(ref), stage=name, **info)

        pipe = self.settings.pipeline
        result = DraftResult(ok=False, dry_run=dry_run, ref=ref)
        stage("prepare")
        await self.sync_clock()
        await self.prepare(ref)
        if t0_epoch is None:
            t0_epoch = await self.fetch_t0(ref)
        result.t0_epoch = t0_epoch
        if t0_epoch is None:
            raise PortalError(
                f"Объявление {ref.anno_id}: срок начала приёма не найден — укажите T0",
                code="NO_T0",
            )
        if request_tax and not dry_run:
            stage("tax")
            await self.request_tax_debts()
        left = t0_epoch - self.clock.server_now()
        self.log.info(
            "Заявка %s взведена: T0 через %.0f с (часы: %s)%s",
            ref,
            max(0.0, left),
            self.clock.describe(),
            " — DRY-RUN, «Подать» не нажимается" if dry_run else "",
        )
        self.session.set_t0(time.monotonic() + max(0.0, left))
        stage("armed", t0_epoch=t0_epoch)

        if left > pipe.draft_prepare_lead_s:
            await self._wait_until(t0_epoch - pipe.draft_prepare_lead_s)
            # Свежие csrf и соединение перед выстрелом; заодно уточняем часы.
            await self.prepare(ref)
            await self.sync_clock(samples=3)
        await self._wait_until(t0_epoch)
        stage("fire")

        if dry_run:
            result.ok = True
            result.message = "DRY-RUN: момент подачи наступил, «Подать» не нажималась"
            result.t0_delta_ms = (self.clock.server_now() - t0_epoch) * 1000.0
            self.log.info("%s (T0 %+.0f мс)", result.message, result.t0_delta_ms)
            stage("done", ok=True, dry_run=True)
            return result

        deadline = t0_epoch + pipe.draft_retry_window_s
        while True:
            fired_at = self.clock.server_now()
            result.attempts += 1
            payload = await self.submit_once(ref)
            result.responses.append(payload)
            status = str(payload.get("status") or "")
            message = re.sub(r"\s+", " ", str(payload.get("message") or "")).strip()
            if status == "ok":
                result.ok = True
                result.t0_delta_ms = (fired_at - t0_epoch) * 1000.0
                result.message = "Заявка подана"
                self.log.success(
                    "Заявка %s ПОДАНА: попытка %d, T0 %+.0f мс",
                    ref,
                    result.attempts,
                    result.t0_delta_ms,
                )
                await self._verify(ref)
                break
            result.message = message or f"портал ответил status={status!r}"
            fatal = payload.get("debtor") == 1 or any(
                marker in message.lower() for marker in _FATAL_MARKERS
            )
            if fatal or self.clock.server_now() >= deadline:
                self.log.error(
                    "Заявка %s не подана (попыток: %d): %s",
                    ref,
                    result.attempts,
                    result.message,
                )
                break
            self.log.warning(
                "Попытка %d: %s — повтор", result.attempts, result.message[:160]
            )
            await asyncio.sleep(pipe.draft_retry_interval_s)
        stage("done", ok=result.ok, dry_run=False, attempts=result.attempts)
        return result

    async def _verify(self, ref: DraftRef) -> None:
        url = self._url(self.settings.endpoints.app_view_path, app_id=ref.app_id)
        try:
            await self._get_cabinet_html(url)
            self.log.info("Карточка поданной заявки: %s", url)
        except PortalError as exc:
            self.log.warning("Не удалось открыть карточку заявки: %s", exc)
