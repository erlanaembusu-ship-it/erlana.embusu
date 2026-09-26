"""Оркестратор подачи заявки: план → подпись → предзагрузка → submit.

Главный принцип — **в момент T0 не делается ничего, кроме отправки**.
Всё остальное выполняется заранее, параллельно с ожиданием открытия окна:

    1. ``plan``   — синхронная сборка payload из данных лота и нишевого шаблона;
    2. ``warmup`` — пакетная подпись всех документов ОДНИМ вызовом NCALayer и
                    предзагрузка вложений в кабинет (пока окно ещё закрыто);
    3. ``watch``  — ожидание T0 (``lot_watcher``) параллельно с шагами 1–2;
    4. ``submit`` — минимальный по латентности POST с ключом идемпотентности;
    5. ``verify`` — подтверждение факта подачи; повтор только после проверки
                    статуса, чтобы исключить дублирующую заявку.

Целевой бюджет полного цикла — 20–50 с, из которых «горячая» часть после T0
занимает единицы секунд.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.niche_blueprints import (
    DocKind,
    DocumentSpec,
    NicheBlueprint,
    SignMode,
    build_profile_values,
    default_values,
    get_blueprint,
    missing_required_documents,
    resolve_blueprint,
)
from config.settings import APP_VERSION, LIVE_SUBMIT_NOTICE, AppSettings
from core.lot_watcher import LotState, LotWatcher
from core.ncalayer_client import (
    NCALayerClient,
    NCALayerError,
    SecretPassword,
    SignedDocument,
    SignItem,
    sha256_hex,
)
from core.session_manager import PortalError, SessionManager
from utils.logger import BUS, Stopwatch, get_logger

__all__ = ["STAGES", "BidPipeline", "BidPlan", "BidRequest", "BidResult"]

# Имена этапов (используются в UI и в отчёте по таймингам)
STAGES = ("clock", "plan", "sign", "upload", "wait", "submit", "verify")

# Статусы, которыми портал ПОДТВЕРЖДАЕТ приём заявки, и статусы отказа.
# «pending»/«processing» сознательно НЕ в списке: это не подтверждение подачи
# (ложная «ЗАЯВКА ПОДАНА»), финальный статус проверяется verify по ключу.
ACCEPTED_STATUSES = frozenset(
    {
        "accepted",
        "ok",
        "success",
        "created",
        "registered",
        "submitted",
        "принята",
        "подана",
        "зарегистрирована",
    }
)
REJECTED_STATUSES = frozenset(
    {
        "rejected",
        "declined",
        "denied",
        "error",
        "failed",
        "cancelled",
        "canceled",
        "отклонена",
        "ошибка",
        "отказ",
    }
)
BID_ID_KEYS = ("bidId", "applicationId", "id", "number", "bidNumber")
STATUS_KEYS = ("status", "state", "bidStatus", "applicationStatus")
# Ответы submit, после которых повтор в бюджете допустим (тот же idem-ключ).
# 425 — окно ещё закрыто (заявка точно не создана); остальные неоднозначны —
# перед повтором обязателен verify по ключу.
SUBMIT_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def extract_bid_id(payload: Any) -> str:
    """Достаёт идентификатор заявки из ответа портала (рекурсивно по data)."""
    if not isinstance(payload, dict):
        return ""
    for key in BID_ID_KEYS:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    nested = payload.get("data")
    if isinstance(nested, dict) and nested is not payload:
        return extract_bid_id(nested)
    return ""


def extract_status(payload: Any) -> str:
    """Достаёт статус заявки из ответа портала (рекурсивно по data)."""
    if not isinstance(payload, dict):
        return ""
    for key in STATUS_KEYS:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    nested = payload.get("data")
    if isinstance(nested, dict) and nested is not payload:
        return extract_status(nested)
    return ""


def response_problem(payload: Any) -> str | None:
    """Возвращает причину, по которой ответ НЕЛЬЗЯ считать успехом (или None).

    HTTP 2xx сам по себе успехом не является: HTML-страница, пустой/нечитаемый
    JSON или статус отказа — это НЕ принятая заявка.
    """
    if not isinstance(payload, dict) or not payload:
        return "пустой или нечитаемый ответ портала (ожидался JSON с заявкой)"
    error = payload.get("error") or payload.get("errors")
    if error and str(error).strip().lower() not in {"ok", "none"}:
        return "портал вернул ошибку в ответе"
    if payload.get("success") is False or payload.get("ok") is False:
        return "портал сообщил о неуспехе операции"
    if isinstance(payload.get("data"), dict):
        nested_problem = response_problem(payload["data"])
        if nested_problem:
            return nested_problem
    status = extract_status(payload).strip().lower()
    if status in REJECTED_STATUSES:
        return f"портал отклонил заявку (status={status})"
    if (status and status not in ACCEPTED_STATUSES) or (
        not status and not extract_bid_id(payload)
    ):
        hint = (
            "ответ портала не содержит ни идентификатора заявки, "
            "ни подтверждающего статуса"
        )
        return f"{hint} (status={status or '—'})"
    return None


@dataclass(slots=True)
class BidRequest:
    """Задание на подачу заявки (формируется в UI)."""

    lot_id: int
    blueprint_id: str = ""  # "" → подобрать автоматически
    price: float | None = None  # None → из правила шаблона
    fields: dict[str, Any] = field(default_factory=dict)
    # documents    — документы ПОСТАВЩИКА (USER_DOC);
    # lot_documents — документы закупки (LOT_DOC).
    documents: list[Path] = field(default_factory=list)
    lot_documents: list[Path] = field(default_factory=list)
    # Явное соответствие «ключ документа шаблона → файл». Заполняется UI и
    # обязательно для неоднозначных USER_DOC (несколько файлов с одинаковыми
    # масками): конвейер НЕ угадывает сопоставление по порядку файлов.
    document_slots: dict[str, Path] = field(default_factory=dict)
    generated: dict[str, str] = field(default_factory=dict)  # key → готовый текст
    upload_before_t0: bool = True
    dry_run: bool = False
    # Строгий режим: отсутствие обязательного документа шаблона — ошибка плана.
    strict_documents: bool = True

    def document_paths(self) -> list[Path]:
        """Все файлы заявки, дедуплицированные по ПОЛНОМУ пути, а не по имени.

        Одинаковые basename из разных каталогов — это разные документы, терять
        (или склеивать) их нельзя.
        """
        result: list[Path] = []
        seen: set[str] = set()
        for path in [
            *self.documents,
            *self.lot_documents,
            *(self.document_slots or {}).values(),
        ]:
            if path is None:
                continue
            resolved = Path(path)
            marker = str(resolved)
            if marker in seen:
                continue
            seen.add(marker)
            result.append(resolved)
        return result

    def slot_for(self, key: str) -> Path | None:
        """Файл, явно назначенный на ключ документа шаблона (или None)."""
        value = (self.document_slots or {}).get(key)
        return Path(value) if value is not None else None


@dataclass(slots=True)
class BidPlan:
    """Готовый к отправке пакет: payload + подписанные документы."""

    lot: LotState
    blueprint: NicheBlueprint
    values: dict[str, Any]
    price: float
    idem_key: str
    payload: dict[str, Any]
    sign_items: list[SignItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    signed: list[SignedDocument] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    prepared_at: float = 0.0
    # DRY-RUN вычисляется ОДИН раз в plan(): request.dry_run OR settings.dry_run.
    # Дальше warmup/submit ориентируются только на это поле.
    dry_run: bool = False

    @property
    def is_valid(self) -> bool:
        return not self.errors

    @property
    def signed_count(self) -> int:
        return len(self.signed)

    def describe(self) -> str:
        return (
            f"лот {self.lot.lot_id}: {len(self.sign_items)} док., "
            f"цена {self.price:,.2f} ₸, шаблон «{self.blueprint.title_ru}»"
        )


@dataclass(slots=True)
class BidResult:
    """Итог подачи заявки с разбивкой по этапам."""

    ok: bool
    lot_id: int
    bid_id: str = ""
    status: str = ""
    idem_key: str = ""
    stages: dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0
    signed: int = 0
    uploaded: int = 0
    t0_delta_ms: float | None = None
    dry_run: bool = False
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        head = "УСПЕХ" if self.ok else "ОШИБКА"
        tail = f"заявка {self.bid_id}" if self.bid_id else "; ".join(self.errors) or "—"
        return f"[{head}] лот {self.lot_id}, {tail}, {self.total_ms / 1000:.2f} с"


def make_idempotency_key(
    lot_id: int, bin_iin: str, price: float, documents: Iterable[tuple[str, str]]
) -> str:
    """Ключ идемпотентности: одинаковый вход → одинаковый ключ → нет дубля."""
    hasher = hashlib.sha256()
    hasher.update(f"{lot_id}|{bin_iin}|{price:.2f}".encode())
    for name, digest in sorted(documents):
        hasher.update(f"|{name}:{digest}".encode())
    return hasher.hexdigest()[:32]


def render_bid_document(plan_data: dict[str, Any]) -> str:
    """Формирует структурированный документ заявки (JSON).

    Портал требует собственный формализованный документ заявки, точная XSD
    которого публично не документирована. Поэтому приложение формирует
    нейтральный структурированный JSON, а при наличии официального шаблона
    его можно подставить через ``BidRequest.generated`` (key → готовый XML).
    """
    return json.dumps(plan_data, ensure_ascii=False, indent=2, sort_keys=True)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class BidPipeline:
    """Конвейер подачи: планирование, подпись, предзагрузка, submit, verify."""

    def __init__(
        self,
        session: SessionManager,
        ncalayer: NCALayerClient,
        watcher: LotWatcher,
        settings: AppSettings,
        logger: logging.Logger | None = None,
        license_guard: Any | None = None,
    ) -> None:
        self.session = session
        self.ncalayer = ncalayer
        self.watcher = watcher
        self.settings = settings
        self.log = logger or get_logger("pipeline")
        # LicenseGuard — опционален (тесты/утилиты): нужен для тарифного лимита.
        self.license_guard = license_guard
        self._upload_semaphore = asyncio.Semaphore(
            settings.pipeline.doc_upload_concurrency,
        )
        self.stats: dict[str, Any] = {
            "planned": 0,
            "warmed": 0,
            "submitted": 0,
            "failed": 0,
            "last_total_ms": 0.0,
            "last_t0_delta_ms": None,
        }

    # -- вспомогательное ---------------------------------------------------- #
    def _profile_values(self) -> dict[str, Any]:
        profile = self.settings.profile
        return build_profile_values(
            {
                "bin_iin": profile.bin_iin,
                "name_ru": profile.name_ru,
                "email": profile.email,
                "phone": profile.phone,
                "address": profile.address,
                "signer_fio": profile.signer_fio,
                "signer_position": profile.signer_position,
            }
        )

    @staticmethod
    def _resolve_lot_value(lot: LotState, path: str) -> Any:
        """Достаёт значение из данных лота по пути вида ``TrdBuy.startDate``."""
        if not path:
            return None
        current: Any = lot.raw
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _load_document(
        self,
        spec_key: str,
        label: str,
        path: Path,
        mode: SignMode,
        content_type: str,
        limit_mb: float | None = None,
    ) -> SignItem:
        """Читает файл в память и считает хеш (файл читается ровно один раз).

        ``path`` передаётся в ``SignItem``, поэтому исходное имя файла
        сохраняется (``file_name`` == имя файла на диске), а байты кешируются в
        ``data``. Лимит — минимальный из лимита документа шаблона
        (``spec.max_mb``) и общего ``pipeline.max_document_mb``.
        """
        max_mb = float(self.settings.pipeline.max_document_mb)
        limit = float(limit_mb) if limit_mb else max_mb
        limit = min(limit, max_mb)
        raw = path.read_bytes()
        size_mb = len(raw) / (1024 * 1024)
        if size_mb > limit:
            raise PortalError(
                f"Документ «{path.name}» больше лимита {limit:.0f} МБ",
                code="DOC_TOO_LARGE",
            )
        return SignItem(
            key=spec_key,
            label=label,
            path=path,
            data=raw,
            mode=mode,
            content_type=content_type,
        )

    # -- шаг 1: планирование ------------------------------------------------ #
    @staticmethod
    def _stable_digest(item: SignItem) -> str:
        """Хеш содержимого документа без летучих полей.

        Сгенерированные документы содержат отметку времени; в ключ
        идемпотентности она попадать не должна, иначе повторная подача того же
        пакета получит другой ключ и портал создаст дубль заявки.
        """
        raw = item.data if item.data is not None else b""
        if item.path is None and raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                payload = None
            if isinstance(payload, dict):
                payload.pop("generatedAt", None)
                payload.pop("createdAt", None)
                raw = json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
        return sha256_hex(raw)

    @staticmethod
    def _spec_matches(path: Path, spec: DocumentSpec) -> bool:
        """Подходит ли файл под маски документа шаблона."""
        if not spec.patterns:
            return True
        name = path.name.lower()
        for pattern in spec.patterns:
            if path.match(pattern) or name.endswith(pattern.lstrip("*").lower()):
                return True
        return False

    def _attach_file(
        self,
        items: list[SignItem],
        errors: list[str],
        warnings: list[str],
        spec: DocumentSpec,
        path: Path,
        used: set[str],
        mimetypes: Any,
    ) -> None:
        """Прикладывает файл как конкретный документ шаблона."""
        used.add(str(path))
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        try:
            items.append(
                self._load_document(
                    spec.key,
                    spec.label,
                    path,
                    spec.sign,
                    content_type,
                    float(spec.max_mb) if spec.max_mb else None,
                )
            )
        except FileNotFoundError as exc:
            message = f"Документ «{path}» не найден: {exc}"
            (errors if spec.required else warnings).append(message)
        except PortalError as exc:
            (errors if spec.required else warnings).append(str(exc))
        except OSError as exc:
            errors.append(f"Не удалось прочитать документ «{path}»: {exc}")

    def _collect_documents(
        self,
        blueprint: NicheBlueprint,
        request: BidRequest,
        values: dict[str, Any],
        warnings: list[str],
        errors: list[str],
    ) -> list[SignItem]:
        """Собирает полный набор документов к подписи (один пакет).

        Соответствие документов шаблону — детерминированное:
          * GENERATED — генерируются приложением;
          * LOT_DOC — только из ``request.lot_documents``;
          * USER_DOC — только из ``request.documents``;
          * ``request.document_slots`` (ключ → файл) имеет приоритет.

        Порядок файлов НЕ является основанием для сопоставления: если под маску
        документа подходит несколько файлов, соответствие не угадывается (нужен
        ``document_slots``), а неоднозначность попадает в отчёт. Исходные имена и
        байты документов сохраняются.
        """
        import mimetypes

        cfg = self.settings.pipeline
        items: list[SignItem] = []
        used: set[str] = set()

        # 1) Генерируемые документы — всегда на месте.
        for spec in blueprint.documents:
            if spec.kind is not DocKind.GENERATED:
                continue
            text = request.generated.get(spec.key)
            if text is None:
                body = dict(values)
                body.update(
                    {
                        "document": spec.key,
                        "documentLabel": spec.label,
                        "lotId": request.lot_id,
                        "supplierBin": values.get("bin_iin", ""),
                        "generatedAt": _utc_now_iso(),
                    }
                )
                text = render_bid_document(body)
            items.append(
                SignItem(
                    key=spec.key,
                    label=spec.label,
                    data=text.encode("utf-8"),
                    mode=spec.sign,
                    content_type="application/json",
                )
            )

        lot_pool = [Path(p) for p in request.lot_documents if p is not None]
        user_pool = [Path(p) for p in request.documents if p is not None]
        slots: dict[str, Path] = {
            str(key): Path(value)
            for key, value in (request.document_slots or {}).items()
            if value is not None
        }

        def pool_for(spec: DocumentSpec) -> list[Path]:
            return lot_pool if spec.kind is DocKind.LOT_DOC else user_pool

        file_specs = [
            spec for spec in blueprint.documents if spec.kind is not DocKind.GENERATED
        ]
        # Сначала обязательные: опциональный документ не должен «забрать» файл,
        # предназначенный обязательному с той же маской.
        ordered = sorted(
            file_specs,
            key=lambda spec: (not spec.required, blueprint.documents.index(spec)),
        )

        for spec in ordered:
            slot = slots.pop(spec.key, None)
            if slot is not None:
                if str(slot) in used:
                    errors.append(
                        f"Файл «{slot.name}» назначен сразу на несколько "
                        f"документов шаблона (последний: «{spec.label}»)"
                    )
                    continue
                self._attach_file(items, errors, warnings, spec, slot, used, mimetypes)
                continue
            candidates = [
                path
                for path in pool_for(spec)
                if str(path) not in used and self._spec_matches(path, spec)
            ]
            if len(candidates) == 1:
                self._attach_file(
                    items,
                    errors,
                    warnings,
                    spec,
                    candidates[0],
                    used,
                    mimetypes,
                )
            elif len(candidates) > 1:
                names = ", ".join(sorted(item.name for item in candidates))
                warnings.append(
                    f"Неоднозначное соответствие для «{spec.label}»: подходит "
                    f"{len(candidates)} файл(ов) ({names}). Передайте явное "
                    f"соответствие document_slots['{spec.key}']."
                )

        # 2) Файлы вне шаблона и неиспользованные слоты — прикладываем как есть,
        #    не теряя исходные имена и байты.
        leftovers: list[tuple[str, Path, str]] = []
        for path in [*user_pool, *lot_pool]:
            if str(path) in used:
                continue
            used.add(str(path))
            leftovers.append(
                (f"extra_{path.stem}", path, f"Файл «{path.name}» приложен вне шаблона")
            )
        for key, path in slots.items():
            if str(path) in used:
                continue
            used.add(str(path))
            leftovers.append(
                (
                    f"extra_{key}",
                    path,
                    (
                        f"Слот «{key}» не соответствует шаблону — "
                        f"файл «{path.name}» приложен как есть"
                    ),
                )
            )
        for key, path, message in leftovers:
            content_type = (
                mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            )
            try:
                items.append(
                    self._load_document(
                        key,
                        path.name,
                        path,
                        SignMode.CMS,
                        content_type,
                    )
                )
                warnings.append(message)
            except (OSError, PortalError) as exc:
                errors.append(str(exc))

        # 3) Обязательные документы шаблона.
        provided = {item.key for item in items}
        for spec in missing_required_documents(blueprint, provided):
            message = f"Не приложен обязательный документ шаблона: {spec.label}"
            if request.strict_documents:
                errors.append(message)
            else:
                warnings.append(f"{message} — портал может отклонить заявку")

        if not items:
            warnings.append("К заявке не приложено ни одного документа")
        if len(items) > cfg.max_documents:
            errors.append(
                f"К заявке приложено {len(items)} документ(ов) — превышен "
                f"лимит pipeline.max_documents={cfg.max_documents}"
            )
        return items

    def plan(self, lot: LotState, request: BidRequest) -> BidPlan:
        """Собирает payload и список документов; ничего не подписывает."""
        text = f"{lot.name} {lot.description}".strip()
        blueprint = (
            get_blueprint(request.blueprint_id)
            if request.blueprint_id
            else resolve_blueprint(text)
        )
        warnings: list[str] = []
        if not request.blueprint_id and blueprint.id == "generic":
            warnings.append("Ниша не распознана — используется универсальный шаблон")

        values: dict[str, Any] = default_values(blueprint)
        values.update(self._profile_values())
        for spec in blueprint.fields:
            if spec.source.value == "lot" and spec.lot_field:
                resolved = self._resolve_lot_value(lot, spec.lot_field)
                if resolved is None:
                    continue
                if isinstance(resolved, (list, tuple)):
                    resolved = ", ".join(str(item) for item in resolved)
                if resolved != "":
                    values[spec.key] = resolved
        values.update(
            {
                "lot_id": lot.lot_id,
                "lot_number": lot.lot_number,
                "lot_amount": lot.amount,
                "trd_buy_id": lot.trd_buy_id,
            }
        )
        values.update(request.fields)

        price = request.price
        auto_price = price is None
        if auto_price:
            price = blueprint.pricing.suggest(lot.amount)
        price = float(price or 0.0)
        values["price"] = price
        if auto_price and price:
            warnings.append(f"Цена рассчитана автоматически: {price:,.2f} ₸")

        errors = blueprint.validate(values, lot.amount, price)

        # -- предпусковая проверка требований участия ------------------------ #
        # 1) Тарифный лимит: сумма лота не должна превышать подключённый тариф.
        if self.license_guard is not None and lot.amount:
            license_status = self.license_guard.check()
            tariff_limit = license_status.max_lot_amount
            if tariff_limit > 0 and float(lot.amount) > tariff_limit:
                errors.append(
                    f"Сумма лота {lot.amount:,.2f} ₸ превышает лимит "
                    f"подключённого тарифа {tariff_limit:,.2f} ₸ — "
                    "подача по этому лоту заблокирована"
                )
        # 2) Сводка обязательных требований к поставщику (в журнал, до взвода).
        required_docs = [d.label for d in blueprint.required_documents]
        self.log.info(
            "Требования участия: обязательные документы — %s; требования "
            "поставщика — %s; тарифный лимит — %s",
            "; ".join(required_docs) or "нет в шаблоне ниши",
            "; ".join(blueprint.notes_ru) or "нет особых",
            (
                f"{license_status.max_lot_amount:,.2f} ₸"
                if self.license_guard is not None and license_status.max_lot_amount > 0
                else "без ограничения"
            ),
        )
        comment = values.get("comment") or blueprint.build_comment(values)
        values["comment"] = comment

        # DRY-RUN определяется ОДИН раз здесь: либо задание, либо настройки.
        dry_run = bool(request.dry_run or self.settings.dry_run)
        sign_items = self._collect_documents(
            blueprint,
            request,
            values,
            warnings,
            errors,
        )
        digests = [(item.key, self._stable_digest(item)) for item in sign_items]
        idem_key = make_idempotency_key(
            lot.lot_id,
            str(values.get("bin_iin") or self.settings.profile.bin_iin),
            price,
            digests,
        )
        payload = {
            "idemKey": idem_key,
            "lotId": lot.lot_id,
            "lotNumber": lot.lot_number,
            "trdBuyId": lot.trd_buy_id,
            "trdBuyNumber": lot.trd_buy_number,
            "blueprint": blueprint.id,
            "supplier": {
                "binIin": values.get("bin_iin") or self.settings.profile.bin_iin,
                "name": values.get("supplier_name") or self.settings.profile.name_ru,
                "email": values.get("email") or self.settings.profile.email,
                "phone": values.get("phone") or self.settings.profile.phone,
                "address": values.get("address") or self.settings.profile.address,
            },
            "price": price,
            "vatIncluded": bool(values.get("vat_included", True)),
            "fields": {key: value for key, value in values.items() if key != "comment"},
            "comment": comment,
            "deliveryPlace": list(lot.kato),
            "documents": [
                {
                    "key": item.key,
                    "fileName": item.file_name,
                    "contentType": item.content_type,
                    "sha256": digest,
                }
                for item, (_, digest) in zip(sign_items, digests, strict=True)
            ],
            "createdAt": _utc_now_iso(),
            "appVersion": APP_VERSION,
        }

        self.stats["planned"] += 1
        plan = BidPlan(
            lot=lot,
            blueprint=blueprint,
            values=values,
            price=price,
            idem_key=idem_key,
            payload=payload,
            sign_items=sign_items,
            warnings=warnings,
            errors=errors,
            dry_run=dry_run,
        )
        self.log.info(
            "План собран: %s%s%s",
            plan.describe(),
            " [DRY-RUN]" if dry_run else "",
            f" | предупреждения: {'; '.join(warnings)}" if warnings else "",
        )
        for problem in errors:
            self.log.error("Ошибка плана: %s", problem)
        BUS.publish(
            "plan_ready",
            lot_id=lot.lot_id,
            valid=plan.is_valid,
            documents=len(sign_items),
            price=price,
            warnings=list(warnings),
            errors=list(errors),
            blueprint=blueprint.id,
            dry_run=dry_run,
        )
        return plan

    # -- защита LIVE -------------------------------------------------------- #
    def _live_guard(self, plan: BidPlan) -> None:
        """Запрещает реальную подпись/загрузку/подачу без подтверждённого API.

        Это последняя линия обороны в ЯДРЕ, независимая от UI: даже если
        кто-то снимет DRY-RUN в интерфейсе или вызовет конвейер напрямую,
        в LIVE без подтверждённого контракта кабинета ничего не подпишется и
        не уйдёт на непроверенные адреса.
        """
        if plan.dry_run or self.settings.live_submit_allowed:
            return
        raise PortalError(LIVE_SUBMIT_NOTICE, code="LIVE_SUBMIT_UNVERIFIED")

    # -- шаг 2: взвод (подпись + предзагрузка) ------------------------------ #
    async def warmup(
        self, plan: BidPlan, password: SecretPassword | None = None
    ) -> BidPlan:
        """Готовит заявку ДО T0: пакетная подпись и предзагрузка документов.

        Возвращает тот же план с заполненными ``signed`` и ``attachments``.
        В DRY-RUN (``plan.dry_run``) не выполняется НИ подпись, НИ загрузка.
        """
        cfg = self.settings.pipeline
        stopwatch = Stopwatch(f"warmup-{plan.lot.lot_id}")
        password = password or self.session.password

        if plan.dry_run:
            # DRY-RUN: ни подписи (диалог NCALayer), ни предзагрузки вложений —
            # никаких внешних действий, только фиксация готовности плана.
            self.log.warning(
                "DRY-RUN: взвод без подписи и без предзагрузки документов",
            )
            stopwatch.mark("sign")
            stopwatch.mark("upload")
            plan.prepared_at = time.time()
            self.stats["warmed"] += 1
            timings = stopwatch.report()
            plan.payload["_timings"] = {
                "sign_ms": timings.get("sign"),
                "upload_ms": timings.get("upload"),
            }
            BUS.publish(
                "warmup_done",
                lot_id=plan.lot.lot_id,
                signed=0,
                uploaded=0,
                timings=timings,
                dry_run=True,
            )
            return plan

        self._live_guard(plan)
        if cfg.sign_before_t0 and plan.sign_items:
            self.log.info(
                "Подпись %d документ(ов) одним вызовом NCALayer…",
                len(plan.sign_items),
            )
            plan.signed = await self.ncalayer.sign_cms_batch(
                plan.sign_items,
                password=password,
                batch=True,
            )
        stopwatch.mark("sign")

        if cfg.upload_before_t0 and plan.signed:
            plan.attachments = await self._upload_attachments(plan)
        stopwatch.mark("upload")

        plan.prepared_at = time.time()
        self.stats["warmed"] += 1
        timings = stopwatch.report()
        self.log.success(
            "Заявка взведена: подписано %d, загружено %d. %s",
            len(plan.signed),
            len(plan.attachments),
            stopwatch.summary(),
        )
        BUS.publish(
            "warmup_done",
            lot_id=plan.lot.lot_id,
            signed=len(plan.signed),
            uploaded=len(plan.attachments),
            timings=timings,
        )
        plan.payload["_timings"] = {
            "sign_ms": timings.get("sign"),
            "upload_ms": timings.get("upload"),
        }
        return plan

    async def _upload_attachments(self, plan: BidPlan) -> list[dict[str, Any]]:
        """Параллельная предзагрузка подписанных документов в кабинет."""
        endpoint = self.settings.endpoints
        url = endpoint.cabinet_url(endpoint.bid_attachment_path, lot_id=plan.lot.lot_id)

        async def upload(document: SignedDocument) -> dict[str, Any]:
            async with self._upload_semaphore:
                body = {
                    "idemKey": plan.idem_key,
                    "lotId": plan.lot.lot_id,
                    "key": document.key,
                    "fileName": document.file_name,
                    "contentType": document.content_type,
                    "sha256": document.sha256,
                    "size": document.size,
                    "contentBase64": document.content_b64,
                    "signatureBase64": document.signature_b64,
                }
                response = await self.session.request(
                    "POST",
                    url,
                    json=body,
                    timeout=self.settings.timeouts.attachment_upload,
                    # Загрузка БЕЗ повторов: ретрай мог задвоить вложение,
                    # если первая попытка реально дошла до портала.
                    retry=False,
                )
                if response.status_code >= 400:
                    raise PortalError(
                        f"Загрузка «{document.file_name}»: HTTP {response.status_code}",
                        status=response.status_code,
                        body=response.text,
                    )
                try:
                    data = response.json()
                except Exception:
                    data = {}
                attachment_id = ""
                if isinstance(data, dict):
                    attachment_id = str(
                        data.get("id")
                        or data.get("attachmentId")
                        or data.get("fileId")
                        or "",
                    )
                if not attachment_id:
                    raise PortalError(
                        f"Загрузка «{document.file_name}» не подтверждена: нет ID вложения",
                        code="UPLOAD_UNCONFIRMED",
                    )
                return {
                    "key": document.key,
                    "fileName": document.file_name,
                    "contentType": document.content_type,
                    "sha256": document.sha256,
                    "size": document.size,
                    "attachmentId": attachment_id or document.sha256,
                }

        results = await asyncio.gather(
            *[upload(document) for document in plan.signed],
            return_exceptions=True,
        )
        attachments: list[dict[str, Any]] = []
        problems: list[str] = []
        for item, result in zip(plan.signed, results, strict=True):
            if isinstance(result, BaseException):
                problems.append(f"{item.file_name}: {result}")
            else:
                attachments.append(result)
        if problems:
            raise PortalError(
                "Не удалось предзагрузить документы: " + "; ".join(problems),
                code="UPLOAD_FAILED",
            )
        return attachments

    # -- шаг 3: финальный submit -------------------------------------------- #
    def _t0_delta_ms(self, plan: BidPlan) -> float | None:
        start = plan.lot.start_dt(self.settings.watcher.portal_tz)
        if start is None:
            return None
        return round((self.watcher.clock.server_now() - start.timestamp()) * 1000.0, 1)

    async def submit(self, plan: BidPlan) -> BidResult:
        """Отправляет заявку. Единственный сетевой вызов после T0 — POST."""
        stopwatch = Stopwatch(f"submit-{plan.lot.lot_id}")
        endpoint = self.settings.endpoints
        url = endpoint.cabinet_url(endpoint.bid_submit_path, lot_id=plan.lot.lot_id)

        if plan.errors:
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=list(plan.errors),
                stages=stopwatch.report(),
                total_ms=stopwatch.total_ms,
                dry_run=plan.dry_run,
            )

        body = dict(plan.payload)
        # Служебные ключи (``_timings`` и т. п.) — только для отчёта, порталу
        # они не нужны и в тело запроса попадать не должны.
        for key in [k for k in body if str(k).startswith("_")]:
            body.pop(key, None)
        body["attachments"] = plan.attachments
        body["signedDocuments"] = [
            {
                "key": doc.key,
                "fileName": doc.file_name,
                "sha256": doc.sha256,
                "signature": doc.signature_b64,
            }
            for doc in plan.signed
        ]

        # DRY-RUN приходит из плана (request.dry_run OR settings.dry_run).
        if plan.dry_run:
            self.log.warning(
                "DRY-RUN: submit не отправляется (dry_run=%s, настройка=%s)",
                plan.dry_run,
                self.settings.dry_run,
            )
            return BidResult(
                ok=True,
                lot_id=plan.lot.lot_id,
                bid_id="dry-run",
                status="dry_run",
                idem_key=plan.idem_key,
                signed=len(plan.signed),
                uploaded=len(plan.attachments),
                dry_run=True,
                stages=stopwatch.report(),
                total_ms=stopwatch.total_ms,
                t0_delta_ms=self._t0_delta_ms(plan),
            )

        try:
            self._live_guard(plan)
        except PortalError as exc:
            self.stats["failed"] += 1
            self.log.error("%s", exc)
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=[str(exc)],
                stages=stopwatch.report(),
                total_ms=stopwatch.total_ms,
            )

        retries = self.settings.retries
        budget_s = retries.submit_budget_s
        deadline = time.monotonic() + budget_s
        pause = 0.1
        attempt = 0
        response: Any = None
        payload: dict[str, Any] = {}
        network_error = ""
        # Последний исход неоднозначен (сеть/таймаут/5xx): заявка могла дойти.
        ambiguous = False
        while True:
            attempt += 1
            try:
                response = await self._hot_request(
                    "POST",
                    url,
                    deadline,
                    timeout=self.settings.timeouts.submit,
                    json=body,
                    follow_redirects=False,
                )
                payload = self._safe_json(response)
                network_error = ""
            except PortalError as exc:
                response, payload, network_error = None, {}, str(exc)
                if not exc.retryable:
                    break
            if attempt == 1:
                stopwatch.mark("submit")

            status = response.status_code if response is not None else None
            if status is not None and 200 <= status < 300:
                problem = response_problem(payload)
                if problem is None:
                    result = self._success_result(plan, payload, stopwatch)
                    return await self._post_submit_verify(plan, result)
                # HTTP 2xx, но заявка НЕ подтверждена (HTML/пустой JSON/отказ).
                self.log.error(
                    "Submit: HTTP %d, но подача НЕ подтверждена — %s", status, problem
                )
                if self.settings.pipeline.verify_after_submit:
                    verified = await self.verify(plan, deadline=self._grace(deadline))
                    if verified.ok:
                        return self._verified_success(plan, verified, stopwatch)
                self.stats["failed"] += 1
                return BidResult(
                    ok=False,
                    lot_id=plan.lot.lot_id,
                    idem_key=plan.idem_key,
                    errors=[f"Подача не подтверждена: {problem}"],
                    stages=stopwatch.report(),
                    total_ms=stopwatch.total_ms,
                    t0_delta_ms=self._t0_delta_ms(plan),
                    raw=payload,
                )

            if (
                status is not None
                and status != 409
                and status not in SUBMIT_RETRY_STATUSES
            ):
                ambiguous = False
                break  # окончательный отказ портала
            ambiguous = status != 425
            if status is None and not retries.submit_verify_before_retry:
                break
            if status is None:
                self.log.warning(
                    "Submit упал по сети (%s) — проверяю статус по ключу "
                    "идемпотентности",
                    network_error,
                )
            elif status != 425:
                self.log.warning(
                    "Submit вернул HTTP %d — проверяю, не принята ли заявка ранее",
                    status,
                )
            # 425 — портал явно отказал (окно закрыто), заявка не создана:
            # verify не нужен, повтор сразу. Остальное — сначала verify.
            if status != 425:
                verified = await self.verify(plan, deadline=deadline)
                if verified.ok:
                    return self._verified_success(plan, verified, stopwatch)
            if status == 409:
                break
            if time.monotonic() + pause >= deadline:
                break
            await asyncio.sleep(pause)
            pause = min(pause * 2, 0.4)
            self.log.debug("Повтор submit #%d (HTTP %s)", attempt + 1, status or "—")

        # Бюджет исчерпан на неоднозначном исходе: последний шанс узнать,
        # не принята ли заявка, чтобы не сообщить ложный отказ.
        if ambiguous and retries.submit_verify_before_retry:
            verified = await self.verify(plan, deadline=self._grace(deadline))
            if verified.ok:
                return self._verified_success(plan, verified, stopwatch)

        self.stats["failed"] += 1
        if response is None:
            message = f"Подача не выполнена: {network_error}"
        else:
            detail = payload.get("message", "") if isinstance(payload, dict) else ""
            message = f"Подача отклонена: HTTP {response.status_code} {detail}".strip()
        if time.monotonic() >= deadline - 0.01 and attempt > 1:
            message += f" (бюджет подачи {budget_s:.1f} с исчерпан, попыток: {attempt})"
        self.log.error(message)
        return BidResult(
            ok=False,
            lot_id=plan.lot.lot_id,
            idem_key=plan.idem_key,
            errors=[message],
            stages=stopwatch.report(),
            total_ms=stopwatch.total_ms,
            t0_delta_ms=self._t0_delta_ms(plan),
            raw=payload,
        )

    def _grace(self, deadline: float) -> float:
        """Дедлайн финальной проверки: не короче таймаута чтения от «сейчас»."""
        return max(deadline, time.monotonic() + self.settings.timeouts.read)

    async def _hot_request(
        self, method: str, url: str, deadline: float, *, timeout: float, **kwargs: Any
    ) -> Any:
        """Одна попытка в «горячем» окне: без ретраев и relogin, не дольше бюджета."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PortalError("Бюджет подачи исчерпан", code="SUBMIT_BUDGET_EXCEEDED")
        try:
            async with asyncio.timeout(remaining):
                return await self.session.request(
                    method,
                    url,
                    timeout=min(timeout, remaining),
                    retry=False,
                    allow_relogin=False,
                    **kwargs,
                )
        except TimeoutError as exc:
            raise PortalError(
                f"{method} {url}: нет ответа за {remaining:.1f} с",
                code="SUBMIT_TIMEOUT",
                retryable=True,
            ) from exc

    def _verified_success(
        self, plan: BidPlan, verified: BidResult, stopwatch: Stopwatch
    ) -> BidResult:
        verified.stages = stopwatch.report()
        verified.total_ms = stopwatch.total_ms
        return self._note_submitted(plan, verified, stopwatch)

    async def _post_submit_verify(self, plan: BidPlan, result: BidResult) -> BidResult:
        """Подтверждает факт подачи по ключу идемпотентности (если включено).

        Метрика ``submitted`` уже учтена в ``_note_submitted`` при успешном
        HTTP-ответе, поэтому подтверждение её НЕ удваивает.
        """
        if not self.settings.pipeline.verify_after_submit:
            return result
        check = await self.verify(plan)
        raw = result.raw if isinstance(result.raw, dict) else {}
        raw["verify"] = {
            "ok": check.ok,
            "bid_id": check.bid_id,
            "status": check.status,
            "errors": list(check.errors),
        }
        result.raw = raw
        if check.ok:
            result.bid_id = result.bid_id or check.bid_id
            result.status = check.status or result.status
        else:
            result.ok = False
            result.status = "unconfirmed"
            result.errors = [
                (
                    "Ответ на подачу получен, но факт приёма не подтверждён. "
                    "Проверьте кабинет перед повторной отправкой."
                ),
                *check.errors,
            ]
            self.stats["submitted"] = max(0, self.stats["submitted"] - 1)
            self.stats["failed"] += 1
            self.log.warning("Факт приёма заявки не подтверждён")
        return result

    def _note_submitted(
        self, plan: BidPlan, result: BidResult, stopwatch: Stopwatch
    ) -> BidResult:
        """Единственная точка учёта принятой заявки (``submitted`` = один раз)."""
        self.stats["submitted"] += 1
        self.stats["last_total_ms"] = round(stopwatch.total_ms, 1)
        delta = self._t0_delta_ms(plan)
        self.stats["last_t0_delta_ms"] = delta
        result.t0_delta_ms = delta
        self.log.success(
            "ЗАЯВКА ПОДАНА: лот %s, заявка %s, отклонение от T0 %s мс",
            plan.lot.lot_id,
            result.bid_id or "—",
            f"{delta:+.0f}" if delta is not None else "н/д",
        )
        BUS.publish(
            "bid_submitted",
            lot_id=plan.lot.lot_id,
            bid_id=result.bid_id,
            status=result.status,
            total_ms=result.total_ms,
            t0_delta_ms=delta,
            stages=result.stages,
        )
        return result

    def _success_result(
        self, plan: BidPlan, payload: dict[str, Any], stopwatch: Stopwatch
    ) -> BidResult:
        bid_id = self._extract_bid_id(payload)
        status = extract_status(payload) or "accepted"
        stopwatch.mark("verify")
        result = BidResult(
            ok=True,
            lot_id=plan.lot.lot_id,
            bid_id=bid_id,
            status=status,
            idem_key=plan.idem_key,
            stages=stopwatch.report(),
            total_ms=stopwatch.total_ms,
            signed=len(plan.signed),
            uploaded=len(plan.attachments),
            t0_delta_ms=self._t0_delta_ms(plan),
            raw=payload,
        )
        return self._note_submitted(plan, result, stopwatch)

    # -- проверка факта подачи ---------------------------------------------- #
    async def verify(
        self, plan: BidPlan, *, deadline: float | None = None
    ) -> BidResult:
        """Проверяет факт подачи по ключу идемпотентности.

        Успехом считается только ответ, в котором есть идентификатор заявки или
        подтверждающий статус: HTTP 2xx с HTML/пустым JSON/статусом отказа —
        это НЕ подтверждение. Метрику ``submitted`` здесь не трогаем (учёт идёт
        в ``_note_submitted``), иначе повторная проверка удвоила бы счётчик.
        С ``deadline`` (горячее окно подачи) — одна попытка не дольше дедлайна.
        """
        endpoint = self.settings.endpoints
        url = endpoint.cabinet_url(
            endpoint.bid_status_path,
            lot_id=plan.lot.lot_id,
            idem_key=plan.idem_key,
        )
        try:
            if deadline is None:
                response = await self.session.request(
                    "GET",
                    url,
                    timeout=self.settings.timeouts.read,
                )
            else:
                response = await self._hot_request(
                    "GET", url, deadline, timeout=self.settings.timeouts.read
                )
        except PortalError as exc:
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=[str(exc)],
            )
        if response.status_code == 404:
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=["Заявка не найдена по ключу идемпотентности"],
            )
        if response.status_code >= 400:
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=[f"Проверка статуса: HTTP {response.status_code}"],
            )
        payload = self._safe_json(response)
        problem = response_problem(payload)
        if problem is not None:
            return BidResult(
                ok=False,
                lot_id=plan.lot.lot_id,
                idem_key=plan.idem_key,
                errors=[f"Проверка статуса: {problem}"],
                raw=payload,
            )
        bid_id = self._extract_bid_id(payload)
        status = extract_status(payload) or "accepted"
        self.log.success(
            "Подтверждено: заявка %s (%s) уже принята порталом",
            bid_id or "—",
            status,
        )
        return BidResult(
            ok=True,
            lot_id=plan.lot.lot_id,
            bid_id=bid_id,
            status=status,
            idem_key=plan.idem_key,
            signed=len(plan.signed),
            uploaded=len(plan.attachments),
            t0_delta_ms=self._t0_delta_ms(plan),
            raw=payload,
        )

    @staticmethod
    def _safe_json(response: Any) -> dict[str, Any]:
        try:
            data = response.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _extract_bid_id(payload: Any) -> str:
        return extract_bid_id(payload)

    # -- полный цикл -------------------------------------------------------- #
    async def run_cycle(
        self,
        request: BidRequest,
        *,
        on_stage: Callable[[str, dict[str, Any]], None] | None = None,
        on_lot_state: Callable[[LotState], None] | None = None,
    ) -> BidResult:
        """Полный цикл: часы → план → взвод → ожидание T0 → submit → verify.

        Взвод (подпись и предзагрузка) идёт ПАРАЛЛЕЛЬНО с ожиданием окна,
        поэтому к моменту T0 остаётся один сетевой вызов — submit.
        """
        overall = Stopwatch(f"cycle-{request.lot_id}")

        def stage(name: str, **info: Any) -> None:
            if on_stage is not None:
                on_stage(name, {"lot_id": request.lot_id, **info})

        def failure(
            message: str, *, idem_key: str = "", dry_run: bool = False
        ) -> BidResult:
            self.stats["failed"] += 1
            self.log.error(message)
            result = BidResult(
                ok=False,
                lot_id=request.lot_id,
                idem_key=idem_key,
                errors=[message],
                stages=overall.report(),
                total_ms=round(overall.total_ms, 1),
                dry_run=dry_run,
            )
            stage("done", ok=False, total_ms=result.total_ms)
            return result

        warm_task: asyncio.Task[Any] | None = None
        watch_task: asyncio.Task[Any] | None = None
        confirm_task: asyncio.Task[Any] | None = None
        try:
            stage("clock")
            await self.watcher.sync_clock()
            overall.mark("clock")

            stage("plan")
            state = await self.watcher.fetch(request.lot_id, conditional=False)
            if state is None:
                raise PortalError(f"Лот {request.lot_id} не найден", status=404)
            if on_lot_state is not None:
                on_lot_state(state)
            plan = self.plan(state, request)
            overall.mark("plan")

            # Ошибки плана останавливают цикл ДО подписи и наблюдения: в
            # неполном/некорректном пакете отправлять нечего.
            if not plan.is_valid:
                return failure(
                    "План недействителен, подача остановлена до подписи: "
                    + "; ".join(plan.errors),
                    idem_key=plan.idem_key,
                    dry_run=plan.dry_run,
                )

            # LIVE без подтверждённого API: стоп ДО подписи и наблюдения.
            if not plan.dry_run and not self.settings.live_submit_allowed:
                return failure(
                    LIVE_SUBMIT_NOTICE,
                    idem_key=plan.idem_key,
                    dry_run=False,
                )

            stage("warmup")
            warm_task = asyncio.create_task(self.warmup(plan), name="bid-warmup")
            watch_task = asyncio.create_task(
                self.watcher.watch(request.lot_id, on_state=on_lot_state),
                name="bid-watch",
            )
            try:
                plan = await warm_task
            except (NCALayerError, PortalError) as exc:
                return failure(
                    f"Взвод заявки не удался: {exc}",
                    idem_key=plan.idem_key,
                    dry_run=plan.dry_run,
                )
            overall.mark("warmup")

            stage("wait")
            try:
                open_state = await watch_task
            except Exception as exc:
                return failure(
                    f"Ожидание открытия окна прервано: {exc}",
                    idem_key=plan.idem_key,
                    dry_run=plan.dry_run,
                )
            plan.lot = open_state
            overall.mark("wait")

            # Подтверждение открытия статусом лота — В ФОНЕ: медленный OWS
            # раньше сдвигал submit на секунды после T0 или срывал подачу
            # с OPEN_NOT_CONFIRMED. Теперь submit уходит по часам сервера,
            # а результат подтверждения — в журнал и статистику.
            def _confirm_done(task: asyncio.Task[Any]) -> None:
                if task.cancelled():
                    return
                exc = task.exception()
                if exc is not None:
                    self.log.warning("Открытие не подтверждено статусом OWS: %s", exc)
                    return
                self.stats["open_confirmed"] = True
                self.log.success("Открытие подтверждено статусом лота")

            try:
                confirm_task = asyncio.create_task(
                    self.watcher.confirm_open(request.lot_id, fallback=open_state)
                )
                confirm_task.add_done_callback(_confirm_done)
            except RuntimeError as exc:  # нет работающего loop — не критично
                self.log.debug("Подтверждение открытия не запущено: %s", exc)

            stage("submit")
            result = await self.submit(plan)
            overall.mark("submit")
        finally:
            # Любая ошибка/отмена: снимаем фоновые задачи и таймер T0, чтобы не
            # осталось «висящих» подписей, загрузок и наблюдения за лотом.
            await self._cleanup_tasks(warm_task, watch_task, confirm_task)
            self.watcher.stop()

        stages = dict(result.stages)
        stages.update(
            {
                "cycle_clock": overall.stage_ms("clock") or 0.0,
                "cycle_plan": overall.stage_ms("plan") or 0.0,
                "cycle_warmup": overall.stage_ms("warmup") or 0.0,
                "cycle_wait": overall.stage_ms("wait") or 0.0,
                "sign": (plan.payload.get("_timings") or {}).get("sign_ms") or 0.0,
                "upload": (plan.payload.get("_timings") or {}).get("upload_ms") or 0.0,
                "total": round(overall.total_ms, 1),
            }
        )
        result.stages = stages
        result.total_ms = round(overall.total_ms, 1)
        result.dry_run = plan.dry_run
        stage("done", ok=result.ok, total_ms=result.total_ms)
        self.log.info("Полный цикл: %s", overall.summary())
        return result

    @staticmethod
    async def _cleanup_tasks(*tasks: asyncio.Task[Any] | None) -> None:
        """Гарантированно отменяет и «дожимает» фоновые задачи цикла."""
        children = [task for task in tasks if task is not None]
        for task in children:
            if not task.done():
                task.cancel()
        if children:
            await asyncio.gather(*children, return_exceptions=True)
