"""Нишевые шаблоны («blueprints») заявок: поля, документы, правила цены.

Blueprint описывает, что именно нужно заполнить и приложить для конкретной
ниши закупки. Резолвер сам подбирает шаблон по наименованию лота, а недостающие
значения берёт из данных лота (``source="lot"``) — это ключ к скорости:
к моменту T0 в payload уже всё готово, заполнять вручную почти нечего.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


class FieldType(str, Enum):
    TEXT = "text"
    MULTILINE = "multiline"
    INT = "int"
    MONEY = "money"
    PERCENT = "percent"
    DATE = "date"
    CHOICE = "choice"
    BOOL = "bool"


class Source(str, Enum):
    """Откуда берётся значение поля."""

    LOT = "lot"  # автоматически из карточки лота
    PROFILE = "profile"  # из профиля поставщика
    DERIVED = "derived"  # вычисляется конвейером (цена, коэффициенты)
    MANUAL = "manual"  # вводит пользователь в UI


class DocKind(str, Enum):
    LOT_DOC = "lot_doc"  # документ закупки — скачивается с портала
    USER_DOC = "user_doc"  # документ поставщика из локальной папки
    GENERATED = "generated"  # генерируется приложением (например, ценовое предложение)


class SignMode(str, Enum):
    CMS = "cms"  # CMS (CAdES) — основной режим для заявок
    XML = "xml"  # XAdES для XML-документов (модуль basics поддерживает массивы)
    NONE = "none"  # подпись не требуется


@dataclass(frozen=True, slots=True)
class FieldSpec:
    key: str
    label: str
    type: FieldType = FieldType.TEXT
    required: bool = True
    source: Source = Source.MANUAL
    lot_field: str = ""  # путь до поля лота, напр. "amount"
    default: Any = None
    choices: tuple[str, ...] = ()
    max_len: int = 0
    pattern: str = ""
    help_ru: str = ""

    def coerce(self, value: Any) -> Any:
        """Приводит значение к типу поля; бросает ValueError при ошибке."""
        if value is None or value == "":
            if self.required:
                raise ValueError(f"Поле «{self.label}» обязательно")
            return self.default
        try:
            if self.type in (FieldType.INT, FieldType.MONEY, FieldType.PERCENT):
                number = float(str(value).strip().replace(" ", "").replace(",", "."))
                if not math.isfinite(number):
                    raise ValueError("Число должно быть конечным")
                if self.type is FieldType.INT:
                    if not number.is_integer():
                        raise ValueError("Ожидается целое число")
                    return int(number)
                return round(number, 2)
            if self.type is FieldType.BOOL:
                if isinstance(value, bool):
                    return value
                text = str(value).strip().lower()
                if text in {"1", "true", "yes", "да"}:
                    return True
                if text in {"0", "false", "no", "нет"}:
                    return False
                raise ValueError("Ожидается да/нет")
            return str(value).strip()
        except (
            TypeError,
            ValueError,
            OverflowError,
        ) as exc:  # pragma: no cover - защита от мусора
            raise ValueError(
                f"Поле «{self.label}»: неверный формат ({value!r})"
            ) from exc

    def validate(self, value: Any) -> str | None:
        """Возвращает текст ошибки или None (никогда не бросает исключений)."""
        if value in (None, ""):
            return f"«{self.label}»: обязательное поле" if self.required else None
        try:
            if self.type is FieldType.MONEY and float(value) <= 0:
                return f"«{self.label}»: сумма должна быть больше нуля"
            if self.type is FieldType.INT and int(value) < 0:
                return f"«{self.label}»: отрицательное значение"
        except (TypeError, ValueError, OverflowError):
            return f"«{self.label}»: неверный формат ({value!r})"
        if self.max_len and len(str(value)) > self.max_len:
            return f"«{self.label}»: не более {self.max_len} символов"
        if self.pattern and not re.fullmatch(self.pattern, str(value)):
            return f"«{self.label}»: значение не соответствует формату"
        if (
            self.choices
            and self.type is not FieldType.BOOL
            and str(value) not in self.choices
        ):
            return f"«{self.label}»: допустимые значения: {', '.join(self.choices)}"
        return None


@dataclass(frozen=True, slots=True)
class DocumentSpec:
    key: str
    label: str
    kind: DocKind = DocKind.USER_DOC
    required: bool = True
    sign: SignMode = SignMode.CMS
    patterns: tuple[str, ...] = ()
    mime_types: tuple[str, ...] = ()
    max_mb: float = 50.0
    note_ru: str = ""


@dataclass(frozen=True, slots=True)
class PricingRule:
    """Правило формирования стартового ценового предложения."""

    strategy: str = "lot_amount"  # lot_amount | fixed | manual
    factor: float = 1.0  # множитель к сумме лота
    min_factor: float = 0.5  # ниже не опускаемся (антидемпинг)
    max_factor: float = 1.0
    fixed_amount: float = 0.0
    step: float = 0.01
    note_ru: str = ""

    def suggest(self, lot_amount: float | None) -> float | None:
        if self.strategy == "fixed":
            return round(self.fixed_amount, 2) or None
        if (
            self.strategy == "manual"
            or not lot_amount
            or not math.isfinite(lot_amount)
            or lot_amount < 0
        ):
            return None
        factor = min(max(self.factor, self.min_factor), self.max_factor)
        price = self._round(lot_amount * factor)
        # Округление к ближайшему шагу могло вывести цену за границы лота —
        # и она не прошла бы собственную validate().
        step = self.step or 0.01
        upper = lot_amount * self.max_factor
        lower = lot_amount * self.min_factor
        if price > upper:
            price = round(math.floor(upper / step + 1e-9) * step, 2)
        elif price < lower:
            price = round(math.ceil(lower / step - 1e-9) * step, 2)
        return price

    def _round(self, value: float) -> float:
        step = self.step or 0.01
        return round(round(value / step) * step, 2)

    def validate(self, price: float, lot_amount: float | None) -> str | None:
        if not math.isfinite(price) or price <= 0:
            return "Цена должна быть конечным числом больше нуля"
        if lot_amount is not None and not math.isfinite(lot_amount):
            return "Некорректная сумма лота"
        if lot_amount:
            factor = price / lot_amount
            if factor < self.min_factor:
                return (
                    f"Цена {price:,.2f} ниже допустимого порога "
                    f"({self.min_factor:.0%} от суммы лота)"
                )
            if factor > self.max_factor:
                return f"Цена {price:,.2f} выше суммы лота — заявка будет отклонена"
        return None


@dataclass(frozen=True, slots=True)
class DeliveryRule:
    days_default: int = 30
    days_min: int = 1
    days_max: int = 730
    place_source: str = "lot"  # kato лота
    note_ru: str = ""


@dataclass(frozen=True, slots=True)
class NicheBlueprint:
    id: str
    title_ru: str
    keywords: tuple[str, ...]
    fields: tuple[FieldSpec, ...]
    documents: tuple[DocumentSpec, ...]
    pricing: PricingRule = PricingRule()
    delivery: DeliveryRule = DeliveryRule()
    comment_template: str = ""
    notes_ru: tuple[str, ...] = ()

    # -- выборки ----------------------------------------------------------- #
    def field(self, key: str) -> FieldSpec | None:
        return next((f for f in self.fields if f.key == key), None)

    def document(self, key: str) -> DocumentSpec | None:
        return next((d for d in self.documents if d.key == key), None)

    @property
    def required_fields(self) -> tuple[FieldSpec, ...]:
        return tuple(f for f in self.fields if f.required)

    @property
    def required_documents(self) -> tuple[DocumentSpec, ...]:
        return tuple(d for d in self.documents if d.required)

    def manual_fields(self, include_optional: bool = True) -> tuple[FieldSpec, ...]:
        """Поля, которые реально нужно вводить руками (остальное — авто)."""
        return tuple(
            f
            for f in self.fields
            if f.source is Source.MANUAL and (f.required or include_optional)
        )

    # -- валидация --------------------------------------------------------- #
    def validate(
        self,
        values: Mapping[str, Any],
        lot_amount: float | None = None,
        price: float | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for spec in self.fields:
            raw = values.get(spec.key)
            try:
                coerced = spec.coerce(raw)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if coerced is not None:
                problem = spec.validate(coerced)
                if problem:
                    errors.append(problem)
        if price is not None:
            problem = self.pricing.validate(float(price), lot_amount)
            if problem:
                errors.append(problem)
        return errors

    def build_comment(self, values: Mapping[str, Any]) -> str:
        if not self.comment_template:
            return ""
        try:
            return self.comment_template.format(**values)
        except (KeyError, IndexError):
            return self.comment_template


# --------------------------------------------------------------------------- #
# Общие поля/документы
# --------------------------------------------------------------------------- #
PRICE_FIELD = FieldSpec(
    key="price",
    label="Цена заявки, ₸",
    type=FieldType.MONEY,
    required=True,
    source=Source.DERIVED,
    help_ru="Считается автоматически: сумма лота × коэффициент.",
)
VAT_FIELD = FieldSpec(
    key="vat_included",
    label="Цена с НДС",
    type=FieldType.BOOL,
    required=False,
    source=Source.MANUAL,
    default=True,
)
DELIVERY_DAYS_FIELD = FieldSpec(
    key="delivery_days",
    label="Срок поставки, дней",
    type=FieldType.INT,
    required=True,
    source=Source.MANUAL,
    default=30,
)
DELIVERY_PLACE_FIELD = FieldSpec(
    key="delivery_place",
    label="Место поставки (КТ)",
    type=FieldType.TEXT,
    required=True,
    source=Source.LOT,
    lot_field="plnPointKatoList",
    help_ru="Берётся из лота автоматически.",
)
COMMENT_FIELD = FieldSpec(
    key="comment",
    label="Комментарий к заявке",
    type=FieldType.MULTILINE,
    required=False,
    source=Source.DERIVED,
    max_len=1000,
)
AGREEMENT_FIELD = FieldSpec(
    key="agree_terms",
    label="Согласие с условиями закупки",
    type=FieldType.BOOL,
    required=True,
    source=Source.MANUAL,
    default=True,
)

PRICE_OFFER_DOC = DocumentSpec(
    key="price_offer",
    label="Ценовое предложение (формируется приложением)",
    kind=DocKind.GENERATED,
    required=True,
    sign=SignMode.CMS,
    note_ru="Генерируется автоматически из полей заявки и подписывается ЭЦП.",
)
TZ_DOC = DocumentSpec(
    key="tz_signed",
    label="Техническая спецификация — подписанный экземпляр",
    kind=DocKind.LOT_DOC,
    required=True,
    sign=SignMode.CMS,
    patterns=("*.pdf", "*.doc", "*.docx"),
    note_ru="Берётся из документов лота и подписывается пачкой вместе с остальными.",
)
SUPPLIER_APP_DOC = DocumentSpec(
    key="supplier_app",
    label="Заявка поставщика (формируется приложением)",
    kind=DocKind.GENERATED,
    required=True,
    sign=SignMode.CMS,
)
PERMIT_DOC = DocumentSpec(
    key="permit_copy",
    label="Нотариальная копия лицензии/разрешения",
    kind=DocKind.USER_DOC,
    required=False,
    sign=SignMode.CMS,
    patterns=("*.pdf", "*.jpg", "*.jpeg", "*.png"),
    max_mb=20.0,
)
QUALITY_DOC = DocumentSpec(
    key="quality_cert",
    label="Сертификаты соответствия / качества",
    kind=DocKind.USER_DOC,
    required=False,
    sign=SignMode.CMS,
    patterns=("*.pdf", "*.jpg", "*.jpeg", "*.png"),
    max_mb=20.0,
)


# --------------------------------------------------------------------------- #
# Отраслевые шаблоны
# --------------------------------------------------------------------------- #
FOOD_SUPPLY = NicheBlueprint(
    id="food_supply",
    title_ru="Продукты питания (поставка)",
    keywords=(
        "продукт",
        "питани",
        "мяс",
        "молок",
        "хлеб",
        "овощ",
        "фрукт",
        "крупа",
        "крупы",
        "мук",
        "сахар",
        "масл",
        "рыб",
        "птиц",
        "яйц",
        "кондитер",
        "минеральн",
        "сок",
        "консерв",
        "соль",
        "специи",
        "макарон",
        "бакале",
    ),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        DELIVERY_DAYS_FIELD,
        DELIVERY_PLACE_FIELD,
        FieldSpec(
            key="shelf_life",
            label="Остаточный срок годности, мес.",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=6,
            help_ru="Обычно требуется не менее 80% от срока годности.",
        ),
        FieldSpec(
            key="manufacturer_country",
            label="Страна происхождения товара",
            type=FieldType.TEXT,
            required=True,
            source=Source.MANUAL,
            default="KZ",
        ),
        FieldSpec(
            key="vet_certificate",
            label="Наличие ветсправки/сертификата",
            type=FieldType.BOOL,
            required=True,
            source=Source.MANUAL,
            default=True,
        ),
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(
        PRICE_OFFER_DOC,
        TZ_DOC,
        SUPPLIER_APP_DOC,
        DocumentSpec(
            key="food_cert",
            label="Декларация/сертификат соответствия ТР ТС",
            kind=DocKind.USER_DOC,
            required=True,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.jpeg", "*.png"),
            max_mb=20.0,
        ),
        QUALITY_DOC,
        PERMIT_DOC,
    ),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.55, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=14, days_min=1, days_max=365),
    comment_template=(
        "Поставка продуктов питания. Страна происхождения: {manufacturer_country}. "
        "Остаточный срок годности не менее {shelf_life} мес. "
        "Срок поставки: {delivery_days} дней."
    ),
    notes_ru=(
        "Сертификаты ТР ТС должны действовать на дату подачи заявки.",
        "Остаточный срок годности — критичный критерий допуска.",
    ),
)


CONSTRUCTION = NicheBlueprint(
    id="construction",
    title_ru="Строительно-монтажные работы (СМР)",
    keywords=(
        "строитель",
        "смр",
        "ремонт",
        "реконструкц",
        "капитальн",
        "кровл",
        "фасад",
        "отделочн",
        "монтаж",
        "канализ",
        "водопровод",
        "электромонтаж",
        "благоустрой",
        "дорог",
        "асфальт",
        "тротуар",
        "фундамент",
        "бетон",
        "сметн",
    ),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        FieldSpec(
            key="license_no",
            label="Номер лицензии (СМР, ГАСК)",
            type=FieldType.TEXT,
            required=True,
            source=Source.MANUAL,
            max_len=64,
        ),
        FieldSpec(
            key="work_days",
            label="Срок выполнения работ, дней",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=60,
        ),
        DELIVERY_PLACE_FIELD,
        FieldSpec(
            key="subcontract_share",
            label="Доля субподряда, %",
            type=FieldType.PERCENT,
            required=False,
            source=Source.MANUAL,
            default=0.0,
        ),
        FieldSpec(
            key="warranty_months",
            label="Гарантия на работы, мес.",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=24,
        ),
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(
        PRICE_OFFER_DOC,
        TZ_DOC,
        SUPPLIER_APP_DOC,
        DocumentSpec(
            key="gask_license",
            label="Лицензия ГАСК на СМР (или нотариальная копия)",
            kind=DocKind.USER_DOC,
            required=True,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.jpeg", "*.png"),
        ),
        DocumentSpec(
            key="experience_ref",
            label="Справка об опыте аналогичных работ",
            kind=DocKind.USER_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.docx"),
            max_mb=20.0,
        ),
        DocumentSpec(
            key="pesd",
            label="ПСД / сметная документация (если работа с ТЭО/ПСД)",
            kind=DocKind.LOT_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.xls", "*.xlsx", "*.zip"),
        ),
        QUALITY_DOC,
    ),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.6, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=60, days_min=1, days_max=1095),
    comment_template=(
        "Работы по лицензии № {license_no}. Срок выполнения: {work_days} дней, "
        "гарантия {warranty_months} мес. Доля субподряда: {subcontract_share}%."
    ),
    notes_ru=(
        "Признак СМР приходит в лоте полем Lots.isConstructionWork.",
        "Требование к лицензии ГАСК зависит от объёма и вида работ.",
    ),
)


IT_EQUIPMENT = NicheBlueprint(
    id="it_equipment",
    title_ru="Компьютерная техника и ПО",
    keywords=(
        "компьютер",
        "ноутбук",
        "сервер",
        "монитор",
        "принтер",
        "мфу",
        "оргтехник",
        "сетев",
        "программн",
        "лицензи",
        "картридж",
        "проектор",
        "видеонаблюд",
        "телекоммуникац",
        "икт",
    ),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        DELIVERY_DAYS_FIELD,
        DELIVERY_PLACE_FIELD,
        FieldSpec(
            key="brand", label="Бренд / модель", type=FieldType.TEXT, required=True
        ),
        FieldSpec(
            key="warranty_months",
            label="Гарантия, мес.",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=36,
        ),
        FieldSpec(
            key="origin_country",
            label="Страна происхождения",
            type=FieldType.TEXT,
            required=True,
            source=Source.MANUAL,
            default="KZ",
        ),
        FieldSpec(
            key="is_producer",
            label="Являюсь производителем/авториз. партнёром",
            type=FieldType.BOOL,
            required=True,
            source=Source.MANUAL,
            default=False,
        ),
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(
        PRICE_OFFER_DOC,
        TZ_DOC,
        SUPPLIER_APP_DOC,
        DocumentSpec(
            key="authorization_letter",
            label="Авторизационное письмо производителя",
            kind=DocKind.USER_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.png"),
            max_mb=20.0,
        ),
        DocumentSpec(
            key="ctkz_cert",
            label="Сертификат СТ KZ / декларация ТР ТС",
            kind=DocKind.USER_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.png"),
            max_mb=20.0,
        ),
        QUALITY_DOC,
        PERMIT_DOC,
    ),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.6, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=30, days_min=1, days_max=365),
    comment_template=(
        "Поставка ИКТ: {brand}. Гарантия {warranty_months} мес., "
        "страна происхождения {origin_country}, срок поставки {delivery_days} дней."
    ),
    notes_ru=(
        "В закупках ИКТ часто требуется СТ KZ и авторизационное письмо.",
        "Для ПО указывайте количество лицензий в комментарии.",
    ),
)

MEDICAL_SUPPLY = NicheBlueprint(
    id="medical_supply",
    title_ru="Медицинские изделия и препараты",
    keywords=(
        "медицин",
        "лекарств",
        "препарат",
        "шприц",
        "бинт",
        "расходн",
        "реагент",
        "лаборатор",
        "вакцин",
        "дезинфекц",
        "санитар",
    ),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        DELIVERY_DAYS_FIELD,
        DELIVERY_PLACE_FIELD,
        FieldSpec(
            key="registration_kz",
            label="Номер РУ в РК",
            type=FieldType.TEXT,
            required=True,
            source=Source.MANUAL,
            max_len=64,
            help_ru="Регистрационное удостоверение МЗ РК.",
        ),
        FieldSpec(
            key="shelf_life",
            label="Остаточный срок годности, мес.",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=12,
        ),
        FieldSpec(
            key="storage_temp",
            label="Условия хранения",
            type=FieldType.TEXT,
            required=False,
            source=Source.MANUAL,
            default="+15..+25 °C",
        ),
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(
        PRICE_OFFER_DOC,
        TZ_DOC,
        SUPPLIER_APP_DOC,
        DocumentSpec(
            key="registration_cert",
            label="Регистрационное удостоверение МЗ РК",
            kind=DocKind.USER_DOC,
            required=True,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.png"),
            max_mb=20.0,
        ),
        DocumentSpec(
            key="pharma_license",
            label="Лицензия на фармдеятельность",
            kind=DocKind.USER_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.png"),
            max_mb=20.0,
        ),
        QUALITY_DOC,
    ),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.6, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=21, days_min=1, days_max=365),
    comment_template=(
        "Медицинская продукция, РУ № {registration_kz}. Остаточный срок годности "
        "не менее {shelf_life} мес. Условия хранения: {storage_temp}."
    ),
    notes_ru=(
        "Цены на препараты могут регулироваться госреестром — не занижайте ниже лимита.",
    ),
)


CLEANING_SERVICES = NicheBlueprint(
    id="cleaning_services",
    title_ru="Клининговые и сервисные услуги",
    keywords=(
        "клининг",
        "уборк",
        "санитарн",
        "дезинсекц",
        "дератизац",
        "обслужив",
        "техобслужив",
        "утилизац",
        "стирк",
        "прачечн",
    ),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        FieldSpec(
            key="service_months",
            label="Период оказания услуг, мес.",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=12,
        ),
        DELIVERY_PLACE_FIELD,
        FieldSpec(
            key="staff_count",
            label="Количество персонала",
            type=FieldType.INT,
            required=True,
            source=Source.MANUAL,
            default=2,
        ),
        FieldSpec(
            key="shift_mode",
            label="Режим работы",
            type=FieldType.TEXT,
            required=False,
            source=Source.MANUAL,
            default="5/2, 08:00–17:00",
        ),
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(
        PRICE_OFFER_DOC,
        TZ_DOC,
        SUPPLIER_APP_DOC,
        DocumentSpec(
            key="staff_qualification",
            label="Подтверждение квалификации персонала",
            kind=DocKind.USER_DOC,
            required=False,
            sign=SignMode.CMS,
            patterns=("*.pdf", "*.jpg", "*.png"),
            max_mb=20.0,
        ),
        PERMIT_DOC,
    ),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.6, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=365, days_min=1, days_max=1095),
    comment_template=(
        "Услуги: {service_months} мес., персонал {staff_count} чел., режим: {shift_mode}."
    ),
    notes_ru=(
        "Для дезинсекции/дератизации нужна лицензия на соответствующий вид деятельности.",
    ),
)

GENERIC = NicheBlueprint(
    id="generic",
    title_ru="Универсальный шаблон (любая закупка)",
    keywords=(),
    fields=(
        PRICE_FIELD,
        VAT_FIELD,
        DELIVERY_DAYS_FIELD,
        DELIVERY_PLACE_FIELD,
        AGREEMENT_FIELD,
        COMMENT_FIELD,
    ),
    documents=(PRICE_OFFER_DOC, TZ_DOC, SUPPLIER_APP_DOC, QUALITY_DOC, PERMIT_DOC),
    pricing=PricingRule(
        strategy="lot_amount", factor=1.0, min_factor=0.5, max_factor=1.0
    ),
    delivery=DeliveryRule(days_default=30, days_min=1, days_max=730),
    comment_template=(
        "Заявка подана через FastBid GosZakup. Срок: {delivery_days} дней."
    ),
    notes_ru=("Ниша не распознана — проверьте состав полей и документов вручную.",),
)


# --------------------------------------------------------------------------- #
# Реестр и резолвер
# --------------------------------------------------------------------------- #
BLUEPRINTS: dict[str, NicheBlueprint] = {
    bp.id: bp
    for bp in (
        FOOD_SUPPLY,
        CONSTRUCTION,
        IT_EQUIPMENT,
        MEDICAL_SUPPLY,
        CLEANING_SERVICES,
        GENERIC,
    )
}

DEFAULT_BLUEPRINT_ID = GENERIC.id


def get_blueprint(blueprint_id: str) -> NicheBlueprint:
    """Возвращает шаблон по id; при неизвестном id — универсальный."""
    return BLUEPRINTS.get(blueprint_id, GENERIC)


def score_blueprint(blueprint: NicheBlueprint, text: str) -> int:
    """Сколько ключевых слов ниши нашлось в тексте (наименование+описание лота).

    Основа ищется только в НАЧАЛЕ слова: подстрока давала ложные ниши
    («консоль» → «соль», «высоковольтный» → «сок»).
    """
    haystack = text.lower()
    return sum(
        1
        for keyword in blueprint.keywords
        if re.search(r"\b" + re.escape(keyword.strip()), haystack)
    )


def resolve_blueprint(text: str, min_score: int = 1) -> NicheBlueprint:
    """Подбирает нишевый шаблон по наименованию/описанию лота.

    Побеждает шаблон с наибольшим числом совпадений. Ничья между нишами —
    универсальный шаблон: чужой набор обязательных документов хуже общего.
    """
    best: NicheBlueprint | None = None
    best_score = 0
    tie = False
    for blueprint in BLUEPRINTS.values():
        if blueprint is GENERIC:
            continue
        score = score_blueprint(blueprint, text)
        if score > best_score:
            best, best_score, tie = blueprint, score, False
        elif score and score == best_score:
            tie = True
    if best is None or best_score < min_score or tie:
        return GENERIC
    return best


def default_values(blueprint: NicheBlueprint) -> dict[str, Any]:
    """Значения по умолчанию для полей шаблона (что можно — сразу из дефолтов)."""
    values: dict[str, Any] = {}
    for spec in blueprint.fields:
        if spec.default is not None:
            values[spec.key] = spec.default
    return values


def missing_required_documents(
    blueprint: NicheBlueprint,
    provided: Iterable[str],
) -> list[DocumentSpec]:
    """Обязательные документы, которых нет в наборе."""
    provided_set = set(provided)
    return [doc for doc in blueprint.required_documents if doc.key not in provided_set]


def build_profile_values(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Достаёт значения полей со source=PROFILE из профиля поставщика."""
    return {
        "bin_iin": profile.get("bin_iin", ""),
        "supplier_name": profile.get("name_ru", ""),
        "email": profile.get("email", ""),
        "phone": profile.get("phone", ""),
        "address": profile.get("address", ""),
        "signer_fio": profile.get("signer_fio", ""),
        "signer_position": profile.get("signer_position", ""),
    }


__all__ = [
    "BLUEPRINTS",
    "DEFAULT_BLUEPRINT_ID",
    "GENERIC",
    "DeliveryRule",
    "DocKind",
    "DocumentSpec",
    "FieldSpec",
    "FieldType",
    "NicheBlueprint",
    "PricingRule",
    "SignMode",
    "Source",
    "build_profile_values",
    "default_values",
    "get_blueprint",
    "missing_required_documents",
    "resolve_blueprint",
    "score_blueprint",
]
