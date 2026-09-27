"""Конфигурация FastBid GosZakup: URL, таймауты, лимиты retry, расписание опроса.

ВАЖНО О ДОСТОВЕРНОСТИ ENDPOINT'ОВ
---------------------------------
* Публичный реестр (``PortalEndpoints.base`` = https://ows.goszakup.gov.kz) —
  GraphQL API v3, подтверждён по официальной схеме:
  https://ows.goszakup.gov.kz/help/v3/schema/query.doc.html
  Типы ``Lots`` / ``TrdBuy`` / ``LotsFiltersInput`` и поля
  (``id, lotNumber, refLotStatusId, amount, trdBuyId, TrdBuy.startDate``)
  взяты из схемы как есть.
* Публичный OWS-реестр работает ТОЛЬКО НА ЧТЕНИЕ: мутаций подачи заявки в нём
  нет. Подача заявки — действие личного кабинета поставщика
  (``cabinet_base`` = https://v3bl.goszakup.gov.kz). Пути кабинета в этом файле
  заданы как шаблоны и помечены ``# VERIFY:`` — перед промышленной
  эксплуатацией их нужно сверить с реальным трафиком кабинета (DevTools →
  Network) и, при необходимости, поправить здесь, не трогая код ядра.
* Для автономного тестирования все пути обслуживает ``utils/mock_server.py``.

Модуль не тянет внешних зависимостей: только stdlib.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

APP_NAME: Final[str] = "FastBid GosZakup"
APP_VERSION: Final[str] = "1.1.0"
PORTAL_LOGIN_URL: Final[str] = "https://v3bl.goszakup.gov.kz/ru/user/sso_redirect"
# Единый список loopback-адресов: mock-контракт и доверие к самоподписанному
# TLS NCALayer допускаются ТОЛЬКО для них.
LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost"})
OWS_TOKEN_NOTICE: Final[str] = (
    "Реестр OWS v3 (ows.goszakup.gov.kz) доступен только организациям, "
    "которым выдан доступ к унифицированным сервисам. Доступ выпускается по "
    "запросу организации в АО «Центр электронных финансов» (support@ecc.kz, "
    "8 7172 73 55 15); после выпуска токен появляется в кабинете: "
    "v3bl.goszakup.gov.kz → Профиль участника → Токены."
)
LIVE_AUTH_NOTICE: Final[str] = (
    "Вход в живой кабинет из FastBid пока недоступен: контракт SSO и проверка "
    "кабинетной сессии не подтверждены. Используйте официальный вход в браузере "
    "через zakup.gov.kz. Вход в браузере не авторизует FastBid автоматически."
)
LIVE_SUBMIT_NOTICE: Final[str] = (
    "LIVE-подача заблокирована: адреса и формат подачи кабинета не подтверждены. "
    "Доступны локальная проверка (--mock) и DRY-RUN без подписи и загрузок."
)

# Приём заявок на портале открывается в TrdBuy.startDate. Это и есть T0.
T0_SOURCE_FIELD: Final[str] = "TrdBuy.startDate"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_ENV_WARNINGS: list[str] = []


def _env(name: str, default: Any) -> Any:
    """Читает значение из окружения с приведением к типу default.

    Некорректное числовое значение (например, ``FASTBID_NCA_PORT=abc``) не
    роняет запуск (даже ``--help``) — берётся значение по умолчанию, а
    предупреждение попадает в ``ENV_WARNINGS``.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    if isinstance(default, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on", "да"}
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            _ENV_WARNINGS.append(f"{name}={raw!r} не число — использовано {default!r}")
            return default
    if isinstance(default, float):
        try:
            return float(raw)
        except ValueError:
            _ENV_WARNINGS.append(f"{name}={raw!r} не число — использовано {default!r}")
            return default
    if isinstance(default, tuple):
        return tuple(part.strip() for part in raw.split(",") if part.strip())
    return raw


def user_data_dir() -> Path:
    """Каталог пользовательских данных (кроссплатформенно)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "FastBidGosZakup"


DATA_DIR: Final[Path] = user_data_dir()


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PortalEndpoints:
    """URL портала. Публичные (OWS) — сверены со схемой v3; кабинет — VERIFY."""

    base: str = _env("FASTBID_OWS_BASE", "https://ows.goszakup.gov.kz")
    graphql_path: str = "/v3/graphql"
    cabinet_base: str = _env("FASTBID_CABINET_BASE", "https://v3bl.goszakup.gov.kz")

    # Человекочитаемая карточка объявления (для логов/UI)
    lot_view_path: str = "/ru/announce/index/{trd_buy_id}?tab=lots"

    # --- Аутентификация по ЭЦП (VERIFY по трафику кабинета) ---
    auth_challenge_path: str = "/api/auth/challenge"  # VERIFY
    auth_login_path: str = "/api/auth/login"  # VERIFY
    session_ping_path: str = "/api/session/ping"  # VERIFY

    # --- Подача заявки (VERIFY по трафику кабинета) ---
    bid_payload_path: str = "/api/bid/{lot_id}/payload"  # VERIFY
    bid_attachment_path: str = "/api/bid/{lot_id}/attachments"  # VERIFY
    bid_submit_path: str = "/api/bid/{lot_id}/submit"  # VERIFY
    bid_status_path: str = "/api/bid/{lot_id}/status/{idem_key}"  # VERIFY

    def graphql_url(self) -> str:
        return f"{self.base.rstrip('/')}{self.graphql_path}"

    def cabinet_url(self, path_template: str, **params: Any) -> str:
        path = path_template.format(**params) if params else path_template
        return f"{self.cabinet_base.rstrip('/')}{path}"

    def lot_view_url(self, trd_buy_id: int | str) -> str:
        return self.cabinet_url(self.lot_view_path, trd_buy_id=trd_buy_id)


# --------------------------------------------------------------------------- #
# Таймауты и retry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Timeouts:
    connect: float = 3.0
    read: float = 8.0
    write: float = 10.0
    pool: float = 5.0
    # Жёсткий дедлайн финального submit: он должен быть коротким,
    # чтобы успеть отдать заявку в первые секунды после T0.
    submit: float = 12.0
    attachment_upload: float = 60.0
    lot_query: float = 6.0
    # Таймауты NCALayer живут в NCALayerSettings (единый источник правды):
    # sign_timeout / sign_batch_timeout / rpc_timeout.


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 3
    backoff_base: float = 0.15
    backoff_max: float = 2.0
    jitter: float = 0.1
    retry_statuses: tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    relogin_attempts: int = 2
    relogin_delay: float = 1.5
    # Жёсткий бюджет «горячей» части после T0: все POST submit, повторы на
    # 425/сбоях и verify перед повтором укладываются в N секунд от первого
    # POST. Каждый запрос в окне — одна попытка без relogin, таймаут
    # подрезается до остатка бюджета. Повторы — с тем же idem-ключом.
    submit_budget_s: float = 5.0
    # Перед повторным submit обязательно спрашиваем статус по idempotency-key:
    # двойная подача заявки недопустима.
    submit_verify_before_retry: bool = True


# --------------------------------------------------------------------------- #
# Сессия
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class SessionSettings:
    max_age_seconds: int = 14 * 3600  # портал держит сессию до 14 ч
    keepalive_interval: float = 300.0  # штатный пинг раз в 5 минут
    keepalive_jitter: float = 0.08
    keepalive_max_failures: int = 3
    # За N секунд до T0 переходим на «горячий» keep-alive, чтобы TCP/TLS
    # соединение и cookie были гарантированно живыми к моменту submit.
    hot_keepalive_lead: float = 600.0
    hot_keepalive_interval: float = 60.0
    max_requests_per_session: int = 0  # 0 = без ограничения
    prefetch_session_state_on_start: bool = True


# --------------------------------------------------------------------------- #
# Watcher (T0 trigger)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PollStep:
    """Ступень расписания: до T0 осталось `to_t0_s` секунд → интервал опроса."""

    to_t0_s: float
    interval_s: float


def default_poll_schedule() -> tuple[PollStep, ...]:
    """Адаптивный поллер: чем ближе T0, тем чаще опрос.

    Интервалы подобраны так, чтобы суммарная нагрузка на портал была
    вежливой: >3 ч — раз в 3 минуты, у самого T0 — 5 раз в секунду.
    """
    return (
        PollStep(3 * 3600.0, 180.0),
        PollStep(1800.0, 60.0),
        PollStep(600.0, 20.0),
        PollStep(120.0, 5.0),
        PollStep(30.0, 1.0),
        PollStep(5.0, 0.35),
        PollStep(0.0, 0.20),
    )


@dataclass(frozen=True, slots=True)
class WatcherSettings:
    schedule: tuple[PollStep, ...] = default_poll_schedule()
    prewarm_lead_seconds: float = 90.0  # за 90 с до T0 заявка «взведена»
    post_open_interval: float = 0.30  # подтверждение открытия после T0
    min_interval_hard: float = 0.15  # ниже не опускаемся никогда
    clock_sync_samples: int = 3
    # Фоновое уточнение часов зондами на смене секунды (refine_clock):
    # запускается, если до T0 больше clock_refine_min_lead_s.
    clock_refine_probes: int = 6
    clock_target_ms: float = 25.0
    clock_refine_min_lead_s: float = 2.0
    conditional_requests: bool = True  # If-None-Match / If-Modified-Since
    max_watch_seconds: float = 6 * 3600
    # Портал публикует даты в казахстанском времени (UTC+5, без перехода на
    # летнее время). Все сравнения идут от синхронизированных часов сервера.
    portal_tz: str = "Asia/Almaty"
    # Опережение подачи: заявку отправляем за N мс до расчётного T0, чтобы
    # компенсировать сетевую задержку и попасть в первую секунду окна.
    # Небольшое значение + страховка retry-на-425 покрывают джиттер RTT.
    open_lead_ms: float = 50.0
    # Статусы лота, означающие «приём заявок открыт». Сверяем по
    # RefLotsStatus.code (строка), затем по nameRu. Справочник v3 отдаёт
    # оба поля, числовой код портала не документирован → матчим строки.
    # «Опубликован»/PUBLISHED сюда НЕ входит: это лишь факт публикации,
    # окно приёма определяется ДАТАМИ (TrdBuy.startDate/endDate).
    open_status_codes: tuple[str, ...] = ("ACCEPTING", "ACCEPT", "OPEN")
    open_status_names: tuple[str, ...] = (
        "прием заявок",
        "приём заявок",
        "заявки принимаются",
        "прием ценовых",
    )
    closed_status_names: tuple[str, ...] = (
        "завершен",
        "завершён",
        "отменен",
        "отменён",
        "не состоялся",
        "рассмотрение",
    )


# --------------------------------------------------------------------------- #
# NCALayer (сервис НУЦ РК)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class NCALayerSettings:
    """Параметры локального сервиса НУЦ РК (NCALayer / KAZTOKEN desktop).

    Протокол подтверждён:
      * модуль ``kz.gov.pki.knca.basics`` (метод ``sign``), конверт
        ``{"module", "method", "args"}``, ``args.data`` допускает МАССИВ —
        это и есть пакетная подпись одним диалогом;
      * ответ ``{"status": bool, "body": {"result": ...}}``;
        ``body`` без ``result`` = пользователь отменил операцию;
      * ошибка ``{"status": false, "code", "message", "details"}``.
    """

    host: str = _env("FASTBID_NCA_HOST", "127.0.0.1")
    port: int = _env("FASTBID_NCA_PORT", 13579)
    # Настоящий NCALayer работает по TLS (wss) с локальным самоподписанным
    # сертификатом. ws применяется только для mock-сервера (redirect_to_mock).
    scheme: str = _env("FASTBID_NCA_SCHEME", "wss")
    basics_path: str = "/kz.gov.pki.knca.basics"
    legacy_path: str = "/kz.gov.pki.knca"
    module_basics: str = "kz.gov.pki.knca.basics"
    module_legacy: str = "kz.gov.pki.knca"
    allowed_storages: tuple[str, ...] = (
        "AKKaztokenStore",
        "AKEToken72KStore",
        "AKEToken5110Store",
        "AKJaCartaStore",
        "AKKZIDCardStore",
        "AKAKEYStore",
        "PKCS12",
        "JKS",
    )
    locale: str = "ru"
    ext_key_usage_oids: tuple[str, ...] = ("1.3.6.1.5.5.7.3.4",)  # ЭЦП (подпись)
    cms_decode: bool = True  # data приходит в base64 → просим декодировать
    cms_encapsulate: bool = True  # подпись встроена в CMS (не detached)
    tsa_profile: bool = False  # метка времени tsp.pki.gov.kz
    batch_in_single_request: bool = True  # вся пачка — один вызов = один диалог
    batch_fallback_sequential: bool = True  # старый NCALayer не умеет массив
    # Передавать пароль от контейнера ЭЦП прямо в payload вызова.
    # ВАЖНО: НУЦ РК не документирует поле пароля в методе sign — NCALayer может
    # его проигнорировать и показать свой диалог. Подавление диалога НА КАЖДЫЙ
    # файл обеспечивается самим фактом пакетного вызова (одна операция sign на
    # всю пачку). Флаг оставлен включаемым, чтобы можно было использовать
    # прошивки/сборки NCALayer и KAZTOKEN desktop, поддерживающие проброс
    # пароля, а также для автономных тестов на mock-сервере.
    pass_password: bool = True
    # Режим директора: авто-выбор ключа ЭЦП (диалог выбора не показывается).
    # Алиас сохраняется в DPAPI-профиле (ui → «ЭЦП директора») и подставляется
    # в рантайме; env — только для автономной отладки.
    auto_sign: bool = _env("FASTBID_ECP_AUTO", False)
    key_alias: str = _env("FASTBID_ECP_KEY_ALIAS", "")
    probe_timeout: float = 0.4
    sign_timeout: float = 120.0  # один документ: пользователь вводит пароль
    sign_batch_timeout: float = 180.0  # пачка документов одним диалогом
    rpc_timeout: float = 15.0  # служебные вызовы (getKeyInfo и пр.)
    keep_alive_ping: float | None = None  # NCALayer не любит ping'и → None

    @property
    def basics_url(self) -> str:
        return f"{self.root_url}{self.basics_path}"

    @property
    def legacy_url(self) -> str:
        return f"{self.root_url}{self.legacy_path}"

    @property
    def root_url(self) -> str:
        # IPv6-адрес (::1) в URL обязан быть в квадратных скобках.
        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{self.scheme}://{host}:{self.port}"


# --------------------------------------------------------------------------- #
# Конвейер подачи заявки
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class PipelineSettings:
    doc_upload_concurrency: int = 6  # параллельная предзагрузка документов
    max_document_mb: float = 50.0
    max_documents: int = 40
    idempotent_submit: bool = True  # ключ идемпотентности в каждом submit
    verify_after_submit: bool = True  # подтверждение факта подачи
    # Всё, что можно, делаем ДО T0: хеши, подписи, загрузку файлов.
    upload_before_t0: bool = True
    sign_before_t0: bool = True
    keep_payload_on_failure: bool = True
    price_factor_default: float = 1.0  # множитель к сумме лота для стартовой цены
    price_min_factor: float = 0.5
    price_step: float = 0.01
    hash_algo: str = "sha256"
    retry_attachment_upload: bool = True


# --------------------------------------------------------------------------- #
# Лицензия / UI / логи / профиль поставщика
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class LicenseSettings:
    """Привязка лицензии к БИН/ИИН из ЭЦП + отпечатку железа (HWID).

    Лицензия — Ed25519-подписанный JSON. Приватный ключ вендора в поставку НЕ
    попадает: в приложении только ПУБЛИЧНЫЙ ключ, вшитый в
    ``core/vendor_key.py``. Env-подмены (``FASTBID_LICENSE_PUBKEY``) и файл
    ключа рядом с данными убраны: репозиторий публичный, и без вшитого ключа
    любой мог выпустить себе лицензию. Смена ключа вендора = правка
    ``core/vendor_key.py`` + пересборка.
    """

    license_path: Path = DATA_DIR / "license.json"
    trial_path: Path = DATA_DIR / "trial.json"
    # Переопределяется ТОЛЬКО программно (dataclasses.replace) в тестах:
    # env-переменной для подмены ключа больше нет.
    public_key_pem: str = ""
    trial_days: int = 14
    offline_grace_days: int = 7
    require_hwid_match: bool = True
    require_bin_match: bool = True
    # Блокировать работу (взвод заявок) при недействительной лицензии.
    # По умолчанию False: приложение запускается, показывает статус и
    # позволяет изучать интерфейс, но предупреждает о проблеме с лицензией.
    # Для продажи выставляйте FASTBID_LICENSE_ENFORCE=1 при сборке.
    enforce: bool = _env("FASTBID_LICENSE_ENFORCE", False)


@dataclass(frozen=True, slots=True)
class UISettings:
    # Светлая тема по умолчанию — в стиле zakup.gov.kz
    appearance: str = _env("FASTBID_APPEARANCE", "light")  # light | dark | system
    theme: str = _env("FASTBID_THEME", "green")  # green | blue | dark-blue
    window_size: tuple[int, int] = (1280, 820)
    min_window_size: tuple[int, int] = (1040, 680)
    refresh_ms: int = 100  # период дренажа UI-очереди (10 Гц)
    log_rows: int = 2000
    scaling: float = 1.0
    sound_on_success: bool = False


@dataclass(frozen=True, slots=True)
class LogSettings:
    level: str = _env("FASTBID_LOG_LEVEL", "DEBUG")
    file_name: str = "fastbid.log"
    rotate_mb: float = 8.0
    backups: int = 3
    console: bool = True
    ui_buffer: int = 5000  # кольцевой буфер для UI, записей


@dataclass(frozen=True, slots=True)
class ProfileSettings:
    """Данные поставщика для payload заявки."""

    bin_iin: str = _env("FASTBID_BIN", "")
    name_ru: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    signer_fio: str = ""
    signer_position: str = ""
    doc_dir: Path = DATA_DIR / "docs"
    export_dir: Path = DATA_DIR / "export"


# --------------------------------------------------------------------------- #
# Корневой конфиг
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EcpSettings:
    """Режим директора: ЭЦП и пароль сохранены, диалоги NCALayer не нужны.

    Пароль хранится ТОЛЬКО в DPAPI-шифрованном файле пользовательского
    каталога (расшифровка — тем же пользователем Windows на той же машине),
    в репозиторий и env не попадает. Включение — осознанное решение:
    любой, кто получит сессию Windows директора, сможет подписывать.
    """

    auto_sign: bool = _env("FASTBID_ECP_AUTO", False)
    # Алиас ключа (ИИН/БИН или отпечаток) для авто-выбора в NCALayer.
    key_alias: str = _env("FASTBID_ECP_KEY_ALIAS", "")
    # DPAPI-шифрованный пароль (заполняется из GUI «Настройки»).
    password_file: Path = DATA_DIR / "ecp_secret.bin"


@dataclass(frozen=True, slots=True)
class AppSettings:
    endpoints: PortalEndpoints = PortalEndpoints()
    timeouts: Timeouts = Timeouts()
    retries: RetryPolicy = RetryPolicy()
    session: SessionSettings = SessionSettings()
    watcher: WatcherSettings = WatcherSettings()
    ncalayer: NCALayerSettings = NCALayerSettings()
    pipeline: PipelineSettings = PipelineSettings()
    license: LicenseSettings = LicenseSettings()
    ui: UISettings = UISettings()
    log: LogSettings = LogSettings()
    profile: ProfileSettings = ProfileSettings()
    ecp: EcpSettings = EcpSettings()
    # token и ecp работают с подтверждённым локальным mock-контрактом.
    # LIVE-вход выполняется на официальном сайте; перенос сессии не реализован.
    auth_mode: str = _env("FASTBID_AUTH_MODE", "token")
    dry_run: bool = False
    # Режим работы: live (реальный портал) | mock (локальные заглушки)
    mode: str = "live"

    @property
    def uses_local_mock(self) -> bool:
        """Одного mode=mock недостаточно для разрешения тестового контракта."""
        if self.mode != "mock" or self.ncalayer.host not in LOOPBACK_HOSTS:
            return False
        for base in (self.endpoints.base, self.endpoints.cabinet_base):
            url = urlsplit(base)
            if (
                url.scheme != "http"
                or url.hostname not in LOOPBACK_HOSTS
                or url.username is not None
                or url.password is not None
            ):
                return False
        return True

    @property
    def cabinet_api_verified(self) -> bool:
        """Подтверждён ли контракт API кабинета (вход, ping, загрузка, submit).

        Сейчас подтверждён только локальный mock-контракт. Когда пути кабинета
        будут сверены по HAR-записи реального трафика, условие меняется ЗДЕСЬ
        (и только здесь) — остальной код опирается на это свойство.
        """
        return self.uses_local_mock

    @property
    def live_submit_allowed(self) -> bool:
        """Разрешена ли реальная подпись/загрузка/подача (не DRY-RUN)."""
        return self.cabinet_api_verified

    # -- производные пути -------------------------------------------------- #
    @property
    def data_dir(self) -> Path:
        return DATA_DIR

    @property
    def log_path(self) -> Path:
        return DATA_DIR / self.log.file_name

    def ensure_dirs(self) -> list[Path]:
        created: list[Path] = []
        for path in (
            DATA_DIR,
            self.profile.doc_dir,
            self.profile.export_dir,
        ):
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                created.append(path)
        return created

    # -- модификаторы ------------------------------------------------------ #
    def with_(self, **overrides: Any) -> AppSettings:
        return replace(self, **overrides)

    def redirect_to_mock(
        self, host: str = "127.0.0.1", http_port: int = 8643, ws_port: int = 13580
    ) -> AppSettings:
        """Перенаправляет ВСЁ (реестр + кабинет + NCALayer) на локальные заглушки."""
        base = f"http://{host}:{http_port}"
        endpoints = replace(self.endpoints, base=base, cabinet_base=base)
        ncalayer = replace(
            self.ncalayer,
            host=host,
            port=ws_port,
            scheme="ws",
            probe_timeout=1.0,
        )
        return replace(
            self,
            endpoints=endpoints,
            ncalayer=ncalayer,
            mode="mock",
            auth_mode="ecp",
        )

    def describe(self) -> dict[str, Any]:
        """Компактное описание конфигурации для лога/UI."""
        return {
            "mode": self.mode,
            "ows": self.endpoints.graphql_url(),
            "cabinet": self.endpoints.cabinet_base,
            "ncalayer": self.ncalayer.basics_url,
            "session_max_age_h": round(self.session.max_age_seconds / 3600, 2),
            "keepalive_s": self.session.keepalive_interval,
            "relogin_delay_s": self.retries.relogin_delay,
            "price_factor": self.pipeline.price_factor_default,
            "dry_run": self.dry_run,
            "cabinet_api_verified": self.cabinet_api_verified,
            "live_submit_allowed": self.live_submit_allowed,
            "data_dir": str(DATA_DIR),
        }


def load_settings(**overrides: Any) -> AppSettings:
    """Единая точка входа для получения настроек."""
    settings = AppSettings()
    env_overrides: dict[str, Any] = {}
    if _env("FASTBID_DRY_RUN", False):
        env_overrides["dry_run"] = True
    if env_overrides or overrides:
        settings = replace(settings, **(env_overrides | overrides))
    return settings


SETTINGS: Final[AppSettings] = load_settings()
