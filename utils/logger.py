"""Миллисекундный логгер с выводом в UI и файл.

Формат строки: ``HH:mm:ss.SSS LEVEL [компонент] сообщение``.

Ключевые особенности:
* кольцевой буфер записей (для мгновенной отрисовки в UI без чтения файла);
* ``UILogSink`` — потокобезопасная очередь, которую дренирует Tkinter-поток
  через ``after()``: рабочий поток НИКОГДА не трогает виджеты напрямую;
* ``Stopwatch`` — замер этапов конвейера с точностью до миллисекунд.

Модуль зависит только от stdlib.
"""

from __future__ import annotations

import logging
import logging.handlers
import queue
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Цвета уровней для UI (тёмная тема CustomTkinter)
LEVEL_COLORS: dict[str, str] = {
    "DEBUG": "#7a8290",
    "INFO": "#d8dee9",
    "SUCCESS": "#43c76b",
    "WARNING": "#e8b93b",
    "ERROR": "#e0574b",
    "CRITICAL": "#ff3b30",
}

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


def _success(
    self: logging.Logger, message: str, *args: object, **kwargs: object
) -> None:
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)  # type: ignore[attr-defined]


if not hasattr(logging.Logger, "success"):
    logging.Logger.success = _success  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class LogRecord:
    """Готовая к отрисовке запись лога."""

    ts: datetime
    level: str
    component: str
    message: str

    @property
    def color(self) -> str:
        return LEVEL_COLORS.get(self.level, "#d8dee9")

    def format(self) -> str:
        local = self.ts.astimezone()
        stamp = f"{local:%H:%M:%S}.{local.microsecond // 1000:03d}"
        return f"{stamp} {self.level:<8} [{self.component}] {self.message}"


class MSFormatter(logging.Formatter):
    """Формат с миллисекундами и локальным временем."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s.%(msecs)03d %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        # Локальное время — осознанно: журнал читают операторы на месте.
        local = datetime.fromtimestamp(record.created).astimezone()
        return f"{local:%H:%M:%S}"

    def format(self, record: logging.LogRecord) -> str:
        # Трейсбеки и прочий хвост записи фильтр сообщений не видит.
        return redact_secrets(super().format(record))


# Маскирование секретов в журнале: Bearer-токены не должны попадать в файлы
# и UI-консоль даже при аварийном выводе ответов/исключений целиком.
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-+/=]{8,}", re.IGNORECASE)


def redact_secrets(text: str) -> str:
    """Маскирует Bearer-токены в произвольном тексте журнала."""
    return _BEARER_RE.sub(r"\1***", text)


class SecretsFilter(logging.Filter):
    """Вычищает Bearer-токены из сообщений до попадания в обработчики."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            redacted = redact_secrets(message)
            if redacted != message:
                record.msg, record.args = redacted, None
        except Exception:  # pragma: no cover - фильтр не должен ломать лог
            pass
        return True


class RingLogStore(logging.Handler):
    """Кольцевой буфер записей + подписка для UI."""

    def __init__(self, capacity: int = 5000, level: int = logging.NOTSET) -> None:
        super().__init__(level)
        self._buffer: deque[LogRecord] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = LogRecord(
                ts=datetime.fromtimestamp(record.created, tz=timezone.utc),
                level=record.levelname,
                component=record.name,
                message=record.getMessage(),
            )
        except Exception:  # pragma: no cover - логгер не должен падать
            return
        with self._lock:
            self._buffer.append(entry)

    def snapshot(self, limit: int = 0) -> list[LogRecord]:
        with self._lock:
            items = list(self._buffer)
        return items[-limit:] if limit else items

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()


class UILogSink(logging.Handler):
    """Потокобезопасная очередь для UI-потока."""

    def __init__(self, maxsize: int = 20000) -> None:
        super().__init__(level=logging.NOTSET)
        self.queue: queue.Queue[LogRecord] = queue.Queue(maxsize=maxsize)

    def emit(self, record: logging.LogRecord) -> None:
        # Ошибка форматирования не должна долетать до вызывающего кода
        # (конвейера подачи).
        try:
            entry = LogRecord(
                ts=datetime.fromtimestamp(record.created, tz=timezone.utc),
                level=record.levelname,
                component=record.name,
                message=record.getMessage(),
            )
        except Exception:
            self.handleError(record)
            return
        try:
            self.queue.put_nowait(entry)
        except queue.Full:  # pragma: no cover - UI не успевает
            pass

    def drain(self, max_items: int = 400) -> list[LogRecord]:
        out: list[LogRecord] = []
        for _ in range(max_items):
            try:
                out.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return out


def setup_logging(
    log_path: Path | None = None,
    level: str | int = "DEBUG",
    *,
    console: bool = True,
    rotate_mb: float = 8.0,
    backups: int = 3,
    ui_sink: UILogSink | None = None,
    buffer_capacity: int = 5000,
) -> tuple[RingLogStore, UILogSink]:
    """Настраивает корневой логгер: файл с ротацией + консоль + UI-мост.

    Возвращает (кольцевой буфер, UI-sink). Функция идемпотентна: повторный
    вызов перенастраивает обработчики, не плодя дубликаты.
    """
    if isinstance(level, str):
        # Опечатка в FASTBID_LOG_LEVEL не должна ронять запуск.
        level = logging.getLevelNamesMapping().get(level.strip().upper(), logging.DEBUG)
    root = logging.getLogger()
    root.setLevel(level)

    for handler in list(root.handlers):
        if getattr(handler, "_fastbid", False):
            root.removeHandler(handler)
            handler.close()

    formatter = MSFormatter()
    secrets_filter = SecretsFilter()

    store = RingLogStore(capacity=buffer_capacity, level=logging.NOTSET)
    store._fastbid = True  # type: ignore[attr-defined]
    store.setFormatter(formatter)
    store.addFilter(secrets_filter)
    root.addHandler(store)

    sink = ui_sink or UILogSink()
    sink._fastbid = True  # type: ignore[attr-defined]
    for old in [f for f in sink.filters if isinstance(f, SecretsFilter)]:
        sink.removeFilter(old)
    sink.addFilter(secrets_filter)
    root.addHandler(sink)

    if console:
        console_handler = logging.StreamHandler()
        console_handler._fastbid = True  # type: ignore[attr-defined]
        console_handler.setFormatter(formatter)
        console_handler.addFilter(secrets_filter)
        root.addHandler(console_handler)

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=int(rotate_mb * 1024 * 1024),
            backupCount=backups,
            encoding="utf-8",
        )
        file_handler._fastbid = True  # type: ignore[attr-defined]
        file_handler.setFormatter(formatter)
        file_handler.addFilter(secrets_filter)
        root.addHandler(file_handler)

    # Библиотечные логгеры не должны забивать журнал на DEBUG-уровне
    for noisy in ("httpx", "httpcore", "h2", "websockets", "asyncio", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # TCP-probe NCALayer (открыть сокет и закрыть) заставляет websockets писать
    # ERROR «did not receive a valid HTTP request». Это нормальный сценарий
    # проверки доступности сервиса, а не сбой — не засоряем журнал.
    for quiet in (
        "websockets.server",
        "websockets.asyncio.server",
        "websockets.protocol",
    ):
        logging.getLogger(quiet).setLevel(logging.CRITICAL)

    return store, sink


def get_logger(component: str) -> logging.Logger:
    """Логгер с именем компонента (имя попадает в квадратные скобки)."""
    return logging.getLogger(component)


class Stopwatch:
    """Замер этапов конвейера с миллисекундной точностью.

    Использование::

        sw = Stopwatch("cycle")
        ...
        sw.mark("signed")
        ...
        sw.mark("submitted")
        sw.report()  # {'signed': 431.2, 'submitted': 120.7, 'total': 552.4}
    """

    __slots__ = ("_label", "_last", "_marks", "_start")

    def __init__(self, label: str = "") -> None:
        self._label = label
        self._start = time.perf_counter()
        self._last = self._start
        self._marks: list[tuple[str, float]] = []

    def mark(self, name: str) -> float:
        """Фиксирует этап; возвращает длительность этапа в мс."""
        now = time.perf_counter()
        delta_ms = (now - self._last) * 1000.0
        self._marks.append((name, delta_ms))
        self._last = now
        return delta_ms

    def restart(self) -> None:
        self._start = self._last = time.perf_counter()
        self._marks.clear()

    @property
    def total_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0

    def stage_ms(self, name: str) -> float | None:
        for stage, value in self._marks:
            if stage == name:
                return value
        return None

    def report(self) -> dict[str, float]:
        data = {name: round(value, 1) for name, value in self._marks}
        data["total"] = round(self.total_ms, 1)
        return data

    def summary(self) -> str:
        parts = [f"{name}={value:.0f}ms" for name, value in self._marks]
        parts.append(f"total={self.total_ms:.0f}ms")
        prefix = f"{self._label}: " if self._label else ""
        return prefix + " ".join(parts)


class EventBus:
    """Простой потокобезопасный pub/sub для событий конвейера → UI."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[str, dict], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[str, dict], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, event: str, **payload: object) -> None:
        with self._lock:
            subscribers: Sequence[Callable[[str, dict], None]] = tuple(
                self._subscribers
            )
        for callback in subscribers:
            try:
                callback(event, dict(payload))
            except Exception:  # pragma: no cover - подписчик не должен ломать шину
                get_logger("event_bus").exception(
                    "Ошибка обработчика события %s", event
                )


BUS = EventBus()


def log_stages(
    logger: logging.Logger, stopwatch: Stopwatch, prefix: str = "Тайминги"
) -> None:
    """Пишет тайминги этапов в лог одной строкой."""
    logger.info("%s: %s", prefix, stopwatch.summary())


def iter_levels() -> Iterable[str]:
    """Уровни для фильтра в UI (в порядке возрастания важности)."""
    return ("DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")
