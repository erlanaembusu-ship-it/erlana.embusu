"""Точка входа FastBid GosZakup.

Режимы запуска
--------------
* ``python main.py`` — обычная работа (реальный портал + NCALayer).
* ``python main.py --mock`` — GUI поверх локальных заглушек
  (``utils/mock_server.py``): приём заявок открывается через
  ``--open-after`` секунд.
* ``python main.py --selftest`` — headless-проверка полного цикла против
  заглушек с отчётом по таймингам; код выхода 0/1 для CI.
* ``python main.py --hwid`` — показать HWID машины.
* ``python main.py --gen-keys`` — сгенерировать пару ключей вендора (Ed25519)
  для выпуска лицензий.
* ``python main.py --issue-license ...`` — подписать лицензию.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # Windows-консоль должна переживать любые символы в логах
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from config.settings import APP_NAME, APP_VERSION, AppSettings, load_settings
from core.license_guard import generate_keypair
from utils.logger import BUS, get_logger, setup_logging
from utils.mock_server import MockLot, MockServers

# ui.app тянет tkinter: импортируем лениво в run_gui(), чтобы утилиты
# --hwid/--gen-keys/--issue-license/--selftest работали и без Tk.


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fastbid",
        description=f"{APP_NAME} {APP_VERSION} — скоростная подача заявок",
    )
    parser.add_argument(
        "--mock", action="store_true", help="работать против локальных заглушек"
    )
    parser.add_argument(
        "--open-after",
        type=float,
        default=20.0,
        help="через сколько секунд мок откроет приём заявок",
    )
    parser.add_argument("--http-port", type=int, default=8643)
    parser.add_argument("--ws-port", type=int, default=13580)
    parser.add_argument(
        "--selftest", action="store_true", help="headless e2e-проверка полного цикла"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="подробный лог selftest"
    )
    parser.add_argument(
        "--nca-password",
        default="NCAPassword123",
        help="пароль тестового контейнера ЭЦП (mock)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="проверить план без подписи, загрузки и подачи",
    )
    parser.add_argument("--hwid", action="store_true", help="показать HWID и выйти")
    parser.add_argument(
        "--gen-keys", action="store_true", help="сгенерировать пару ключей вендора"
    )
    parser.add_argument(
        "--issue-license", action="store_true", help="подписать файл лицензии"
    )
    parser.add_argument(
        "--private-key",
        default="",
        help="приватный ключ вендора (PEM) для --issue-license",
    )
    parser.add_argument("--bin", default="", help="БИН/ИИН лицензиата")
    parser.add_argument("--licensee", default="", help="наименование лицензиата")
    parser.add_argument("--days", type=int, default=365, help="срок лицензии в днях")
    parser.add_argument("--to", default="license.json", help="куда записать лицензию")
    parser.add_argument("--target-hwid", default="", help="HWID машины лицензиата")
    parser.add_argument(
        "--max-amount",
        type=float,
        default=0.0,
        help="тарифный лимит: максимальная сумма лота, ₸ (0 = без ограничения)",
    )
    return parser


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
class ServerThread(threading.Thread):
    """Локальные заглушки в отдельном daemon-потоке (режим --mock)."""

    def __init__(
        self, host: str, http_port: int, ws_port: int, open_after: float
    ) -> None:
        super().__init__(name="fastbid-mock", daemon=True)
        self.servers = MockServers(
            host,
            http_port,
            ws_port,
            lot=MockLot(open_after_s=open_after),
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self.error: Exception | None = None

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.servers.start())
            self._ready.set()
            self._loop.run_forever()
        except Exception as exc:
            self.error = exc
            self._ready.set()
        finally:
            self._loop.run_until_complete(self.servers.stop())
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            self._loop.close()

    def wait_until_ready(self, timeout: float = 10.0) -> bool:
        return self._ready.wait(timeout=timeout) and self.error is None

    def stop(self) -> None:
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self.join(timeout=5)


def run_gui(settings: AppSettings, args: Any) -> int:
    log = get_logger("main")
    settings.ensure_dirs()
    _store, sink = setup_logging(
        settings.log_path,
        settings.log.level,
        console=settings.log.console,
        rotate_mb=settings.log.rotate_mb,
        backups=settings.log.backups,
        buffer_capacity=settings.log.ui_buffer,
    )
    for key, value in settings.describe().items():
        log.info("Конфиг: %s = %s", key, value)

    server_thread: ServerThread | None = None
    if args.mock:
        server_thread = ServerThread(
            "127.0.0.1", args.http_port, args.ws_port, args.open_after
        )
        server_thread.start()
        if not server_thread.wait_until_ready():
            log.error("Не удалось запустить заглушки")
            return 1
        settings = server_thread.servers.settings_for(settings)
        log.warning("MOCK-РЕЖИМ: %s", server_thread.servers.summary())

    # Ленивый импорт: ui.app тянет tkinter (см. комментарий у импортов).
    from ui.app import AsyncBridge, Backend, FastBidApp
    from ui.components import UiEventQueue

    bridge = AsyncBridge()
    bridge.start()
    events = UiEventQueue()
    BUS.subscribe(lambda event, payload: events.put(event, **payload))
    backend = Backend(settings, events)
    backend.bind_loop(bridge.loop)

    bridge.submit(backend.start_session())
    bridge.submit(backend.probe_nca())
    backend.refresh_license()
    events.put("license")

    try:
        app = FastBidApp(settings, bridge, backend, events, sink)
        app.mainloop()
    finally:
        # Порядок важен: сначала гасим сессию/NCALayer в фоновом loop, затем
        # сам loop, затем заглушки. Ошибка на любом шаге не должна помешать
        # остальным (и не должна скрыть исходное исключение из mainloop).
        if bridge._loop is not None:
            try:
                bridge.submit(backend.stop_session()).result(timeout=8)
            except Exception as exc:
                log.debug("Ошибка завершения сессии: %s", exc)
            finally:
                bridge.stop()
        if server_thread is not None:
            try:
                server_thread.stop()
            except Exception as exc:
                log.debug("Ошибка остановки заглушек: %s", exc)
    log.info("Приложение завершено")
    return 0


# --------------------------------------------------------------------------- #
# Headless selftest
# --------------------------------------------------------------------------- #
def run_selftest(settings: AppSettings, args: Any) -> int:
    """Полный цикл против заглушек: гоняет authenticate → cycle → report."""
    import tempfile as _tempfile

    from core.bid_pipeline import BidPipeline, BidRequest
    from core.lot_watcher import LotWatcher
    from core.ncalayer_client import NCALayerClient, SecretPassword
    from core.session_manager import SessionManager

    verbose = bool(args.verbose)
    setup_logging(None, "DEBUG" if verbose else "INFO", console=True)
    log = get_logger("selftest")

    async def scenario() -> tuple[bool, dict[str, Any]]:
        servers = MockServers(
            "127.0.0.1",
            args.http_port,
            args.ws_port,
            lot=MockLot(open_after_s=args.open_after),
            nca_password=args.nca_password,
        )
        await servers.start()
        try:
            mock_settings = servers.settings_for(settings)
            if args.dry_run:
                mock_settings = mock_settings.with_(dry_run=True)
            nca = NCALayerClient(mock_settings.ncalayer)
            session = SessionManager(mock_settings, nca)
            session.set_password(SecretPassword(args.nca_password))
            await session.start()
            key_info = await session.authenticate()
            log.info("Аутентификация: БИН %s", key_info.bin_iin)

            watcher = LotWatcher(session, mock_settings)
            pipeline = BidPipeline(session, nca, watcher, mock_settings)

            with _tempfile.TemporaryDirectory(prefix="fastbid-") as tmp:
                docs_dir = Path(tmp)
                (docs_dir / "tz.pdf").write_bytes(b"%PDF-1.4 fake tz")
                (docs_dir / "cert.pdf").write_bytes(b"%PDF-1.4 fake cert")
                request = BidRequest(
                    lot_id=servers.portal.lot.id,
                    blueprint_id="food_supply",
                    documents=[docs_dir / "cert.pdf"],
                    lot_documents=[docs_dir / "tz.pdf"],
                    fields={
                        "delivery_days": 10,
                        "shelf_life": 6,
                        "manufacturer_country": "KZ",
                        "vet_certificate": True,
                        "agree_terms": True,
                        "vat_included": True,
                    },
                )
                result = await pipeline.run_cycle(request)
            report = {
                "ok": result.ok,
                "bid_id": result.bid_id,
                "stages": result.stages,
                "total_ms": result.total_ms,
                "t0_delta_ms": result.t0_delta_ms,
                "errors": result.errors,
                "nca": dict(nca.stats),
                "portal": dict(servers.portal.counters),
            }
            await session.close()
            await nca.close()
            return result.ok, report
        finally:
            await servers.stop()

    ok, report = asyncio.run(scenario())
    bar = "=" * 64
    print(bar)
    print("SELFTEST:", "PASS" if ok else "FAIL")
    for key, value in report.items():
        print(f"  {key}: {value}")
    print(bar)
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# Утилиты лицензий и dispatch
# --------------------------------------------------------------------------- #
def run_utilities(settings: AppSettings, args: Any) -> int | None:
    if args.hwid:
        from core.license_guard import format_hwid, get_hwid

        print(f"HWID: {format_hwid(get_hwid())}")
        return 0
    if args.gen_keys:
        private_pem, public_pem = generate_keypair()
        print("=== PRIVATE (хранить у вендора, НЕ вкладывать в поставку) ===")
        print(private_pem)
        print("=== PUBLIC (вшить в core/vendor_key.py и пересобрать) ===")
        print(public_pem)
        return 0
    if args.issue_license:
        if not args.private_key or not args.bin or not args.target_hwid:
            print(
                "Нужно: --private-key <PEM-файл> --bin <БИН> "
                "--target-hwid <HWID> [--licensee ... --days N --to файл]"
            )
            return 2
        from core.license_guard import LicenseGuard

        normalized_hwid = LicenseGuard.normalize_hwid(args.target_hwid)
        if len(normalized_hwid) != 32 or any(
            ch not in "0123456789ABCDEF" for ch in normalized_hwid
        ):
            print(
                "HWID должен быть 32 hex-символа. Возьмите его из вывода "
                "--hwid или кнопки «Копировать HWID» (формат с дефисами "
                "допустим — нормализуем автоматически)."
            )
            return 2
        private_pem = Path(args.private_key).read_text(encoding="utf-8")
        document = LicenseGuard.issue(
            args.licensee or "Лицензиат",
            args.bin,
            normalized_hwid,
            args.days,
            private_pem,
            max_lot_amount=float(args.max_amount or 0.0),
        )
        Path(args.to).write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Лицензия записана: {args.to}")
        return 0
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings()
    if args.dry_run:
        settings = settings.with_(dry_run=True)

    utility = run_utilities(settings, args)
    if utility is not None:
        return utility
    if args.selftest:
        return run_selftest(settings, args)
    return run_gui(settings, args)


if __name__ == "__main__":
    raise SystemExit(main())
