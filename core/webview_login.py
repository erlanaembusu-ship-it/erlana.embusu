"""Захват сессии портала через встроенный браузер (pywebview/WebView2).

Приложение открывает окно входа на портал — пользователь входит как обычно
(SSO ЭЦП через NCALayer). Приложение следит за cookies окна: как только
появляется сессионная cookie v3bl — окно закрывается, Cookie-строка
передаётся в приложение. Никаких DevTools и ручного копирования.
"""

from __future__ import annotations

import threading
import time

SESSION_NAMES = {"SESSION", "SESSIONID", "JSESSIONID", "PHPSESSID"}


def capture_portal_session(login_url: str, timeout_s: float = 600.0) -> str:
    """Открывает окно входа на портал; возвращает Cookie-строку сессии v3bl.

    Блокирует до входа пользователя или закрытия окна ("" — отмена).
    NCALayer спросит ключ/пароль ЭЦП — штатный вход на портал.
    """
    import webview

    result = {"cookie": "", "closed": False}
    window = webview.create_window(
        "Вход на портал — FastBid GosZakup", login_url, width=1150, height=850
    )

    def poll() -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                if window.events.closed.is_set():
                    result["closed"] = True
                    return
                cookies = window.get_cookies()
            except Exception:
                cookies = []
            pairs: list[str] = []
            session_pair = ""
            for c in cookies:
                name = getattr(c, "name", "")
                domain = str(getattr(c, "domain", ""))
                if "goszakup" not in domain:
                    continue
                pair = f"{name}={getattr(c, 'value', '')}"
                pairs.append(pair)
                if name.upper() in SESSION_NAMES:
                    session_pair = pair
            if session_pair:
                result["cookie"] = "; ".join(sorted(set(pairs)))
                try:
                    window.destroy()
                except Exception:
                    pass
                return
            time.sleep(0.7)

    thread = threading.Thread(target=poll, daemon=True)
    thread.start()
    webview.start()
    thread.join(timeout=5)
    return result["cookie"]
