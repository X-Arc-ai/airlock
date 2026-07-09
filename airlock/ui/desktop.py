"""Airlock desktop shell — a native window + always-on menubar shield.

Airlock's live surface is an *event feed*, not a dashboard: quarantine flashes,
verdict cards with the malicious span highlighted, and the trust-ledger replay
served by ``airlock.ui.server``. This module wraps that feed in a first-class
desktop experience:

* **macOS** — a ``rumps`` menubar item shows the shield and a *live block
  count* (🛡 3) that ticks up every time Airlock quarantines something, plus a
  native ``pywebview`` window onto the feed. The Mac-only libraries are imported
  **only** on ``darwin`` so this file imports and parses cleanly on Linux / the
  Hetzner box.
* **everything else** (Linux server, Docker) — there is no menubar, so we start
  the feed server and print the ``http://127.0.0.1:<port>`` URL to open in a
  browser. This is the path used on the demo box.

Run it directly::

    python -m airlock.ui.desktop      # or: python airlock/ui/desktop.py

On macOS the CLI (``python -m airlock ui``) hands off to this shell
automatically; elsewhere the CLI serves the feed itself.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
import webbrowser

try:  # repo root (or installed package) already on sys.path
    from airlock import config
except ImportError:  # executed as a plain script: `python airlock/ui/desktop.py`
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
    from airlock import config

UI_HOST = "127.0.0.1"
UI_URL = f"http://{UI_HOST}:{config.UI_PORT}"
WINDOW_TITLE = "Airlock — agent firewall"
POLL_SECONDS = 2.0


# --------------------------------------------------------------------- server

def serve_in_background() -> threading.Thread:
    """Start the Airlock feed server (uvicorn) in a daemon thread.

    Returns immediately; the caller owns the main thread (needed by both
    ``pywebview`` and ``rumps``, which each require the macOS main run loop).
    """
    def _serve() -> None:
        import uvicorn
        from airlock.ui.server import app as ui_app  # local import: keep module import light
        uvicorn.run(ui_app, host=UI_HOST, port=config.UI_PORT, log_level="warning")

    t = threading.Thread(target=_serve, name="airlock-ui", daemon=True)
    t.start()
    return t


def wait_for_server(timeout: float = 15.0) -> bool:
    """Block until the feed server accepts connections (or timeout)."""
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((UI_HOST, config.UI_PORT), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def block_count() -> int:
    """Number of quarantines recorded so far (drives the menubar shield count).

    Best-effort: any error (server not up yet, network blip) reads as 0 rather
    than crashing the menubar.
    """
    try:
        import httpx
        r = httpx.get(f"{UI_URL}/api/quarantine", timeout=1.5)
        r.raise_for_status()
        data = r.json()
        return len(data) if isinstance(data, list) else 0
    except Exception:
        return 0


# ------------------------------------------------------------- native window

def open_window(url: str = UI_URL) -> None:
    """Open a native pywebview window onto the feed (blocks until closed).

    On macOS this is launched in a *child process* (see ``main``) so its Cocoa
    run loop does not fight the menubar's; run standalone it just works.
    """
    import webview  # imported lazily — only present where we actually open a window
    webview.create_window(WINDOW_TITLE, url, width=1180, height=820,
                          min_size=(720, 560))
    webview.start()


def _spawn_window(url: str = UI_URL) -> "subprocess.Popen[bytes]":
    """Launch open_window() in a separate process (keeps rumps on the main loop)."""
    return subprocess.Popen([sys.executable, __file__, "--window", url])


# ---------------------------------------------------------------- macOS shell

def run_macos() -> None:
    """Menubar shield with a live block count + a native feed window (macOS)."""
    import rumps

    class AirlockMenubar(rumps.App):
        def __init__(self) -> None:
            super().__init__("🛡", quit_button=None)
            self._blocks = -1
            self._window: "subprocess.Popen[bytes] | None" = None
            self.menu = [
                rumps.MenuItem("Open Airlock window", callback=self.open_window),
                rumps.MenuItem("Open feed in browser", callback=self.open_browser),
                None,  # separator
                rumps.MenuItem("Blocks: 0"),
                None,
                rumps.MenuItem("Quit Airlock", callback=self.quit),
            ]
            self._refresh(None)
            # auto-open the native window once the server is ready
            self._window = _spawn_window(UI_URL)

        @rumps.timer(POLL_SECONDS)
        def _refresh(self, _sender) -> None:
            n = block_count()
            if n == self._blocks:
                return
            self._blocks = n
            # 🛡 alone when clean; 🛡 N (with an alert tint via the ⚠️ prefix)
            self.title = "🛡" if n == 0 else f"🛡 {n}"
            self.menu["Blocks: 0"].title = f"Blocks: {n}"

        def open_window(self, _sender) -> None:
            if self._window is None or self._window.poll() is not None:
                self._window = _spawn_window(UI_URL)

        def open_browser(self, _sender) -> None:
            webbrowser.open(UI_URL)

        def quit(self, _sender) -> None:
            if self._window is not None and self._window.poll() is None:
                self._window.terminate()
            rumps.quit_application()

    AirlockMenubar().run()


# ---------------------------------------------------------------- other OSes

def run_headless() -> None:
    """No menubar here — serve the feed and point the operator at the URL."""
    print(f"[airlock] event feed live at {UI_URL}")
    print("[airlock] open that URL in a browser to watch quarantines stream in.")
    print("[airlock] (native menubar shield + window are macOS-only; "
          "on Linux/Docker the feed is the surface.)")
    try:
        webbrowser.open(UI_URL)
    except Exception:
        pass
    # Block forever so the daemon server thread keeps running.
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[airlock] shutting down.")


# ---------------------------------------------------------------------- entry

def main() -> None:
    # Child-process window path (macOS spawns this to keep rumps on the main loop).
    if len(sys.argv) >= 2 and sys.argv[1] == "--window":
        url = sys.argv[2] if len(sys.argv) >= 3 else UI_URL
        open_window(url)
        return

    serve_in_background()
    wait_for_server()

    if sys.platform == "darwin":
        try:
            run_macos()
            return
        except Exception as exc:  # missing rumps/pywebview, no GUI session, etc.
            print(f"[airlock] desktop shell unavailable ({exc}); "
                  "falling back to browser.")
    run_headless()


if __name__ == "__main__":
    main()
