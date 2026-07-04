"""Airlock UI server — the live event surface for the on-device agent firewall.

Endpoints
    GET  /                the event-feed frontend (static/index.html)
    GET  /events          SSE stream; every ingested event is broadcast to all clients
    POST /ingest          proxy / screener push an event dict here -> fan-out to SSE
    GET  /api/quarantine  quarantine_log entries from the TrustLedger (newest first)
    GET  /api/sources     known sources with current trust state
    GET  /api/asof?ts=    bi-temporal trust replay at an ISO-8601 instant
    GET  /api/recent      recent trust events (feed backfill on page load)
    GET  /api/policy      active egress policy (allowlist hosts / deny paths / filters)

Run:  python -m airlock.ui.server
  or: uvicorn airlock.ui.server:app --port $AIRLOCK_UI_PORT
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from .. import config, policy
from ..ledger import TrustLedger, utc_now

STATIC_DIR = Path(__file__).resolve().parent / "static"


class EventHub:
    """Fan-out of ingested events to every connected SSE client.

    One asyncio.Queue per subscriber; publishing never blocks — a client that
    stops draining (full queue) is dropped and will simply reconnect (SSE
    auto-retry) with fresh state.
    """

    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()
        self.delivered = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, event: dict) -> int:
        sent = 0
        for q in list(self._subs):
            try:
                q.put_nowait(event)
                sent += 1
            except asyncio.QueueFull:
                self._subs.discard(q)
        self.delivered += sent
        return sent

    @property
    def subscribers(self) -> int:
        return len(self._subs)


def create_app(db_path: Optional[str] = None) -> FastAPI:
    """Build the Airlock UI app. ``db_path`` overrides config.DB_PATH (tests)."""
    app = FastAPI(title="Airlock UI", version="0.1.0", docs_url=None, redoc_url=None)
    ledger = TrustLedger(db_path or config.DB_PATH)
    hub = EventHub()
    app.state.ledger = ledger
    app.state.hub = hub

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------- frontend

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    # ------------------------------------------------------------ event bus

    @app.get("/events")
    async def events(request: Request) -> EventSourceResponse:
        q = hub.subscribe()

        async def stream():
            try:
                yield {"data": json.dumps(
                    {"kind": "hello", "ts": utc_now(), "subscribers": hub.subscribers})}
                while True:
                    event = await q.get()
                    yield {"data": json.dumps(event, ensure_ascii=False, default=str)}
            finally:
                hub.unsubscribe(q)

        return EventSourceResponse(stream(), ping=15)

    @app.post("/ingest")
    async def ingest(request: Request):
        try:
            event = await request.json()
        except Exception:
            event = None
        if not isinstance(event, dict):
            return JSONResponse({"ok": False, "error": "body must be a JSON object"},
                                status_code=400)
        event.setdefault("ts", utc_now())
        event.setdefault("kind", "verdict" if "decision" in event else "event")
        sent = hub.publish(event)
        return {"ok": True, "ts": event["ts"], "delivered_to": sent}

    # -------------------------------------------------------------- ledger

    @app.get("/api/quarantine")
    def api_quarantine() -> list[dict]:
        return ledger.quarantines()

    @app.get("/api/sources")
    def api_sources() -> list[dict]:
        return ledger.sources()

    @app.get("/api/asof")
    def api_asof(ts: Optional[str] = None):
        try:
            return ledger.as_of(ts or utc_now())
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": f"bad ts {ts!r}: {exc}"}, status_code=400)

    @app.get("/api/recent")
    def api_recent(limit: int = 50) -> list[dict]:
        return ledger.recent(limit=max(1, min(int(limit), 500)))

    # -------------------------------------------------------------- policy

    @app.get("/api/policy")
    def api_policy() -> dict:
        return {
            "allowlist_hosts": sorted(policy.ALLOWLIST_HOSTS),
            "deny_paths": sorted(policy.DENY_PATHS),
            "secret_patterns": [kind for kind, _rx, _grp in policy.SECRET_PATTERNS],
        }

    return app


app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=config.UI_PORT, log_level="info")


if __name__ == "__main__":
    main()
