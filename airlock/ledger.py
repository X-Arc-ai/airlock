"""Bi-temporal TrustLedger for Airlock.

Every screening verdict, quarantine, and trust revocation is recorded as an
immutable event with explicit validity boundaries (trust_granted_at /
trust_revoked_at), so ``as_of(ts)`` can replay exactly which sources were
trusted at any moment in time.

Pure stdlib sqlite3. Safe for multi-threaded use (one connection + RLock,
WAL journal so cross-process readers like the UI never block the proxy).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional, Union

from . import config

PREVIEW_CHARS = 280

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    name        TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    trust       TEXT NOT NULL DEFAULT 'trusted'
);
CREATE TABLE IF NOT EXISTS trust_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source           TEXT NOT NULL,
    event            TEXT NOT NULL,            -- 'grant' | 'screen' | 'revoke'
    trust_granted_at TEXT,
    trust_revoked_at TEXT,
    reason           TEXT,
    verdict_json     TEXT
);
CREATE TABLE IF NOT EXISTS quarantine_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    source          TEXT NOT NULL,
    threat_family   TEXT,
    malicious_span  TEXT,
    reason          TEXT,
    confidence      REAL,
    content_preview TEXT
);
CREATE INDEX IF NOT EXISTS idx_trust_events_source ON trust_events(source);
CREATE INDEX IF NOT EXISTS idx_quarantine_log_ts   ON quarantine_log(ts);
"""


def utc_now() -> str:
    """ISO-8601 UTC with microseconds, e.g. 2026-07-04T12:34:56.789012+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _canon(ts: str) -> str:
    """Normalize any ISO-8601 timestamp to the ledger's canonical UTC form so
    lexicographic comparison in SQL is chronologically correct."""
    s = str(ts).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class TrustLedger:
    """Append-mostly trust ledger over sources / trust_events / quarantine_log."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(db_path or config.DB_PATH)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.executescript(_SCHEMA)
            self._db.commit()

    # ------------------------------------------------------------------ write

    def record(self, verdict: Union[Any, dict], content: str = "") -> int:
        """Log one screening. Returns the id of the 'screen' trust_event row.

        If the verdict is a quarantine, additionally writes a quarantine_log
        entry and revokes trust for the source (closing its open grant
        interval), all in one transaction.
        """
        if hasattr(verdict, "to_dict"):
            v = verdict.to_dict()
        elif isinstance(verdict, dict):
            v = dict(verdict)
        else:
            raise TypeError(f"record() wants a Verdict or dict, got {type(verdict)!r}")
        source = str(v.get("source") or "unknown")
        quarantined = str(v.get("decision", "")).lower() == "quarantine"
        now = utc_now()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT trust FROM sources WHERE name=?", (source,)).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO sources(name, first_seen, trust) VALUES (?,?,'trusted')",
                    (source, now))
                trust = "trusted"
                grant_reason = "first contact"
            else:
                trust = row["trust"]
                grant_reason = "re-observed"
            # Open a grant interval unless the source is already revoked
            # (revocation is sticky; there is no automatic re-grant).
            if trust != "revoked":
                open_grant = self._db.execute(
                    "SELECT id FROM trust_events WHERE source=? AND event='grant' "
                    "AND trust_revoked_at IS NULL", (source,)).fetchone()
                if open_grant is None:
                    self._db.execute(
                        "INSERT INTO trust_events(source, event, trust_granted_at, reason) "
                        "VALUES (?,'grant',?,?)", (source, now, grant_reason))
            cur = self._db.execute(
                "INSERT INTO trust_events(source, event, trust_granted_at, reason, verdict_json) "
                "VALUES (?,'screen',?,?,?)",
                (source, now, str(v.get("reason", "")),
                 json.dumps(v, ensure_ascii=False)))
            event_id = int(cur.lastrowid)
            if quarantined:
                self._db.execute(
                    "INSERT INTO quarantine_log"
                    "(ts, source, threat_family, malicious_span, reason, confidence, content_preview) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (now, source, v.get("threat_family"), v.get("malicious_span"),
                     v.get("reason"), float(v.get("confidence") or 0.0),
                     (content or "")[:PREVIEW_CHARS]))
                why = f"quarantined: {v.get('threat_family', 'unknown')} — {v.get('reason', '')}"
                self._revoke_in_txn(source, why[:500], now)
        return event_id

    def revoke(self, source: str, reason: str) -> None:
        """Explicitly revoke trust for a source (closes any open grant)."""
        now = utc_now()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT name FROM sources WHERE name=?", (source,)).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO sources(name, first_seen, trust) VALUES (?,?,'revoked')",
                    (source, now))
            self._revoke_in_txn(source, reason, now)

    def _revoke_in_txn(self, source: str, reason: str, now: str) -> None:
        """Must run inside an open transaction while holding the lock."""
        self._db.execute(
            "UPDATE trust_events SET trust_revoked_at=? "
            "WHERE source=? AND event='grant' AND trust_revoked_at IS NULL",
            (now, source))
        self._db.execute(
            "INSERT INTO trust_events(source, event, trust_revoked_at, reason) "
            "VALUES (?,'revoke',?,?)", (source, now, reason))
        self._db.execute("UPDATE sources SET trust='revoked' WHERE name=?", (source,))

    # ------------------------------------------------------------------- read

    def as_of(self, iso_ts: str) -> list[dict]:
        """Replay trust state at a moment in time.

        Returns one dict per source first seen at or before ``iso_ts``:
        {source, trust: 'trusted'|'revoked', since, first_seen, reason}.
        A revocation taking effect exactly at ``iso_ts`` counts as revoked.
        """
        ts = _canon(iso_ts)
        out: list[dict] = []
        with self._lock:
            srcs = self._db.execute(
                "SELECT name, first_seen FROM sources WHERE first_seen <= ? "
                "ORDER BY first_seen, name", (ts,)).fetchall()
            for s in srcs:
                grant = self._db.execute(
                    "SELECT trust_granted_at FROM trust_events "
                    "WHERE source=? AND event='grant' AND trust_granted_at <= ? "
                    "AND (trust_revoked_at IS NULL OR trust_revoked_at > ?) "
                    "ORDER BY trust_granted_at DESC LIMIT 1",
                    (s["name"], ts, ts)).fetchone()
                if grant is not None:
                    out.append({"source": s["name"], "trust": "trusted",
                                "since": grant["trust_granted_at"],
                                "first_seen": s["first_seen"], "reason": None})
                else:
                    rev = self._db.execute(
                        "SELECT trust_revoked_at, reason FROM trust_events "
                        "WHERE source=? AND event='revoke' AND trust_revoked_at <= ? "
                        "ORDER BY trust_revoked_at DESC, id DESC LIMIT 1",
                        (s["name"], ts)).fetchone()
                    out.append({"source": s["name"], "trust": "revoked",
                                "since": rev["trust_revoked_at"] if rev else s["first_seen"],
                                "first_seen": s["first_seen"],
                                "reason": rev["reason"] if rev else None})
        return out

    def quarantines(self) -> list[dict]:
        """All quarantine_log entries, newest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM quarantine_log ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def sources(self) -> list[dict]:
        """All known sources with current trust state."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM sources ORDER BY first_seen, name").fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 50) -> list[dict]:
        """Most recent trust events, newest first; verdict_json parsed to 'verdict'."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM trust_events ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            raw = d.pop("verdict_json", None)
            try:
                d["verdict"] = json.loads(raw) if raw else None
            except (TypeError, ValueError):
                d["verdict"] = None
            out.append(d)
        return out

    # ------------------------------------------------------------------ misc

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "TrustLedger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
