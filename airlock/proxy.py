"""Airlock mitmproxy addon — the network chokepoint.

Every HTTP(S) exchange of a guarded agent passes through here:

* ``response(flow)`` — fetched text bodies (text/html, text/plain,
  application/json, …) are screened by ``airlock.screener.screen`` BEFORE the
  agent ever reads them. Quarantined content is replaced with a safe notice,
  logged to the TrustLedger, and pushed to the UI event feed.
* ``request(flow)`` — outbound egress is checked against
  ``airlock.policy.host_allowed`` (un-allowlisted hosts are blocked with a 403
  before leaving the box) and request bodies pass through
  ``airlock.policy.redact_secrets`` so credentials never leave even to
  allowlisted hosts. Everything is recorded + broadcast.

Runnable directly::

    mitmdump -s airlock/proxy.py -p 8899

or imported and driven with stub flow objects for testing (the addon only
relies on duck-typed ``flow.request`` / ``flow.response`` attributes).
"""
from __future__ import annotations

import json
import logging
import threading

import httpx

try:  # normal package import
    from . import config, policy
    from . import families
    from .ledger import TrustLedger, utc_now
    from .screener import Verdict, screen
except ImportError:  # loaded as a plain script by `mitmdump -s proxy.py`
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from airlock import config, policy
    from airlock import families
    from airlock.ledger import TrustLedger, utc_now
    from airlock.screener import Verdict, screen


def screen_with_boost(content: str, source: str = "unknown", **kw) -> Verdict:
    """Default screening path: Gemma verdict + attack-family cosine boost
    (config.FAMILY_THRESHOLD). The boost is fail-soft and can only add caution."""
    v = screen(content, source=source, **kw)
    try:
        v = families.apply_boost(v, content)
    except Exception:
        pass
    return v

try:  # only needed to fabricate block responses inside real mitmproxy
    from mitmproxy import http as _mitm_http
except Exception:  # pragma: no cover - mitmproxy always present in the venv
    _mitm_http = None

log = logging.getLogger("airlock.proxy")

# Content types we screen. Anything else (images, binaries, streams) passes.
SCREEN_CONTENT_TYPES = {"text/html", "text/plain", "application/json"}
# Cap what we send to the screener; injections live in-band, 8k chars is
# plenty for the MVP and keeps Gemma latency bounded.
SCREEN_MAX_CHARS = 8000
# host:port pairs whose responses we never screen (our own plumbing —
# screening the model's or the UI's own traffic would recurse forever).
SKIP_SCREEN_HOSTS: set[str] = {
    f"127.0.0.1:{config.UI_PORT}",
    f"localhost:{config.UI_PORT}",
}
try:
    _mu = httpx.URL(config.MODEL_URL)
    SKIP_SCREEN_HOSTS.add(f"{_mu.host}:{_mu.port or 80}")
except Exception:
    pass

QUARANTINE_NOTICE = (
    "[AIRLOCK] Content quarantined before it reached the agent.\n"
    "source: {source}\n"
    "threat_family: {family}\n"
    "reason: {reason}\n"
    "confidence: {confidence:.2f}\n\n"
    "The original content has been withheld. Review it in the Airlock "
    "quarantine log.\n"
)
BLOCK_NOTICE = (
    "[AIRLOCK] Egress blocked: host '{host}' is not on the allowlist.\n"
    "The request never left this machine. If this host is legitimate, add it "
    "to airlock.policy.ALLOWLIST_HOSTS.\n"
)


# --------------------------------------------------------------------- helpers

def _get_text(msg) -> str:
    """Best-effort text body from a mitmproxy message or a stub."""
    if msg is None:
        return ""
    try:
        t = msg.get_text(strict=False)
        if t is not None:
            return t
    except Exception:
        pass
    t = getattr(msg, "text", None)
    if isinstance(t, str):
        return t
    raw = getattr(msg, "content", None)
    if isinstance(raw, (bytes, bytearray)):
        try:
            return raw.decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


def _set_text(msg, text: str) -> None:
    """Replace the body on a mitmproxy message or a stub."""
    try:
        msg.set_text(text)
        return
    except Exception:
        pass
    try:
        msg.text = text
        return
    except Exception:
        pass
    try:
        msg.content = text.encode("utf-8")
    except Exception:
        log.error("airlock: could not replace message body")


def _header(msg, name: str) -> str:
    headers = getattr(msg, "headers", None)
    if headers is None:
        return ""
    try:
        return headers.get(name) or headers.get(name.title()) or ""
    except Exception:
        return ""


def _set_header(msg, name: str, value: str) -> None:
    headers = getattr(msg, "headers", None)
    if headers is None:
        return
    try:
        headers[name] = value
    except Exception:
        pass


def _host(flow) -> str:
    req = flow.request
    return str(getattr(req, "pretty_host", None) or getattr(req, "host", "") or "")


def _host_port(flow) -> str:
    port = getattr(flow.request, "port", None)
    return f"{_host(flow)}:{port}" if port else _host(flow)


def _url(flow) -> str:
    req = flow.request
    u = getattr(req, "pretty_url", None)
    if u:
        return str(u)
    scheme = getattr(req, "scheme", "http")
    path = getattr(req, "path", "/")
    return f"{scheme}://{_host_port(flow)}{path}"


def _make_response(status: int, body: str, headers: dict):
    """A response object suitable for `flow.response = ...`."""
    if _mitm_http is not None:
        try:
            return _mitm_http.Response.make(status, body.encode("utf-8"), headers)
        except Exception:
            pass

    class _Resp:  # stub fallback (tests without mitmproxy)
        def __init__(self):
            self.status_code = status
            self.text = body
            self.headers = dict(headers)
    return _Resp()


def _screenable(flow) -> bool:
    resp = getattr(flow, "response", None)
    if resp is None:
        return False
    if _header(resp, "x-airlock"):        # our own notice — never re-screen
        return False
    if _host_port(flow) in SKIP_SCREEN_HOSTS:
        return False
    ct = _header(resp, "content-type").split(";")[0].strip().lower()
    if ct in SCREEN_CONTENT_TYPES or ct.startswith("text/") or ct.endswith("+json"):
        return bool(_get_text(resp).strip())
    return False


# ----------------------------------------------------------------------- addon

class Airlock:
    """mitmproxy addon: screen inbound content, police outbound egress."""

    def __init__(self, ledger: TrustLedger | None = None,
                 ui_url: str | None = None, screen_fn=None):
        self._ledger = ledger
        self.ui_url = ui_url or f"http://127.0.0.1:{config.UI_PORT}/ingest"
        self._screen = screen_fn or screen_with_boost

    # Lazy so `addons = [Airlock()]` at import time creates no DB.
    @property
    def ledger(self) -> TrustLedger:
        if self._ledger is None:
            self._ledger = TrustLedger()
        return self._ledger

    # ------------------------------------------------------------- ui events

    def _post_event(self, kind: str, source: str, *, verdict: Verdict | dict | None = None,
                    detail: str = "", preview: str = "", url: str = "") -> None:
        """Fire-and-forget push to the UI /ingest feed. Never raises."""
        v = verdict.to_dict() if hasattr(verdict, "to_dict") else verdict
        event = {"type": kind, "ts": utc_now(), "source": source, "url": url,
                 "verdict": v, "detail": detail, "preview": (preview or "")[:280]}

        def _send():
            try:
                httpx.post(self.ui_url, json=event, timeout=2)
            except Exception:
                pass  # UI down is never a reason to break the proxy

        threading.Thread(target=_send, daemon=True).start()

    def _record(self, verdict, content: str = "") -> None:
        try:
            self.ledger.record(verdict, content)
        except Exception as e:  # ledger trouble must not take down the proxy
            log.error("airlock: ledger.record failed: %s", e)

    # ------------------------------------------------------------------ hooks

    def request(self, flow) -> None:
        """Egress policy: allowlist enforcement + secret redaction."""
        host = _host(flow)
        url = _url(flow)

        if not policy.host_allowed(host):
            body = BLOCK_NOTICE.format(host=host)
            flow.response = _make_response(
                403, body, {"content-type": "text/plain", "x-airlock": "blocked"})
            verdict = {
                "decision": "quarantine", "threat_family": "egress-blocked",
                "malicious_span": url,
                "reason": f"outbound request to un-allowlisted host '{host}'",
                "confidence": 1.0, "source": host or "unknown", "model": "policy",
            }
            self._record(verdict, _get_text(flow.request))
            self._post_event("egress_blocked", host, verdict=verdict,
                             detail=f"blocked egress to {host}", url=url)
            log.warning("airlock: BLOCKED egress to %s (%s)", host, url)
            return

        body = _get_text(flow.request)
        findings: list[dict] = []
        if body:
            redacted, findings = policy.redact_secrets(body)
            if findings:
                _set_text(flow.request, redacted)
                kinds = ", ".join(sorted({f["kind"] for f in findings}))
                log.warning("airlock: redacted %d secret(s) [%s] in request to %s",
                            len(findings), kinds, host)

        verdict = {
            "decision": "allow", "threat_family": "none", "malicious_span": None,
            "reason": (f"egress allowed; redacted {len(findings)} secret(s)"
                       if findings else "egress allowed"),
            "confidence": 1.0, "source": host or "unknown", "model": "policy",
        }
        self._record(verdict, body)
        self._post_event("secrets_redacted" if findings else "request",
                         host, verdict=verdict, url=url,
                         detail=json.dumps(findings) if findings else "")

    def response(self, flow) -> None:
        """Screen fetched text bodies before the agent reads them."""
        if not _screenable(flow):
            return
        host = _host(flow)
        url = _url(flow)
        content = _get_text(flow.response)

        try:
            verdict = self._screen(content[:SCREEN_MAX_CHARS], source=host or "unknown")
        except Exception as e:  # screener is fail-closed; this is belt+braces
            log.error("airlock: screener crashed (%s); failing closed", e)
            verdict = Verdict("quarantine", "screener-error", None,
                              f"screener crashed: {e}; failing closed", 0.0,
                              source=host or "unknown", model=config.MODEL)

        self._record(verdict, content)

        if verdict.quarantined():
            notice = QUARANTINE_NOTICE.format(
                source=host, family=verdict.threat_family,
                reason=verdict.reason, confidence=verdict.confidence)
            _set_text(flow.response, notice)
            _set_header(flow.response, "x-airlock", "quarantined")
            _set_header(flow.response, "content-type", "text/plain; charset=utf-8")
            self._post_event("quarantine", host, verdict=verdict,
                             preview=content, url=url,
                             detail=f"quarantined {verdict.threat_family}")
            log.warning("airlock: QUARANTINED %s response from %s (%s)",
                        verdict.threat_family, host, url)
        else:
            _set_header(flow.response, "x-airlock", "screened")
            self._post_event("fetch_screened", host, verdict=verdict, url=url,
                             detail="screened: allow")
            log.info("airlock: allowed response from %s (%s)", host, url)

    def http_connect(self, flow) -> None:
        """Refuse CONNECT tunnels to un-allowlisted hosts (HTTPS egress)."""
        host = _host(flow)
        if policy.host_allowed(host):
            return
        try:
            flow.response = _make_response(
                403, BLOCK_NOTICE.format(host=host),
                {"content-type": "text/plain", "x-airlock": "blocked"})
        except Exception:
            pass
        try:
            flow.kill()
        except Exception:
            pass
        verdict = {
            "decision": "quarantine", "threat_family": "egress-blocked",
            "malicious_span": f"CONNECT {host}",
            "reason": f"HTTPS tunnel to un-allowlisted host '{host}'",
            "confidence": 1.0, "source": host or "unknown", "model": "policy",
        }
        self._record(verdict)
        self._post_event("egress_blocked", host, verdict=verdict,
                         detail=f"blocked CONNECT to {host}")
        log.warning("airlock: BLOCKED CONNECT to %s", host)


addons = [Airlock()]  # so `mitmdump -s airlock/proxy.py` just works
