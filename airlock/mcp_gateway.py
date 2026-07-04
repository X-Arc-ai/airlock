"""Airlock MCP gateway (tier-2) — screen MCP tool RESULTS before they enter agent context.

Two jobs:

* ``screen_tool_result(text, tool_name) -> (safe_text, Verdict)`` — run a tool
  result through the Airlock screener. Quarantined results are replaced with a
  withheld-notice; every screen is recorded to the TrustLedger and pushed to
  the live UI feed.
* ``install(agent) -> str`` — per-agent setup for claude / codex / opencode:
  wrap any stdio MCP server command with ``python -m airlock.mcp_gateway -- <cmd...>``.

The module is itself a simplified stdio MCP proxy (newline-delimited JSON-RPC):

    python -m airlock.mcp_gateway -- uvx mcp-server-fetch

Client -> server traffic passes through untouched (we only note which request
ids are ``tools/call`` and their tool names). Server -> client responses to
those ids get their text content screened; quarantined content never reaches
the agent.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Optional

import httpx

from . import config
from .screener import Verdict, screen

WITHHELD_NOTICE = (
    "[AIRLOCK] tool result withheld (quarantined).\n"
    "tool: {tool}\n"
    "threat_family: {family}\n"
    "reason: {reason}\n"
    "confidence: {confidence:.2f}\n"
    "The original output was intercepted before it reached the agent. "
    "Review it in the Airlock quarantine (run `airlock ui`) before trusting this source."
)

# how much of a tool result we hand to the screener (matches proxy behaviour)
SCREEN_MAX_CHARS = 8000

_ledger = None
_ledger_lock = threading.Lock()


def _get_ledger():
    """Lazy module-level TrustLedger (created on first screen, never at import)."""
    global _ledger
    with _ledger_lock:
        if _ledger is None:
            from .ledger import TrustLedger
            _ledger = TrustLedger()
        return _ledger


def post_event(kind: str, source: str, *, verdict: Verdict | dict | None = None,
               detail: str = "", preview: str = "", url: str = "",
               wait: bool = False) -> None:
    """Fire-and-forget push to the UI /ingest feed. Never raises.

    ``wait=True`` posts synchronously (short-lived CLI processes would
    otherwise exit before a daemon thread gets the event out).
    """
    v = verdict.to_dict() if hasattr(verdict, "to_dict") else verdict
    from .ledger import utc_now
    event = {"type": kind, "ts": utc_now(), "source": source, "url": url,
             "verdict": v, "detail": detail, "preview": (preview or "")[:280]}

    def _send():
        try:
            httpx.post(f"http://127.0.0.1:{config.UI_PORT}/ingest",
                       json=event, timeout=2)
        except Exception:
            pass  # UI down must never break screening

    if wait:
        _send()
    else:
        threading.Thread(target=_send, daemon=True).start()


def screen_tool_result(text: str, tool_name: str = "unknown") -> tuple[str, Verdict]:
    """Screen a tool RESULT before it enters agent context.

    Returns ``(safe_text, verdict)``: the original text when allowed, a
    withheld-notice when quarantined. Records to the ledger and pushes a live
    UI event either way. Fails CLOSED (screener already does; a crash here is
    also treated as quarantine).
    """
    source = f"mcp:{tool_name}"
    try:
        verdict = screen(text[:SCREEN_MAX_CHARS], source=source)
        try:  # attack-family cosine boost (config.FAMILY_THRESHOLD); fail-soft
            from .families import apply_boost
            verdict = apply_boost(verdict, text[:SCREEN_MAX_CHARS])
        except Exception:
            pass
    except Exception as e:  # screener is fail-closed; belt + braces
        verdict = Verdict("quarantine", "screener-error", None,
                          f"screener crashed: {e}; failing closed", 0.0,
                          source=source, model=config.MODEL)
    try:
        _get_ledger().record(verdict, text)
    except Exception:
        pass  # ledger trouble must not take down the gateway

    if verdict.quarantined():
        post_event("quarantine", source, verdict=verdict, preview=text,
                   detail=f"tool result withheld ({verdict.threat_family})")
        safe = WITHHELD_NOTICE.format(
            tool=tool_name, family=verdict.threat_family,
            reason=verdict.reason, confidence=verdict.confidence)
        return safe, verdict

    post_event("tool_screened", source, verdict=verdict,
               detail="tool result screened: allow")
    return text, verdict


# ------------------------------------------------------------------- install

_WRAP = '{py} -m airlock.mcp_gateway --'

_INSTALL = {
    "claude": """\
# Airlock tier-2 for Claude Code — wrap each stdio MCP server with the gateway.
#
# One-liner (example: a fetch server):
#   claude mcp add fetch -- {py} -m airlock.mcp_gateway -- uvx mcp-server-fetch
#
# Or edit .mcp.json (project) / ~/.claude.json (user) — put the gateway in
# front of the real server command:
{{
  "mcpServers": {{
    "fetch": {{
      "command": "{py}",
      "args": ["-m", "airlock.mcp_gateway", "--", "uvx", "mcp-server-fetch"]
    }}
  }}
}}
# Every tools/call result is now screened by Gemma before Claude reads it;
# quarantined results are withheld and appear in the Airlock feed (`airlock ui`).""",
    "codex": """\
# Airlock tier-2 for Codex — wrap each stdio MCP server with the gateway.
#
# Edit ~/.codex/config.toml (example: a fetch server):
[mcp_servers.fetch]
command = "{py}"
args = ["-m", "airlock.mcp_gateway", "--", "uvx", "mcp-server-fetch"]

# Every tools/call result is now screened by Gemma before Codex reads it;
# quarantined results are withheld and appear in the Airlock feed (`airlock ui`).""",
    "opencode": """\
# Airlock tier-2 for opencode — wrap each stdio MCP server with the gateway.
#
# Edit opencode.json (example: a fetch server):
{{
  "mcp": {{
    "fetch": {{
      "type": "local",
      "command": ["{py}", "-m", "airlock.mcp_gateway", "--", "uvx", "mcp-server-fetch"],
      "enabled": true
    }}
  }}
}}
# Every tools/call result is now screened by Gemma before opencode reads it;
# quarantined results are withheld and appear in the Airlock feed (`airlock ui`).""",
}


def install(agent: str) -> str:
    """Return the MCP-gateway setup for ``agent`` (claude | codex | opencode)."""
    key = (agent or "").strip().lower()
    if key not in _INSTALL:
        raise ValueError(
            f"unknown agent {agent!r} — expected one of: {', '.join(sorted(_INSTALL))}")
    return _INSTALL[key].format(py=sys.executable)


# --------------------------------------------------------------- stdio proxy

def _screen_response(msg: dict, tool: str) -> dict:
    """Screen the text content of a tools/call response; mutate if quarantined."""
    result = msg.get("result")
    if not isinstance(result, dict):
        return msg
    content = result.get("content")
    if not isinstance(content, list):
        return msg
    texts = [item.get("text", "") for item in content
             if isinstance(item, dict) and item.get("type") == "text"]
    joined = "\n".join(t for t in texts if t)
    if not joined:
        return msg
    safe_text, verdict = screen_tool_result(joined, tool_name=tool)
    if verdict.quarantined():
        result["content"] = [{"type": "text", "text": safe_text}]
    return msg


def serve(cmd: list[str]) -> int:
    """Run ``cmd`` as a stdio MCP server; screen its tool results in-line.

    Newline-delimited JSON-RPC passthrough: client->server untouched (tool
    names of pending tools/call requests are noted); server->client responses
    to those requests get their text content screened before forwarding.
    Anything unparseable passes through verbatim.
    """
    if not cmd:
        raise ValueError("mcp_gateway.serve: empty server command")
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, encoding="utf-8", bufsize=1)
    pending: dict = {}  # request id -> tool name
    lock = threading.Lock()

    def client_to_server() -> None:
        try:
            for line in sys.stdin:
                s = line.strip()
                if s:
                    try:
                        req = json.loads(s)
                        if (isinstance(req, dict) and req.get("method") == "tools/call"
                                and isinstance(req.get("id"), (str, int))):
                            name = (req.get("params") or {}).get("name") or "unknown"
                            with lock:
                                pending[req["id"]] = str(name)
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass
                try:
                    child.stdin.write(line)
                    child.stdin.flush()
                except (BrokenPipeError, ValueError, OSError):
                    break
        finally:
            try:
                child.stdin.close()
            except Exception:
                pass

    threading.Thread(target=client_to_server, daemon=True).start()

    for line in child.stdout:
        out = line
        s = line.strip()
        if s:
            try:
                msg = json.loads(s)
                tool: Optional[str] = None
                if (isinstance(msg, dict) and isinstance(msg.get("id"), (str, int))
                        and ("result" in msg or "error" in msg)):
                    with lock:
                        tool = pending.pop(msg["id"], None)
                if tool is not None and "result" in msg:
                    msg = _screen_response(msg, tool)
                    out = json.dumps(msg, ensure_ascii=False) + "\n"
            except (json.JSONDecodeError, TypeError):
                pass  # not JSON — forward verbatim
        sys.stdout.write(out)
        sys.stdout.flush()
    return child.wait()


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m airlock.mcp_gateway",
        description="Airlock stdio MCP gateway — screens tool results before "
                    "they reach the agent.")
    parser.add_argument("--install", metavar="AGENT",
                        help="print setup for claude | codex | opencode and exit")
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="the real MCP server command (prefix with --)")
    args = parser.parse_args(argv)
    if args.install:
        try:
            print(install(args.install))
            return 0
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("no MCP server command given, e.g.: "
                     "python -m airlock.mcp_gateway -- uvx mcp-server-fetch")
    return serve(cmd)


if __name__ == "__main__":
    sys.exit(main())
