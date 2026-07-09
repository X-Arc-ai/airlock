# Airlock module contracts (frozen — build against these)

Workdir `/root/airlock`, venv `.venv` (deps installed). Gemma via Ollama at 127.0.0.1:11434
(`gemma3:12b-it-qat`, `embeddinggemma`). Import shared bits from `airlock.config`, `airlock.screener`.

## Verdict (airlock/screener.py — DONE)
`Verdict(decision, threat_family, malicious_span, reason, confidence, source, model)`;
`.quarantined()`, `.to_dict()`. `screen(content, source="", *, model=None, url=None) -> Verdict`. Fails CLOSED.

## config (DONE)
`MODEL, MODEL_URL, EMBED_MODEL, DB_PATH, FAMILY_THRESHOLD, PROXY_PORT, UI_PORT`.

## airlock/ledger.py  → TrustLedger  (SQLite, bi-temporal)
Tables: `sources(name PK, first_seen, trust)`; `trust_events(id, source, event, trust_granted_at,
trust_revoked_at, reason, verdict_json)`; `quarantine_log(id, ts, source, threat_family,
malicious_span, reason, confidence, content_preview)`.
API: `TrustLedger(db_path=config.DB_PATH)`; `record(verdict, content) -> int` (logs screen; if
quarantined also writes quarantine_log + a trust revocation event); `revoke(source, reason)`;
`as_of(iso_ts) -> list[dict]` (trust state replay); `quarantines()`, `sources()`, `recent(limit=50)`.
Timestamps ISO-8601 UTC. Pure stdlib sqlite3.

## airlock/policy.py
`redact_secrets(text) -> (redacted_text, findings:list[dict])` (AWS keys, PEM private keys, .env
values, generic API-key shapes). `host_allowed(host) -> bool` (ALLOWLIST_HOSTS default: api.anthropic.com,
api.openai.com, github.com, localhost, 127.0.0.1; else False). `path_allowed(path) -> bool`
(DENY_PATHS: ~/.ssh, ~/.aws, .env, id_rsa). Sets are module-level + overridable.

## airlock/families.py → FamilyMatcher
Loads `corpus/payloads.jsonl` (fields: text, family, label). `match(content) -> (family, score)`
via cosine over embeddinggemma (`POST {MODEL_URL}/api/embed {"model":EMBED_MODEL,"input":[...]}`).
Used to boost confidence + catch obfuscated variants. Cache seed embeddings on init.

## airlock/proxy.py → mitmproxy addon class `Airlock`
`response(flow)`: screen fetched text bodies (content-type text/html|json|plain) BEFORE the agent
reads them; if quarantined, replace body with a safe notice + record to ledger + POST event to UI
`/ingest`. `request(flow)`: `host_allowed()` check (block un-allowlisted egress), `redact_secrets()`
the body, record. Ledger + event on every action. Runnable via `mitmdump -s proxy.py`.

## airlock/sandbox.py
`run(cmd:list[str], proxy_addr="127.0.0.1:{PROXY_PORT}") -> int`. Linux: netns + veth + nftables so
only egress route is the proxy; run cmd inside with HTTP(S)_PROXY set + CA trusted. Mac/other: docker
run with proxy env + restricted net + CA mount. `detect_platform()`. MVP: env-proxy path must work;
netns is the "deep" enforcement (guard with try/except + clear log).

## airlock/mcp_gateway.py  (tier-2, per-agent)
`screen_tool_result(text, tool_name) -> (safe_text, Verdict)` — screens a tool RESULT before it
enters agent context; quarantine → returns a withheld-notice. `install(agent) -> str` prints/writes
MCP-proxy config for claude/codex/opencode. Simplified stdio MCP proxy acceptable for MVP.

## airlock/cli.py  (typer app `app`)
`screen "<text>"` (print verdict json); `run <cmd...>` (tier-1 sandbox+proxy); `protect <agent>`
(tier-2); `ui` (launch UI); `bench` (call bench/run_eval). `--model` global option → sets AIRLOCK_MODEL.
Entry: `python -m airlock ...` (add airlock/__main__.py → cli.app()).

## airlock/ui/  (the 50%-weight demo surface — make it beautiful, dark, event-centric, NOT a dashboard)
`server.py` FastAPI: `GET /` static index; `GET /events` SSE stream; `POST /ingest` (proxy/screener
push events → broadcast); `GET /api/quarantine|/api/sources|/api/asof?ts=` (read TrustLedger).
`static/{index.html,app.js,style.css}`: live feed, verdict cards with the malicious span highlighted,
big red QUARANTINE flash, quarantine list, trust-ledger replay, policy view. `desktop.py`: pywebview
native window + rumps menubar (🛡 + block count) on mac; else open browser.

## bench/run_eval.py
Load deepset/prompt-injections (HF) + corpus/ held-out; sweep `--models gemma3:{1b,4b,12b,27b}-it-qat`;
compute TPR/FPR/precision/F1 + per-family; write `bench/RESULTS.md` (one table, TPR/FPR/precision/F1 per model size). One-command repro.

## corpus/payloads.jsonl
15+ lines {text, family, label:1} across families: direct-override, base64-obfuscated,
unicode-invisible, roleplay, data-exfil, tool-hijack, indirect-document. Held out from tuning.
