"""Egress policy for Airlock: secret redaction, host allowlist, path denial.

ALLOWLIST_HOSTS / DENY_PATHS / SECRET_PATTERNS are module-level and mutable
on purpose so the proxy or CLI can override them at runtime, e.g.::

    from airlock import policy
    policy.ALLOWLIST_HOSTS.add("internal.corp")
"""
from __future__ import annotations

import os
import re

# Hosts an Airlock-guarded process may talk to. Exact match or subdomain.
ALLOWLIST_HOSTS: set[str] = {
    "api.anthropic.com",
    "api.openai.com",
    "github.com",
    "localhost",
    "127.0.0.1",
}

# Paths a guarded process must never read/ship. '~' entries deny the whole
# subtree; bare names deny any path component that matches them.
DENY_PATHS: set[str] = {
    "~/.ssh",
    "~/.aws",
    ".env",
    "id_rsa",
}

# (kind, compiled regex, group index holding the secret — None = whole match).
# Order matters: big blocks first, keyed values before generic shapes.
SECRET_PATTERNS: list[tuple[str, re.Pattern, int | None]] = [
    ("pem-private-key",
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.DOTALL),
     None),
    ("aws-secret-key",
     re.compile(r"(?i)\baws_?(?:secret_?access_?key|secret_?key|secret)\b"
                r"(\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
     2),
    ("aws-access-key-id",
     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
     None),
    ("github-token",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
     None),
    ("slack-token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     None),
    ("google-api-key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     None),
    ("generic-sk-key",  # OpenAI / Anthropic / Stripe style sk-… tokens
     re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
     None),
    ("bearer-token",
     re.compile(r"(?i)\bbearer[ \t]+([A-Za-z0-9._+/=\-]{20,})"),
     1),
    ("env-secret",  # KEY=value lines where KEY smells like a credential
     re.compile(r"(?im)^([ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*"
                r"(?:KEY|TOKEN|SECRET|PASS(?:WORD|WD)?|PWD|CREDENTIALS?)[A-Z0-9_]*"
                r"[ \t]*=[ \t]*[\"']?)(?!\[REDACTED:)([^\s\"']+)"),
     2),
]


def redact_secrets(text: str) -> tuple[str, list[dict]]:
    """Mask secret material in ``text``.

    Returns ``(redacted_text, findings)`` where each finding is
    ``{"kind", "preview", "length"}`` — never the secret itself.
    """
    findings: list[dict] = []
    redacted = str(text)
    for kind, rx, grp in SECRET_PATTERNS:
        def _sub(m: re.Match, _kind: str = kind, _grp: int | None = grp) -> str:
            secret = m.group(_grp) if _grp else m.group(0)
            findings.append({
                "kind": _kind,
                "preview": (secret[:4] + "…") if len(secret) > 4 else "…",
                "length": len(secret),
            })
            token = f"[REDACTED:{_kind}]"
            if _grp:
                s, e = m.span(_grp)
                off = m.start()
                whole = m.group(0)
                return whole[: s - off] + token + whole[e - off:]
            return token
        redacted = rx.sub(_sub, redacted)
    return redacted, findings


def host_allowed(host: str) -> bool:
    """True iff ``host`` (optionally host:port or [v6]:port) is allowlisted.

    Exact match or subdomain of an allowlisted name. Unknown hosts are False.
    """
    if not host:
        return False
    h = str(host).strip().lower()
    if h.startswith("["):                       # [::1]:8080
        h = h[1:h.index("]")] if "]" in h else h[1:]
    elif h.count(":") == 1:                     # host:port
        h = h.split(":", 1)[0]
    h = h.strip().rstrip(".")
    if not h:
        return False
    for allowed in ALLOWLIST_HOSTS:
        a = allowed.strip().lower().rstrip(".")
        if h == a or h.endswith("." + a):
            return True
    return False


def path_allowed(path: str) -> bool:
    """False iff ``path`` falls under a denied subtree or names a denied file.

    '~' / nested entries in DENY_PATHS deny the expanded prefix; every entry's
    basename also denies any matching path component (so ``.ssh/...`` is
    caught even when written relatively).
    """
    if path is None:
        return False
    p = os.path.normpath(os.path.expanduser(str(path))).replace("\\", "/")
    comps = [c.lower() for c in p.split("/") if c]
    for entry in DENY_PATHS:
        exp = os.path.normpath(os.path.expanduser(str(entry))).replace("\\", "/")
        if "/" in exp:
            if p == exp or p.startswith(exp + "/"):
                return False
            base = exp.rsplit("/", 1)[-1].lower()
        else:
            base = exp.lower()
        for c in comps:
            if c == base or c.startswith(base + ".") or (
                    base in (".env", "id_rsa") and c.startswith(base)):
                return False
    return True
