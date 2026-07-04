"""Attack-family matcher: embed untrusted content with embeddinggemma and find
the nearest seed payload by cosine similarity.

Used by the screener to boost confidence and to catch obfuscated variants that a
zero-shot classifier might miss. Seed payloads live in ``corpus/payloads.jsonl``
(held out from bench tuning) and their embeddings are cached on init.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Optional

import httpx

from . import config

# corpus/payloads.jsonl sits at the repo root, one level above the package.
_CORPUS_PATH = Path(__file__).resolve().parent.parent / "corpus" / "payloads.jsonl"


def embed(inputs: list[str], *, url: Optional[str] = None,
          model: Optional[str] = None, timeout: float = 180.0) -> list[list[float]]:
    """Call the Ollama embedding endpoint. Returns one vector per input."""
    url = url or config.MODEL_URL
    model = model or config.EMBED_MODEL
    r = httpx.post(f"{url}/api/embed",
                   json={"model": model, "input": inputs}, timeout=timeout)
    r.raise_for_status()
    return r.json()["embeddings"]


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class FamilyMatcher:
    """Loads seed payloads and matches content to its nearest attack family.

    >>> m = FamilyMatcher()
    >>> family, score = m.match("Ignore all previous instructions...")
    """

    def __init__(self, corpus_path: Optional[str | Path] = None, *,
                 url: Optional[str] = None, model: Optional[str] = None):
        self.corpus_path = Path(corpus_path) if corpus_path else _CORPUS_PATH
        self.url = url or config.MODEL_URL
        self.model = model or config.EMBED_MODEL
        self.seeds: list[dict] = []
        self._embeddings: list[list[float]] = []
        self._load()

    def _load(self) -> None:
        if not self.corpus_path.exists():
            raise FileNotFoundError(f"corpus not found: {self.corpus_path}")
        texts: list[str] = []
        for line in self.corpus_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            self.seeds.append(rec)
            texts.append(rec["text"])
        if texts:
            self._embeddings = embed(texts, url=self.url, model=self.model)

    def __len__(self) -> int:
        return len(self.seeds)

    @property
    def families(self) -> list[str]:
        seen: list[str] = []
        for s in self.seeds:
            if s["family"] not in seen:
                seen.append(s["family"])
        return seen

    def match(self, content: str) -> tuple[str, float]:
        """Return ``(family, score)`` for the nearest seed by cosine similarity.

        ``score`` is in ``[-1, 1]`` (typically 0..1 for text). On an empty corpus
        or embedding failure returns ``("none", 0.0)`` so callers never crash.
        """
        if not self.seeds:
            return ("none", 0.0)
        try:
            vec = embed([content], url=self.url, model=self.model)[0]
        except (httpx.HTTPError, KeyError, ValueError):
            return ("none", 0.0)
        best_family = "none"
        best_score = -1.0
        for seed, emb in zip(self.seeds, self._embeddings):
            s = cosine(vec, emb)
            if s > best_score:
                best_score = s
                best_family = seed["family"]
        return (best_family, best_score)


# --------------------------------------------------------------------------
# Verdict boost — implements the config.FAMILY_THRESHOLD contract:
# quarantine when decision == quarantine OR family match with score >= threshold.

_shared_matcher: Optional[FamilyMatcher] = None


def apply_boost(verdict, content: str):
    """Layer the attack-family matcher over a screener ``Verdict``.

    * ``allow`` + cosine >= ``config.FAMILY_THRESHOLD`` to a known attack seed
      -> flipped to ``quarantine`` (catches obfuscated variants the zero-shot
      screener misses).
    * already ``quarantine`` + strong match -> confidence raised to >= score.

    Strictly fail-soft: on any error (corpus missing, embed endpoint down)
    the verdict is returned unchanged. The boost can only ADD caution — it
    never downgrades a quarantine to allow.
    """
    global _shared_matcher
    try:
        if _shared_matcher is None:
            _shared_matcher = FamilyMatcher()
        family, score = _shared_matcher.match(content)
        if score >= config.FAMILY_THRESHOLD:
            if not verdict.quarantined():
                verdict.decision = "quarantine"
                verdict.threat_family = family
                verdict.reason = (
                    f"family-match boost: cosine {score:.2f} to known '{family}' "
                    f"corpus payload (threshold {config.FAMILY_THRESHOLD}); "
                    f"screener had allowed: {verdict.reason or 'no reason given'}"
                )
            verdict.confidence = max(verdict.confidence, round(float(score), 3))
    except Exception:
        pass
    return verdict
