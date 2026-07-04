#!/usr/bin/env python
"""Airlock screening benchmark — one-command repro.

Evaluates airlock.screener.screen() as a prompt-injection classifier on:
  * deepset/prompt-injections (HF datasets, cached locally) — attacks + benign
  * corpus/payloads.jsonl (held-out Airlock attack corpus, opt-in via --corpus)

Positive class = attack (label 1). A "quarantine" verdict counts as a positive
prediction. The screener fails CLOSED, so screener errors count as quarantine
(tracked separately in the err column).

Examples:
  python bench/run_eval.py --models gemma3:12b-it-qat --n 6          # smoke
  python bench/run_eval.py --models 1b,4b,12b,27b --split all --corpus  # full sweep

Writes bench/RESULTS.md (overwritten each run) and prints the same tables.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DATASET = "deepset/prompt-injections"
CORPUS_PATH = REPO_ROOT / "corpus" / "payloads.jsonl"
DEFAULT_OUT = REPO_ROOT / "bench" / "RESULTS.md"

# Use the local HF cache without touching the network when it is present.
_cache = Path(os.environ.get("HF_DATASETS_CACHE",
                             Path.home() / ".cache" / "huggingface" / "datasets"))
if (_cache / "deepset___prompt-injections").exists():
    os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")

from datasets import load_dataset  # noqa: E402  (env must be set first)

from airlock import config  # noqa: E402
from airlock.screener import screen  # noqa: E402


# ---------------------------------------------------------------- data loading

def load_items(split: str, use_corpus: bool) -> list[dict]:
    """Combined pool of {text, label, source, family} items."""
    ds = load_dataset(DATASET)
    splits = ["train", "test"] if split == "all" else [split]
    items = [
        {"text": row["text"], "label": int(row["label"]),
         "source": "deepset", "family": ""}
        for s in splits for row in ds[s]
    ]
    if use_corpus:
        for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            items.append({"text": d["text"], "label": int(d.get("label", 1)),
                          "source": "corpus", "family": d.get("family", "unknown")})
    return items


def subsample(items: list[dict], n: int, seed: int) -> list[dict]:
    """Label-stratified subsample of n items (n<=0 → everything, shuffled)."""
    rng = random.Random(seed)
    if n <= 0 or n >= len(items):
        out = list(items)
        rng.shuffle(out)
        return out
    pos = [i for i in items if i["label"] == 1]
    neg = [i for i in items if i["label"] == 0]
    rng.shuffle(pos)
    rng.shuffle(neg)
    n_pos = min(len(pos), (n + 1) // 2)
    n_neg = min(len(neg), n - n_pos)
    n_pos = min(len(pos), n - n_neg)  # top up if one side ran short
    out = pos[:n_pos] + neg[:n_neg]
    rng.shuffle(out)
    return out


# ------------------------------------------------------------------ evaluation

def expand_model(name: str) -> str:
    """Allow shorthand sizes: '4b' → 'gemma3:4b-it-qat'."""
    name = name.strip()
    if name and name[:-1].isdigit() and name.endswith("b"):
        return f"gemma3:{name}-it-qat"
    return name


def evaluate(model: str, items: list[dict]) -> list[dict]:
    rows = []
    total = len(items)
    for i, it in enumerate(items, 1):
        t0 = time.perf_counter()
        v = screen(it["text"], source=f"bench:{it['source']}", model=model)
        dt = time.perf_counter() - t0
        pred = 1 if v.quarantined() else 0
        rows.append({**it, "pred": pred, "latency": dt,
                     "error": v.threat_family == "screener-error", "verdict": v})
        mark = "hit " if pred == it["label"] else "MISS"
        print(f"  [{i:>3}/{total}] {mark} label={it['label']} "
              f"pred={v.decision:<10} {dt:5.1f}s src={it['source']}", flush=True)
    return rows


def metrics(rows: list[dict]) -> dict:
    tp = sum(1 for r in rows if r["label"] == 1 and r["pred"] == 1)
    fn = sum(1 for r in rows if r["label"] == 1 and r["pred"] == 0)
    fp = sum(1 for r in rows if r["label"] == 0 and r["pred"] == 1)
    tn = sum(1 for r in rows if r["label"] == 0 and r["pred"] == 0)

    def ratio(a, b):
        return a / b if b else None

    tpr = ratio(tp, tp + fn)
    prec = ratio(tp, tp + fp)
    f1 = (2 * prec * tpr / (prec + tpr)) if prec and tpr and (prec + tpr) else (
        0.0 if (tpr is not None and prec is not None) else None)
    return {
        "n": len(rows), "attacks": tp + fn, "benign": fp + tn,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr": tpr, "fpr": ratio(fp, fp + tn), "precision": prec, "f1": f1,
        "accuracy": ratio(tp + tn, len(rows)),
        "avg_latency": (sum(r["latency"] for r in rows) / len(rows)) if rows else None,
        "errors": sum(1 for r in rows if r["error"]),
    }


# ------------------------------------------------------------------- reporting

def pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def num(x, fmt="{:.3f}") -> str:
    return "n/a" if x is None else fmt.format(x)


def clip(text: str, width: int = 90) -> str:
    one = " ".join(text.split()).replace("|", "\\|")
    return one[:width] + ("…" if len(one) > width else "")


def build_report(results: dict[str, list[dict]], args, pool_note: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = []
    L.append("# Airlock screening benchmark\n")
    L.append(f"- **Date:** {ts}")
    L.append(f"- **Classifier:** `airlock.screener.screen()` (fails closed; "
             f"screener errors count as quarantine)")
    L.append(f"- **Dataset:** `{DATASET}` split=`{args.split}`"
             + (" + `corpus/payloads.jsonl` (held-out)" if args.corpus else ""))
    L.append(f"- **Sample:** {pool_note} (seed={args.seed})")
    L.append(f"- **Model host:** `{config.MODEL_URL}` (Ollama)")
    L.append("")
    L.append("Positive class = attack. Detection rate = recall/TPR on attacks; "
             "FPR = benign flagged as attacks.\n")

    L.append("## Results\n")
    L.append("| Model | N | Attacks | Benign | Detection (TPR) | FPR | Precision | F1 | Accuracy | Avg latency | Errors |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for model, rows in results.items():
        m = metrics(rows)
        L.append(f"| `{model}` | {m['n']} | {m['attacks']} | {m['benign']} | "
                 f"{pct(m['tpr'])} | {pct(m['fpr'])} | {pct(m['precision'])} | "
                 f"{num(m['f1'])} | {pct(m['accuracy'])} | "
                 f"{num(m['avg_latency'], '{:.1f}s')} | {m['errors']} |")
    L.append("")

    L.append("## Per-source\n")
    L.append("| Model | Source | N | Attacks | Detection (TPR) | FPR |")
    L.append("|---|---|---:|---:|---:|---:|")
    for model, rows in results.items():
        for src in ("deepset", "corpus"):
            sub = [r for r in rows if r["source"] == src]
            if not sub:
                continue
            m = metrics(sub)
            L.append(f"| `{model}` | {src} | {m['n']} | {m['attacks']} | "
                     f"{pct(m['tpr'])} | {pct(m['fpr'])} |")
    L.append("")

    if args.corpus:
        L.append("## Per-family (corpus, held out from tuning)\n")
        L.append("| Model | Family | Detected | Total |")
        L.append("|---|---|---:|---:|")
        for model, rows in results.items():
            fams: dict[str, list[int]] = {}
            for r in rows:
                if r["source"] != "corpus":
                    continue
                d, t = fams.setdefault(r["family"], [0, 0])
                fams[r["family"]] = [d + (r["pred"] == 1), t + 1]
            for fam in sorted(fams):
                d, t = fams[fam]
                L.append(f"| `{model}` | {fam} | {d} | {t} |")
        L.append("")

    for model, rows in results.items():
        misses = [r for r in rows if r["label"] == 1 and r["pred"] == 0][:6]
        fps = [r for r in rows if r["label"] == 0 and r["pred"] == 1][:6]
        if not misses and not fps:
            continue
        L.append(f"## Notable errors — `{model}`\n")
        for r in misses:
            L.append(f"- **Missed attack** ({r['source']}"
                     + (f", {r['family']}" if r["family"] else "")
                     + f"): {clip(r['text'])}")
        for r in fps:
            L.append(f"- **False positive** ({r['source']}): {clip(r['text'])} "
                     f"— _{clip(r['verdict'].reason, 120)}_")
        L.append("")

    L.append("---")
    L.append("Repro: `python bench/run_eval.py --models "
             + ",".join(results) + f" --split {args.split} --n {args.n}"
             + (" --corpus" if args.corpus else "") + f" --seed {args.seed}`")
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------------ main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Benchmark airlock.screener.screen() on prompt-injection data.")
    ap.add_argument("--models", default=config.MODEL,
                    help="Comma-separated Ollama models; shorthand sizes ok "
                         "(e.g. '1b,4b,12b' → gemma3:<size>-it-qat). Default: %(default)s")
    ap.add_argument("--n", type=int, default=0,
                    help="Subsample N items (label-stratified). 0 = full set.")
    ap.add_argument("--split", choices=("train", "test", "all"), default="test",
                    help="deepset split to use (default: %(default)s)")
    ap.add_argument("--corpus", action="store_true",
                    help="Also include corpus/payloads.jsonl (held-out attacks)")
    ap.add_argument("--seed", type=int, default=7, help="Sampling seed")
    ap.add_argument("--out", default=str(DEFAULT_OUT),
                    help="Output markdown path (default: bench/RESULTS.md)")
    args = ap.parse_args(argv)

    models = [expand_model(m) for m in args.models.split(",") if m.strip()]
    pool = load_items(args.split, args.corpus)
    items = subsample(pool, args.n, args.seed)
    attacks = sum(1 for i in items if i["label"] == 1)
    pool_note = (f"{len(items)} items ({attacks} attacks / "
                 f"{len(items) - attacks} benign) of {len(pool)} available")
    print(f"Pool: {pool_note}")

    results: dict[str, list[dict]] = {}
    for model in models:
        print(f"\n=== {model} ===", flush=True)
        try:  # warm-up so model load time doesn't skew item latency
            screen("hello", source="bench:warmup", model=model)
        except Exception as e:  # pragma: no cover — screen() itself fails closed
            print(f"  warmup: {e}")
        results[model] = evaluate(model, items)
        m = metrics(results[model])
        print(f"  -> TPR {pct(m['tpr'])}  FPR {pct(m['fpr'])}  "
              f"precision {pct(m['precision'])}  F1 {num(m['f1'])}  "
              f"acc {pct(m['accuracy'])}  avg {num(m['avg_latency'], '{:.1f}s')}  "
              f"errors {m['errors']}")

    report = build_report(results, args, pool_note)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"\nWrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
