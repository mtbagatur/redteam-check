"""Loads an attack pack, runs it against a target and returns one result per case."""
import re
import time

from redteam_check import pack
from redteam_check.detectors import check
from redteam_check.target import TargetError

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
# Worst first: one failed run makes the case fail, whatever the other runs did.
VERDICT_ORDER = ("fail", "review", "error", "pass")


def load_pack(spec: str = "default", packs_dirs=None) -> list[dict]:
    return pack.load(spec, packs_dirs)


def fill(text: str, ctx: dict) -> str:
    product = ctx.get("product", "this product")
    slug = re.sub(r"[^a-z0-9]+", "-", product.lower()).strip("-") or "product"
    return text.replace("{{product}}", product).replace("{{product_slug}}", slug)


def verdict(findings: list) -> str:
    levels = {f[0] for f in findings}
    return "fail" if "fail" in levels else "review" if "review" in levels else "pass"


def _attempt(case: dict, prompt: str, target, ctx: dict) -> dict:
    started = time.monotonic()
    try:
        response, error = target.send(prompt), None
    except TargetError as e:
        response, error = "", str(e)
    ms = int((time.monotonic() - started) * 1000)
    findings = [] if error else check(case, prompt, response, ctx)
    return {"response": response, "ms": ms, "error": error, "verdict": "error" if error else verdict(findings),
            "findings": [{"level": lv, "detector": d, "evidence": ev} for lv, d, ev in findings]}


def run(cases: list[dict], target, ctx: dict, delay: float = 0.0, progress=None, repeat: int = 1) -> list[dict]:
    """Send every case `repeat` times. LLM replies vary between calls, so one clean run proves little.

    Each result carries the worst run (verdict, response, findings) plus `runs` (every attempt),
    `counts` per verdict and `success_rate`: failed runs / runs that got a reply.
    """
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    results = []
    total_requests = len(cases) * repeat
    sent = 0
    for i, case in enumerate(cases):
        prompt = fill(case["prompt"], ctx)
        runs = []
        for _ in range(repeat):
            runs.append(_attempt(case, prompt, target, ctx))
            sent += 1
            if delay and sent < total_requests:
                time.sleep(delay)
        counts = {v: sum(r["verdict"] == v for r in runs) for v in VERDICT_ORDER}
        worst = min(runs, key=lambda r: VERDICT_ORDER.index(r["verdict"]))
        answered = repeat - counts["error"]
        result = {**{k: case[k] for k in ("id", "category", "severity", "lang")}, "pack": case.get("pack"),
                  "prompt": prompt, **worst,
                  "repeat": repeat, "counts": counts,
                  "success_rate": round(counts["fail"] / answered, 4) if answered else None,
                  "runs": runs}
        results.append(result)
        if progress:
            progress(i + 1, len(cases), result)
    return results


def summary(results: list[dict]) -> dict:
    """Case verdicts (worst run) per category, plus run-level counts for the attack success rate."""
    keys = ("total", "pass", "fail", "review", "error")
    by_cat: dict[str, dict] = {}
    for r in results:
        row = by_cat.setdefault(r["category"], {**dict.fromkeys(keys, 0), "runs": 0, "failed_runs": 0,
                                                "answered_runs": 0, "flaky": 0})
        row["total"] += 1
        row[r["verdict"]] += 1
        counts = r.get("counts") or {r["verdict"]: 1}
        n = r.get("repeat", 1)
        row["runs"] += n
        row["failed_runs"] += counts.get("fail", 0)
        row["answered_runs"] += n - counts.get("error", 0)
        row["flaky"] += 0 < counts.get("fail", 0) < n - counts.get("error", 0)
    for row in by_cat.values():
        row["success_rate"] = rate(row)
    totals = {k: sum(row[k] for row in by_cat.values())
              for k in keys + ("runs", "failed_runs", "answered_runs", "flaky")}
    totals["success_rate"] = rate(totals)
    return {"by_category": by_cat, "totals": totals}


def rate(row: dict):
    return round(row["failed_runs"] / row["answered_runs"], 4) if row["answered_runs"] else None
