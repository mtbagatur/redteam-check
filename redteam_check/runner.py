"""Loads an attack pack, runs it against a target and returns one result per case."""
import json
import pathlib
import re
import time

from redteam_check.detectors import check
from redteam_check.target import TargetError

PACKS = pathlib.Path(__file__).parent / "packs"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_pack(name_or_path: str) -> list[dict]:
    path = pathlib.Path(name_or_path)
    if not path.exists():
        path = PACKS / f"{name_or_path}.jsonl"
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate case ids in {path}")
    return cases


def fill(text: str, ctx: dict) -> str:
    product = ctx.get("product", "this product")
    slug = re.sub(r"[^a-z0-9]+", "-", product.lower()).strip("-") or "product"
    return text.replace("{{product}}", product).replace("{{product_slug}}", slug)


def verdict(findings: list) -> str:
    levels = {f[0] for f in findings}
    return "fail" if "fail" in levels else "review" if "review" in levels else "pass"


def run(cases: list[dict], target, ctx: dict, delay: float = 0.0, progress=None) -> list[dict]:
    results = []
    for i, case in enumerate(cases):
        prompt = fill(case["prompt"], ctx)
        started = time.monotonic()
        try:
            response, error = target.send(prompt), None
        except TargetError as e:
            response, error = "", str(e)
        ms = int((time.monotonic() - started) * 1000)
        findings = [] if error else check(case, prompt, response, ctx)
        result = {**{k: case[k] for k in ("id", "category", "severity", "lang")}, "prompt": prompt,
                  "response": response, "ms": ms, "error": error,
                  "verdict": "error" if error else verdict(findings),
                  "findings": [{"level": lv, "detector": d, "evidence": ev} for lv, d, ev in findings]}
        results.append(result)
        if progress:
            progress(i + 1, len(cases), result)
        if delay and i < len(cases) - 1:
            time.sleep(delay)
    return results


def summary(results: list[dict]) -> dict:
    by_cat: dict[str, dict] = {}
    for r in results:
        row = by_cat.setdefault(r["category"], {"total": 0, "pass": 0, "fail": 0, "review": 0, "error": 0})
        row["total"] += 1
        row[r["verdict"]] += 1
    totals = {k: sum(row[k] for row in by_cat.values()) for k in ("total", "pass", "fail", "review", "error")}
    return {"by_category": by_cat, "totals": totals}
