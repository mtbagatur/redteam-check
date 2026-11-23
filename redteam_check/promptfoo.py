"""Read a Promptfoo JSON export without importing its prompts or model outputs."""
import json
import pathlib


MAX_EXPORT_BYTES = 10 * 1024 * 1024


def read_summary(path) -> dict:
    """Return only Promptfoo v3 aggregate counts from a local JSON export.

    Promptfoo exports can contain prompts, provider outputs, and configuration.
    This adapter deliberately discards those fields and never executes export data.
    """
    source = pathlib.Path(path)
    size = source.stat().st_size
    if size > MAX_EXPORT_BYTES:
        raise ValueError(f"Promptfoo export exceeds the {MAX_EXPORT_BYTES // (1024 * 1024)} MiB limit")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Promptfoo JSON export: {exc.msg} at line {exc.lineno} column {exc.colno}") from exc
    if not isinstance(document, dict):
        raise ValueError("Promptfoo export must be a JSON object")

    # Current `promptfoo eval --output results.json` envelope.
    results = document.get("results")
    payload = results if isinstance(results, dict) else document
    if payload.get("version") != 3:
        raise ValueError("unsupported Promptfoo JSON export; expected results.version 3")
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        raise ValueError("Promptfoo export is missing results.stats")

    counts = {}
    for key in ("successes", "failures", "errors"):
        value = stats.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Promptfoo stats.{key} must be a non-negative integer")
        counts[key] = value
    return counts
