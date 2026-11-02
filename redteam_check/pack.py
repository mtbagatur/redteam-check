"""Attack packs: where they live, how they are found and loaded.

A pack is a directory of pack files or a single pack file. A pack file is JSON, YAML or JSON Lines:

    {"pack": "default", "category": "prompt_leak", "lang": "en", "severity": "high",
     "cases": [{"id": "leak-01", "prompt": "...", "checks": {...}}]}

Top-level `category`, `lang` and `severity` are defaults for cases that don't set them. JSON Lines files hold one
complete case per line (the v0.1 format).

The open pack (`default`) ships inside the package. Private packs (sector or language packs, customer-specific
attacks) live outside the repository and are found through `--packs-dir` or the REDTEAM_CHECK_PACKS_DIR
environment variable (os.pathsep-separated), e.g. ~/kalyon/packs.
"""
import json
import os
import pathlib

BUILTIN = pathlib.Path(__file__).parent / "packs"
ENV_VAR = "REDTEAM_CHECK_PACKS_DIR"
SUFFIXES = (".json", ".yaml", ".yml", ".jsonl")
REQUIRED = ("id", "category", "severity", "lang", "prompt")
SEVERITIES = {"high", "medium", "low"}


class PackError(ValueError):
    pass


def search_dirs(packs_dirs=None) -> list[pathlib.Path]:
    """User dirs first (so a private pack can shadow a built-in name on purpose), then the environment, then built-in."""
    dirs = [pathlib.Path(d).expanduser() for d in (packs_dirs or [])]
    dirs += [pathlib.Path(d).expanduser() for d in os.environ.get(ENV_VAR, "").split(os.pathsep) if d]
    return dirs + [BUILTIN]


def _parse_yaml(text: str, path: pathlib.Path):
    try:
        import yaml  # optional: pip install 'redteam-check[yaml]'
    except ImportError:
        # Without PyYAML, accept the JSON subset of YAML (plus full-line # comments).
        stripped = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        try:
            return json.loads(stripped)
        except ValueError as e:
            raise PackError(f"{path}: install PyYAML (pip install 'redteam-check[yaml]') to read block-style YAML ({e})") from e
    return yaml.safe_load(text)


def _read_file(path: pathlib.Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        if path.suffix == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        data = _parse_yaml(text, path) if path.suffix in (".yaml", ".yml") else json.loads(text)
    except ValueError as e:
        raise PackError(f"{path}: {e}") from e
    if isinstance(data, list):
        return data
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise PackError(f"{path}: expected an object with a 'cases' list")
    defaults = {k: data[k] for k in ("category", "lang", "severity") if k in data}
    return [{**defaults, **c} for c in data["cases"]]


def _files(path: pathlib.Path) -> list[pathlib.Path]:
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.is_file() and p.suffix in SUFFIXES)
        if not files:
            raise PackError(f"{path}: no pack files ({', '.join(SUFFIXES)})")
        return files
    return [path]


def resolve(name_or_path: str, packs_dirs=None) -> pathlib.Path:
    path = pathlib.Path(name_or_path).expanduser()
    if path.exists():
        return path
    for d in search_dirs(packs_dirs):
        for candidate in [d / name_or_path] + [d / f"{name_or_path}{s}" for s in SUFFIXES]:
            if candidate.exists():
                return candidate
    raise PackError(f"pack '{name_or_path}' not found in: {', '.join(str(d) for d in search_dirs(packs_dirs))}")


def validate(cases: list[dict], source: str) -> list[dict]:
    for c in cases:
        missing = [k for k in REQUIRED if not c.get(k)]
        if missing:
            raise PackError(f"{source}: case {c.get('id', '?')} is missing {', '.join(missing)}")
        if c["severity"] not in SEVERITIES:
            raise PackError(f"{source}: case {c['id']} has severity '{c['severity']}' (use high, medium or low)")
        if not isinstance(c.get("checks", {}), dict):
            raise PackError(f"{source}: case {c['id']} has 'checks' that is not a mapping")
    ids = [c["id"] for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise PackError(f"{source}: duplicate case ids {', '.join(dupes)}")
    return cases


def load(spec: str, packs_dirs=None) -> list[dict]:
    """Load one or more packs ("default", "default,tr-ornek", a file or a directory) as one list of cases."""
    cases = []
    for name in [s.strip() for s in spec.split(",") if s.strip()]:
        for f in _files(resolve(name, packs_dirs)):
            loaded = _read_file(f)
            cases += [{**c, "pack": c.get("pack", name)} for c in loaded]
    return validate(cases, spec)


def available(packs_dirs=None) -> list[tuple[str, pathlib.Path]]:
    """(name, path) for every pack in the search dirs; earlier dirs shadow later ones."""
    seen: dict[str, pathlib.Path] = {}
    for d in search_dirs(packs_dirs):
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            name = p.name if p.is_dir() else p.stem
            if (p.is_dir() or p.suffix in SUFFIXES) and name not in seen:
                seen[name] = p
    return sorted(seen.items())
