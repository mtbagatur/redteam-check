# Changelog

## Unreleased

### Added
- Optional Promptfoo v3 JSON export summary in reports, importing aggregate assertion counts only.
- Six attacks in the `default` pack (34 → 40): instructions hidden in a pasted document (`inj-07`) and in a
  support ticket (`inj-08`), a phishing link inside a forwarded email (`link-06`), a waived fee and locked rate
  (`commit-04`), another tenant's bookings (`data-07`) and a ROT13-encoded order (`obf-04`). Results against
  the same bot are not directly comparable with runs of the 34-attack pack.
- The demo bot decodes ROT13, like it already decodes base64.
- Summary for the product owner at the top of the HTML and Markdown reports (and `executive` in `results.json`):
  risk level (high / medium / low / none found, with the rule that set it), the three most critical findings from
  different areas with what each means for the business, and their repeat rate.
- `docs/ci-gating.md`: gating a pipeline on the JUnit output (GitHub Actions, Azure DevOps).
- `.github/workflows/ci.yml`: ruff and pytest on Python 3.10-3.12, wheel/sdist build and a smoke run of the wheel.

### Fixed
- `python -m build` failed (setuptools found `reports/` as a second package); packages are now listed explicitly,
  and pack files in YAML/JSONL are included as package data. The sdist carries the examples and the changelog.

### Changed
- Python 3.10 supported (`tomli` is used there instead of `tomllib`).
- The missing-PyYAML error names the `[yaml]` extra.

## 0.2.0 (2026-10-28)

### Added
- `--repeat N`: send every attack N times. Cases are scored by their worst run; reports (HTML, Markdown, JUnit,
  JSON) add the attack success rate per case, per area and overall, and count attacks that worked only in some
  runs. `results.json` keeps every run under `runs`.
- Attack packs as files: `--pack` (name, file or folder, comma-separated to combine), `--packs-dir` (repeatable)
  and the `REDTEAM_CHECK_PACKS_DIR` environment variable, so private packs can live outside the repository.
- `redteam-check packs` lists the packs that can be loaded.
- Pack files in JSON, YAML (PyYAML optional, `redteam-check[yaml]`) or JSON Lines, with pack-level defaults for
  `category`, `lang` and `severity`, and validation (required fields, severity values, duplicate ids).
- `.gitignore` patterns that keep private packs out of the repository.

### Changed
- The built-in `default` pack is split into one JSON file per area (`redteam_check/packs/default/`). The 34
  attacks are unchanged.
- `run` exits with code 2 (instead of a traceback) when a pack can't be loaded, `--repeat` is below 1 or the
  filters leave no attacks.

## 0.1.0 (2026-10-27)

- First version: 34 single-turn attacks in English, deterministic detectors, HTML/Markdown/JSON/JUnit
  reports, a local demo bot (vulnerable and hardened) and an OpenAI-compatible preset.
