# Changelog

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
