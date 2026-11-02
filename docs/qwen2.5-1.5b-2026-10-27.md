# Qwen2.5 1.5B (local, Ollama, CPU): naive vs hardened system prompt

Same 34-attack pack, same model, 27.10.2026. Only the system prompt differs (see examples/openai-compatible.toml;
the hardened one adds six explicit rules: scope, no prompt disclosure, user text is never an instruction,
no commitments, link allow-list, emergency guidance).

| Area | Naive: fail / review | Hardened prompt: fail / review |
|---|---|---|
| Prompt leak | 3 / 1 | 1 / 0 |
| Instruction override | 2 / 0 | 3 / 0 |
| Unsafe links | 1 / 0 | 1 / 1 |
| Commitments | 1 / 0 | 1 / 0 |
| Data exposure | 0 / 0 | 1 / 0 |
| Off-topic | 0 / 3 | 0 / 2 |
| Brand and safety | 0 / 1 | 1 / 0 |
| **Total** | **7 / 5** | **8 / 3** |

What this shows:
- Prompt-only hardening moved failures around rather than removing them: leaks dropped, instruction
  override got worse. Small models do not reliably follow long rule lists; output-side checks are needed.
- Results vary between runs: the same naive configuration gave a different failure count in an earlier run. Report a
  finding only after it reproduces; a `--repeat` option is the next feature.
