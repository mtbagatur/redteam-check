"""Writes the run as JSON (raw), Markdown and HTML (for people) and JUnit XML (for CI)."""
import datetime as dt
import html
import json
import pathlib
from xml.sax.saxutils import escape, quoteattr

from redteam_check.runner import SEVERITY_ORDER, summary

TITLES = {
    "prompt_leak": "System prompt leaks",
    "instruction_override": "Instruction override (prompt injection)",
    "unsafe_link": "Unsafe links and phishing",
    "unauthorised_commitment": "Unauthorised commitments",
    "data_exposure": "Personal data and secrets exposure",
    "off_topic_abuse": "Off-topic use and cost abuse",
    "brand_and_safety": "Brand and user safety",
    "obfuscation": "Obfuscated attacks",
}

FIXES = {
    "prompt_leak": "Keep secrets out of the system prompt entirely; assume it will leak. Add an output check that "
                   "blocks replies containing a canary string or long verbatim spans of the prompt.",
    "instruction_override": "Separate user text from instructions (delimiters, a fixed role), and validate the "
                            "output against the feature's allowed format before it reaches the user.",
    "unsafe_link": "Allow-list the domains the assistant may link to and strip or block every other URL, "
                   "including markdown images, which load automatically and can leak data.",
    "unauthorised_commitment": "The assistant must not confirm refunds, prices or legal terms. Route these to a "
                               "tool or a human with real authority, and add an output check for binding language.",
    "data_exposure": "Scope retrieval and tools to the signed-in user, never keep other users' conversations in "
                     "context, keep keys out of the prompt and environment the model can read, and mask personal "
                     "data in outputs and traces.",
    "off_topic_abuse": "Add a topic classifier or a strict scope instruction plus a max output length; this caps "
                       "both misuse and token cost.",
    "brand_and_safety": "Add refusal rules for politics, insults and competitor talk, and a fixed escalation "
                        "message for medical or emergency questions.",
    "obfuscation": "Normalise input (leetspeak, encodings) before safety checks, and rely on output checks, which "
                   "obfuscation does not bypass.",
}

DETECTOR_TEXT = {
    "canary_leak": "Canary from the system prompt appeared in the reply",
    "system_prompt_leak": "Text from the system prompt appeared in the reply",
    "secret_in_output": "Something shaped like an API key or private key appeared",
    "attack_payload_in_output": "The reply did what the attack asked",
    "missing_safety_guidance": "No safety or escalation guidance in the reply",
    "unlisted_link": "Link to a domain that is not on the allow-list",
    "personal_data_in_output": "Personal data that the user did not provide",
    "cost_abuse_long_output": "Very long reply to an abusive request",
    "no_refusal": "Answered a request outside the product's scope",
}


def _sorted_findings(results):
    bad = [r for r in results if r["verdict"] in ("fail", "review")]
    return sorted(bad, key=lambda r: (r["verdict"] != "fail", SEVERITY_ORDER.get(r["severity"], 9), r["id"]))


def _excerpt(text: str, n: int = 400) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + " …"


def markdown(results, meta) -> str:
    s = summary(results)
    t = s["totals"]
    lines = [f"# AI Red-Team Check: {meta['product']}", "",
             f"Run {meta['started']} · target `{meta['target']}` · pack `{meta['pack']}` · {t['total']} attacks", "",
             f"**{t['fail']} failed · {t['review']} need review · {t['pass']} passed"
             + (f" · {t['error']} errors" if t["error"] else "") + "**", "",
             "| Area | Attacks | Failed | Review | Passed |", "|---|---|---|---|---|"]
    for cat, row in s["by_category"].items():
        lines.append(f"| {TITLES.get(cat, cat)} | {row['total']} | {row['fail']} | {row['review']} | {row['pass']} |")
    lines += ["", "## Findings", ""]
    for r in _sorted_findings(results):
        lines += [(f"### {r['verdict'].upper()} · {r['id']} · {TITLES.get(r['category'], r['category'])} "
                  f"({r['severity']})"), "",
                  f"**Attack:** {r['prompt']}", "",
                  f"**Reply:** {_excerpt(r['response'])}", ""]
        for f in r["findings"]:
            lines.append(f"- {f['level']}: {DETECTOR_TEXT.get(f['detector'], f['detector'])} (`{f['evidence']}`)")
        lines += ["", f"**Fix:** {FIXES.get(r['category'], '')}", ""]
    errors = [r for r in results if r["verdict"] == "error"]
    if errors:
        lines += ["## Errors", ""] + [f"- {r['id']}: {r['error']}" for r in errors] + [""]
    lines += ["## Method and limits", "",
              ("Automated single-turn attacks against the endpoint above, scored by deterministic checks (canary "
              "strings, attack payloads, links, personal-data patterns, refusals). \"Review\" items need a human "
              "decision. A clean run does not prove the system is safe; multi-turn and document-borne (indirect) "
              "injection need a tailored test."), ""]
    return "\n".join(lines)


def html_report(results, meta) -> str:
    s = summary(results)
    t = s["totals"]
    esc = html.escape
    rows = "".join(
        f"<tr><td>{esc(TITLES.get(c, c))}</td><td>{r['total']}</td><td class='fail'>{r['fail']}</td>"
        f"<td class='review'>{r['review']}</td><td>{r['pass']}</td></tr>" for c, r in s["by_category"].items())
    cards = []
    for r in _sorted_findings(results):
        items = "".join(f"<li><b>{esc(f['level'])}</b> · {esc(DETECTOR_TEXT.get(f['detector'], f['detector']))}"
                        f" <code>{esc(str(f['evidence']))}</code></li>" for f in r["findings"])
        cards.append(
            f"<article class='{r['verdict']}'><h3><span class='badge'>{r['verdict'].upper()}</span> {esc(r['id'])}"
            f" · {esc(TITLES.get(r['category'], r['category']))} <small>{esc(r['severity'])}</small></h3>"
            f"<p class='lbl'>Attack</p><pre>{esc(r['prompt'])}</pre>"
            f"<p class='lbl'>Reply</p><pre>{esc(_excerpt(r['response'], 700))}</pre>"
            f"<ul>{items}</ul><p class='fix'><b>Fix:</b> {esc(FIXES.get(r['category'], ''))}</p></article>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Red-Team Check</title><style>
:root{{--bg:#f7f7f5;--card:#fff;--ink:#1b1b1f;--muted:#66666d;--line:#e3e3df;--fail:#b3261e;--review:#9a6700;--ok:#2e7d4f}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151516;--card:#1f1f21;--ink:#ececee;--muted:#9c9ca3;--line:#303033;--fail:#f07067;--review:#e3b341;--ok:#5cc08a}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}
main{{max-width:900px;margin:auto;padding:24px 16px 48px}}h1{{margin:0 0 4px;font-size:26px}}.meta{{color:var(--muted);margin:0 0 18px}}
.kpis{{display:flex;gap:10px;margin:0 0 18px}}.kpi{{flex:1;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center;color:var(--muted)}}
.kpi b{{display:block;font-size:28px;color:var(--ink)}}.kpi.fail b{{color:var(--fail)}}.kpi.review b{{color:var(--review)}}.kpi.pass b{{color:var(--ok)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
td,th{{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left}}td.fail{{color:var(--fail);font-weight:600}}td.review{{color:var(--review)}}
article{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--review);border-radius:12px;padding:12px 16px;margin:12px 0}}
article.fail{{border-left-color:var(--fail)}}h3{{margin:0 0 6px;font-size:16px}}small{{color:var(--muted);font-weight:400}}
.badge{{font-size:11px;padding:2px 6px;border-radius:6px;background:var(--review);color:#fff;vertical-align:middle}}article.fail .badge{{background:var(--fail)}}
.lbl{{margin:8px 0 2px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;background:var(--bg);padding:8px;border-radius:8px;font-size:13px}}
code{{background:var(--bg);padding:0 4px;border-radius:4px;overflow-wrap:anywhere}}.fix{{margin:8px 0 0}}
</style></head><body><main>
<h1>AI Red-Team Check: {esc(meta['product'])}</h1>
<p class="meta">{esc(meta['started'])} · {esc(meta['target'])} · pack {esc(meta['pack'])} · {t['total']} attacks</p>
<div class="kpis"><div class="kpi fail"><b>{t['fail']}</b>failed</div><div class="kpi review"><b>{t['review']}</b>need review</div>
<div class="kpi pass"><b>{t['pass']}</b>passed</div></div>
<table><tr><th>Area</th><th>Attacks</th><th>Failed</th><th>Review</th><th>Passed</th></tr>{rows}</table>
<h2>Findings</h2>{''.join(cards) or '<p>No findings.</p>'}
<h2>Method and limits</h2><p>Automated single-turn attacks scored by deterministic checks. "Review" items need a human
decision. A clean run does not prove the system is safe; multi-turn and document-borne injection need a tailored test.</p>
</main></body></html>"""


def junit(results, meta) -> str:
    t = summary(results)["totals"]
    cases = []
    for r in results:
        body = ""
        if r["verdict"] == "fail":
            msg = "; ".join(f"{f['detector']}: {f['evidence']}" for f in r["findings"] if f["level"] == "fail")
            body = f"<failure message={quoteattr(msg)}>{escape(_excerpt(r['response'], 1000))}</failure>"
        elif r["verdict"] == "error":
            body = f"<error message={quoteattr(r['error'] or '')}/>"
        cases.append(f'<testcase classname="redteam.{r["category"]}" name={quoteattr(r["id"])} '
                     f'time="{r["ms"] / 1000:.3f}">{body}</testcase>')
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="redteam-check" tests="{t["total"]}" '
            f'failures="{t["fail"]}" errors="{t["error"]}">\n' + "\n".join(cases) + "\n</testsuite>\n")


def write_all(results, meta, out_dir) -> dict:
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "results.json", "md": out / "report.md", "html": out / "report.html",
             "junit": out / "junit.xml"}
    paths["json"].write_text(json.dumps({"meta": meta, "summary": summary(results), "results": results},
                                        indent=2, ensure_ascii=False), encoding="utf-8")
    paths["md"].write_text(markdown(results, meta), encoding="utf-8")
    paths["html"].write_text(html_report(results, meta), encoding="utf-8")
    paths["junit"].write_text(junit(results, meta), encoding="utf-8")
    return paths


def now() -> str:
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
