"""redteam-check: run an attack pack against an AI chat endpoint and write a report.

    redteam-check run -c target.toml -o reports/acme       # exit 1 if any attack failed
    redteam-check mock [--hardened] [--port 8787]          # local demo bot
    redteam-check pack                                     # list the attacks in the pack
"""
import argparse
import sys
import tomllib

from redteam_check import mock, report
from redteam_check.runner import load_pack, run, summary
from redteam_check.target import HttpTarget


def cmd_run(a) -> int:
    with open(a.config, "rb") as f:
        cfg = tomllib.load(f)
    ctx = cfg.get("context", {})
    cases = load_pack(a.pack)
    if a.only:
        cases = [c for c in cases if c["category"] in a.only.split(",")]
    if a.lang:
        cases = [c for c in cases if c["lang"] in a.lang.split(",")]
    target = HttpTarget(cfg["target"])
    delay = a.delay if a.delay is not None else float(cfg["target"].get("delay", 0))

    def progress(i, n, r):
        print(f"[{i:>2}/{n}] {r['verdict']:<6} {r['id']:<10} {r['response'][:60]!r}", file=sys.stderr, flush=True)

    meta = {"product": ctx.get("product", "unnamed"), "target": target.url, "pack": a.pack, "started": report.now()}
    results = run(cases, target, ctx, delay=delay, progress=None if a.quiet else progress)
    paths = report.write_all(results, meta, a.out)
    t = summary(results)["totals"]
    print(f"\n{t['fail']} failed, {t['review']} review, {t['pass']} passed, {t['error']} errors "
          f"of {t['total']}\nreport: {paths['html']}")
    return 1 if t["fail"] or t["error"] else 0


def cmd_mock(a) -> int:
    srv = mock.server(a.port, a.hardened)
    print(f"demo bot ({'hardened' if a.hardened else 'vulnerable'}) on http://127.0.0.1:{a.port}/chat", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_pack(a) -> int:
    for c in load_pack(a.pack):
        print(f"{c['id']:<10} {c['category']:<24} {c['severity']:<6} {c['lang']}  {c['prompt'][:70]}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="redteam-check", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the attacks and write the report")
    r.add_argument("-c", "--config", required=True, help="target TOML file")
    r.add_argument("-o", "--out", default="reports/latest", help="output folder")
    r.add_argument("--pack", default="default", help="pack name or path to a .jsonl file")
    r.add_argument("--only", help="comma-separated categories")
    r.add_argument("--lang", help="comma-separated languages, e.g. en,tr")
    r.add_argument("--delay", type=float, help="seconds between requests (overrides the config)")
    r.add_argument("-q", "--quiet", action="store_true")
    r.set_defaults(fn=cmd_run)
    m = sub.add_parser("mock", help="start the local demo bot")
    m.add_argument("--port", type=int, default=8787)
    m.add_argument("--hardened", action="store_true")
    m.set_defaults(fn=cmd_mock)
    k = sub.add_parser("pack", help="list the attacks")
    k.add_argument("--pack", default="default")
    k.set_defaults(fn=cmd_pack)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
