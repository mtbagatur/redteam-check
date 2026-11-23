"""redteam-check: run an attack pack against an AI chat endpoint and write a report.

    redteam-check run -c target.toml -o reports/acme       # exit 1 if any attack failed
    redteam-check mock [--hardened] [--port 8787]          # local demo bot
    redteam-check pack [--pack default]                    # list the attacks in a pack
    redteam-check packs [--packs-dir ~/kalyon/packs]       # list the packs that can be loaded

Private packs (language, sector or customer packs) stay outside this repository; point --packs-dir (or the
REDTEAM_CHECK_PACKS_DIR environment variable) at their folder.
"""
import argparse
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from redteam_check import mock, pack, promptfoo, report
from redteam_check.runner import load_pack, run, summary
from redteam_check.target import HttpTarget


def cmd_run(a) -> int:
    with open(a.config, "rb") as f:
        cfg = tomllib.load(f)
    ctx = cfg.get("context", {})
    if a.repeat < 1:
        print("--repeat must be at least 1", file=sys.stderr)
        return 2
    promptfoo_summary = None
    if a.promptfoo_json:
        try:
            promptfoo_summary = promptfoo.read_summary(a.promptfoo_json)
        except (OSError, ValueError) as e:
            print(f"Promptfoo report error: {e}", file=sys.stderr)
            return 2
    try:
        cases = load_pack(a.pack, a.packs_dir)
    except (pack.PackError, OSError) as e:
        print(f"pack error: {e}", file=sys.stderr)
        return 2
    if a.only:
        cases = [c for c in cases if c["category"] in a.only.split(",")]
    if a.lang:
        cases = [c for c in cases if c["lang"] in a.lang.split(",")]
    target = HttpTarget(cfg["target"])
    delay = a.delay if a.delay is not None else float(cfg["target"].get("delay", 0))

    if not cases:
        print("no attacks left after --only/--lang filters", file=sys.stderr)
        return 2

    def progress(i, n, r):
        runs = f"{r['counts']['fail']}/{r['repeat']} " if r["repeat"] > 1 else ""
        print(f"[{i:>2}/{n}] {r['verdict']:<6} {runs}{r['id']:<10} {r['response'][:60]!r}", file=sys.stderr, flush=True)

    meta = {"product": ctx.get("product", "unnamed"), "target": target.url, "pack": a.pack, "repeat": a.repeat,
            "started": report.now()}
    results = run(cases, target, ctx, delay=delay, progress=None if a.quiet else progress, repeat=a.repeat)
    paths = report.write_all(results, meta, a.out, promptfoo_summary=promptfoo_summary)
    t = summary(results)["totals"]
    print(f"\n{t['fail']} failed, {t['review']} review, {t['pass']} passed, {t['error']} errors "
          f"of {t['total']}")
    if a.repeat > 1:
        print(f"{a.repeat} runs each: attack success rate {report._pct(t['success_rate'])} "
              f"({t['failed_runs']}/{t['answered_runs']} replies), "
              f"{t['flaky']} attacks worked only some of the time")
    print(f"report: {paths['html']}")
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
    try:
        cases = load_pack(a.pack, a.packs_dir)
    except (pack.PackError, OSError) as e:
        print(f"pack error: {e}", file=sys.stderr)
        return 2
    for c in cases:
        print(f"{c['id']:<10} {c['category']:<24} {c['severity']:<6} {c['lang']}  {c['prompt'][:70]}")
    return 0


def cmd_packs(a) -> int:
    for name, path in pack.available(a.packs_dir):
        print(f"{name:<20} {path}")
    return 0


def _pack_args(parser):
    parser.add_argument("--pack", default="default",
                        help="pack name, file or folder; comma-separate to combine (e.g. default,tr-ornek)")
    parser.add_argument("--packs-dir", action="append", default=[], metavar="DIR",
                        help="extra folder to look for packs in (repeatable; searched before the built-in packs)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="redteam-check", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the attacks and write the report")
    r.add_argument("-c", "--config", required=True, help="target TOML file")
    r.add_argument("-o", "--out", default="reports/latest", help="output folder")
    _pack_args(r)
    r.add_argument("--repeat", type=int, default=1, metavar="N",
                   help="send every attack N times and report the success rate (LLM replies vary)")
    r.add_argument("--only", help="comma-separated categories")
    r.add_argument("--lang", help="comma-separated languages, e.g. en,tr")
    r.add_argument("--delay", type=float, help="seconds between requests (overrides the config)")
    r.add_argument("--promptfoo-json", metavar="FILE",
                   help="attach aggregate counts from a local Promptfoo v3 JSON export; raw eval data is ignored")
    r.add_argument("-q", "--quiet", action="store_true")
    r.set_defaults(fn=cmd_run)
    m = sub.add_parser("mock", help="start the local demo bot")
    m.add_argument("--port", type=int, default=8787)
    m.add_argument("--hardened", action="store_true")
    m.set_defaults(fn=cmd_mock)
    k = sub.add_parser("pack", help="list the attacks")
    _pack_args(k)
    k.set_defaults(fn=cmd_pack)
    ks = sub.add_parser("packs", help="list the packs that can be loaded")
    ks.add_argument("--packs-dir", action="append", default=[], metavar="DIR")
    ks.set_defaults(fn=cmd_packs)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
