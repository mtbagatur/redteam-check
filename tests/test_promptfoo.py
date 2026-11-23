import json
import threading
from pathlib import Path

import pytest

from redteam_check import mock, promptfoo, report
from redteam_check.cli import main
from redteam_check.runner import summary
from test_v02 import INJ, ScriptedTarget, _cfg
from redteam_check.runner import run


FIXTURE = Path(__file__).parent / "fixtures/promptfoo_v3_synthetic.json"


def test_reads_only_aggregate_counts():
    assert promptfoo.read_summary(FIXTURE) == {"successes": 7, "failures": 2, "errors": 1}


def test_promptfoo_report_excludes_raw_export_fields():
    counts = promptfoo.read_summary(FIXTURE)
    results = run([INJ], ScriptedTarget(["Sorry, no."]), {})
    meta = {"product": "Sample", "target": "scripted://", "pack": "default", "started": "now"}
    outputs = [report.markdown(results, meta, counts), report.html_report(results, meta, counts),
               json.dumps({"external_promptfoo_eval": counts})]
    for output in outputs:
        for sentinel in ("SYNTHETIC_PROMPT_SENTINEL", "SYNTHETIC_RESPONSE_SENTINEL",
                         "SYNTHETIC_CONFIG_SENTINEL", "SYNTHETIC_VARS_SENTINEL"):
            assert sentinel not in output
    assert "Promptfoo eval" in outputs[0] and "Promptfoo eval" in outputs[1]


def test_optional_section_does_not_change_redteam_results_or_severity():
    results = run([INJ], ScriptedTarget(["Sorry, no."]), {})
    meta = {"product": "Sample", "target": "scripted://", "pack": "default", "started": "now"}
    plain = report.write_all(results, meta, Path("/tmp/redteam-report-without-promptfoo"))
    with_promptfoo = report.write_all(results, meta, Path("/tmp/redteam-report-with-promptfoo"),
                                      promptfoo_summary=promptfoo.read_summary(FIXTURE))
    assert summary(results) == json.loads(plain["json"].read_text())["summary"]
    attached = json.loads(with_promptfoo["json"].read_text())
    assert attached["summary"] == summary(results)
    assert attached["results"] == json.loads(plain["json"].read_text())["results"]
    assert "Promptfoo eval" not in plain["md"].read_text()
    assert "Promptfoo eval" in with_promptfoo["md"].read_text()


@pytest.mark.parametrize("contents, message", [
    ("{broken", "JSON"),
    (json.dumps({"results": {"version": 3}}), "stats"),
    (json.dumps({"results": {"version": 2, "stats": {}}}), "version 3"),
])
def test_invalid_or_incomplete_export_has_clear_error(tmp_path, contents, message):
    source = tmp_path / "invalid.json"
    source.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        promptfoo.read_summary(source)


def test_cli_runs_mock_target_with_fixture_and_reports_counts(tmp_path):
    srv = mock.server(0, False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/chat"
    out = tmp_path / "out"
    try:
        assert main(["run", "-c", str(_cfg(tmp_path, url)), "-o", str(out), "--only",
                    "instruction_override", "--promptfoo-json", str(FIXTURE), "-q"]) == 1
        md = (out / "report.md").read_text(encoding="utf-8")
        assert "Promptfoo eval (separate scoring)" in md
        assert "7 passed · 2 failed · 1 errors" in md
        assert "SYNTHETIC_" not in md
    finally:
        srv.shutdown()
