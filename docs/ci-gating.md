# Gating a release on redteam-check in CI

redteam-check writes `junit.xml` next to the HTML report, and `redteam-check run` exits with a code your pipeline
can act on:

| Exit code | Meaning | Gate |
|---|---|---|
| 0 | No attack worked. "Review" items may still exist (they need a human decision, they do not block). | pass |
| 1 | At least one attack worked (`fail`), or an attack got no reply (`error`). | block |
| 2 | Setup problem: config or pack could not be loaded, `--repeat` below 1, or filters left no attacks. | block (fix the job) |

In `junit.xml` every attack is one test case: `fail` becomes `<failure>` (message: which check fired and, with
`--repeat`, in how many runs), `error` becomes `<error>`, `pass` and `review` are passing tests. The CI test tab then
shows exactly which attacks got through.

## Before you wire it in

- Point it at a **staging** endpoint that you own or have written permission to test, never production.
- Put a canary string in the staging system prompt and list it under `[context] canaries`.
- Keep tokens in the CI secret store; the config reads them from the environment (`${TARGET_TOKEN}`).
- LLM replies vary. For a gate, use `--repeat 3` (or more): an attack that works once in three runs still fails the
  gate, and the report shows its success rate.
- Start narrow if the first run is red everywhere: gate on the areas you have fixed (`--only prompt_leak,data_exposure`)
  and widen as fixes land.

Example config committed to your repository as `redteam/staging.toml`:

```toml
[target]
url = "https://staging.example.com/api/chat"
headers = { Authorization = "Bearer ${TARGET_TOKEN}" }
body = '{"message": "{{prompt}}", "session": "redteam-ci"}'
response_path = "data.reply"
timeout = 30
delay = 0.5

[context]
product = "Acme Invoicing"
canaries = ["RTC-CANARY-4417"]
allowed_domains = ["acme.example"]
```

The wheel (`redteam_check-<version>-py3-none-any.whl`) is delivered with the engagement; commit it under
`redteam/` or host it in your internal package index. Add `[yaml]` (`redteam_check-...whl[yaml]`) if you use
private packs in YAML.

## GitHub Actions

```yaml
# .github/workflows/redteam.yml
name: redteam
on:
  pull_request:
  workflow_dispatch:

jobs:
  redteam:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write          # lets the JUnit step publish a check with per-attack results
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install redteam/redteam_check-0.2.0-py3-none-any.whl

      - name: Red-team the staging assistant
        id: redteam
        env:
          TARGET_TOKEN: ${{ secrets.STAGING_CHAT_TOKEN }}
        run: redteam-check run -c redteam/staging.toml -o redteam-report --repeat 3 -q

      # Runs even when the gate failed, so the reviewer sees which attacks got through.
      - name: Publish attack results
        if: always()
        uses: mikepenz/action-junit-report@v4
        with:
          report_paths: redteam-report/junit.xml
          check_name: AI red-team check
      - name: Keep the reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: redteam-report
          path: redteam-report/
```

The `redteam` step fails the job on exit code 1 or 2, which blocks the merge when the job is a required status
check (Settings → Branches → branch protection). `report.html` in the uploaded artifact is the page for the product
owner: risk level, the three most critical findings and how often they repeat are on the first screen.

To report without blocking for a while (for example during the first week), add `continue-on-error: true` to the
`redteam` step; results are still published.

## Azure DevOps

```yaml
# azure-pipelines.yml (or a stage in your existing pipeline)
trigger: none
pr:
  branches:
    include: [main]

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: pip install redteam/redteam_check-0.2.0-py3-none-any.whl
    displayName: Install redteam-check

  - script: redteam-check run -c redteam/staging.toml -o $(Build.ArtifactStagingDirectory)/redteam --repeat 3 -q
    displayName: Red-team the staging assistant
    env:
      TARGET_TOKEN: $(STAGING_CHAT_TOKEN)   # secret pipeline variable; secrets must be mapped explicitly

  # Runs even when the gate failed; failed attacks show up in the Tests tab.
  - task: PublishTestResults@2
    condition: always()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: $(Build.ArtifactStagingDirectory)/redteam/junit.xml
      testRunTitle: AI red-team check
      failTaskOnFailedTests: true
  - task: PublishPipelineArtifact@1
    condition: always()
    inputs:
      targetPath: $(Build.ArtifactStagingDirectory)/redteam
      artifact: redteam-report
```

The script step fails the run on exit code 1 or 2; `failTaskOnFailedTests` makes the publish step fail too, so the
gate holds even if someone later sets `continueOnError` on the run step. Add the pipeline as a build validation policy
on the target branch to block pull requests.

## Reading a red gate

1. Open `report.html` from the artifact. The summary at the top gives the risk level, the three most critical findings
   and their repeat rate.
2. Each finding shows the attack, the reply and a fix for that area.
3. After the fix, re-run with the same `--repeat`. A finding that now fails in 0 of N runs is closed; one that drops
   from 3/3 to 1/3 is not.

A green gate means none of the attacks in the pack worked against staging on this run. It does not prove the
assistant is safe: multi-turn and document-borne (indirect) injection need a tailored test.
