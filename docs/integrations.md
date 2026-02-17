# CI/CD Integrations

Preflight is designed for CI pipelines. Key features:

- `--format sarif` for GitHub Code Scanning
- `--fail-on <severity>` for gate checks
- `--score-threshold <n>` for quality gates
- `--quiet` for exit-code-only mode
- Non-zero exit codes on policy violations
- By default, only `skills.md` / `SKILLS.MD` are scanned (use `--all-files` to override)

## GitHub Actions

### Basic scan with SARIF upload

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  preflight:
    runs-on: ubuntu-latest
    permissions:
      security-events: write    # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Preflight
        run: npx preflight scan . --format sarif -o results.sarif --fail-on critical

      - name: Upload SARIF to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

This uploads findings directly to GitHub's **Security > Code scanning alerts** tab.

### Score-based quality gate

```yaml
      - name: Run Preflight
        run: npx preflight scan . --score-threshold 70 --format table
```

Fails the build if the security score drops below 70.

### PR comment with JSON

```yaml
      - name: Run Preflight
        id: scan
        run: |
          npx preflight scan . --format json -o preflight-results.json
          SCORE=$(node -e "console.log(JSON.parse(require('fs').readFileSync('preflight-results.json','utf8')).score)")
          echo "score=$SCORE" >> $GITHUB_OUTPUT

      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `## Preflight Security Score: ${{ steps.scan.outputs.score }}/100`
            })
```

## GitLab CI

```yaml
preflight:
  image: node:20
  stage: test
  script:
    - npx preflight scan . --format sarif -o gl-sast-report.sarif --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    when: always
  allow_failure: false
```

GitLab reads SARIF files as SAST reports, displaying findings in merge request security widgets.

## Azure DevOps

```yaml
- task: NodeTool@0
  inputs:
    versionSpec: '20.x'

- script: npx preflight scan . --format sarif -o $(Build.ArtifactStagingDirectory)/preflight.sarif --fail-on high
  displayName: 'Run Preflight'
  continueOnError: true

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: $(Build.ArtifactStagingDirectory)/preflight.sarif
    ArtifactName: CodeAnalysis
```

## Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: Security Scan
        image: node:20
        script:
          - npx preflight scan . --fail-on high --format table
```

## Pre-commit Hook

Add to `.git/hooks/pre-commit` or use [pre-commit](https://pre-commit.com/):

```bash
#!/bin/sh
npx preflight scan . --fail-on critical --quiet
```

This blocks commits that introduce critical findings.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no policy violations |
| 1 | Policy violation: findings above `--fail-on` severity, or score below `--score-threshold` |
| 2 | Error: invalid arguments, missing files, rule loading failure |

## CLI Flags for CI

| Flag | Description |
|------|-------------|
| `--format sarif` | SARIF 2.1.0 output for code scanning integrations |
| `--format json` | Machine-readable JSON with full scan results |
| `-o <file>` | Write output to file (stdout still shows progress on stderr) |
| `--fail-on <severity>` | Exit 1 if any finding at or above severity level |
| `--score-threshold <n>` | Exit 1 if security score is below n |
| `--quiet` | Suppress all output except exit code |
| `--severity <level>` | Only include findings at or above severity |
| `--enable <ids>` | Run only these rules (comma-separated) |
| `--disable <ids>` | Skip these rules (comma-separated) |
| `--rules <files>` | Load additional custom rule files |

## SARIF Output

Preflight generates [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) — the industry standard for static analysis tools.

The SARIF output includes:
- **Tool metadata:** Preflight version and information URI
- **Rule definitions:** Each triggered rule as a `reportingDescriptor` with ID, name, description, CWE helpUri, and category tags
- **Results:** Each finding with rule reference, severity level, message, file location (path, line, column), and code snippet
- **Custom properties:** `preflight-score` on the run object

Severity mapping:

| Preflight Severity | SARIF Level |
|-----------------|-------------|
| Critical | `error` |
| High | `error` |
| Medium | `warning` |
| Low | `note` |
| Info | `note` |
