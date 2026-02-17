# Preflight

Security scanner focused on `skills.md` / `SKILLS.MD` files by default.

## What It Solves

Preflight focuses on AI‑specific security risks inside skill files that general SAST tools miss:

- Prompt injection, jailbreaks, role hijacking, system prompt leaks
- Data exfiltration patterns (webhooks, curl pipes, env + network)
- Unsafe code execution patterns (eval, exec, shell=True)
- MCP misconfiguration and metadata abuse
- Hardcoded secrets and private keys

## How It Works

Pipeline:

```
discover → analyze → deduplicate → score/report
```

- **Discover:** Walks files, parses frontmatter, detects languages
- **Analyze:** Regex rules, frontmatter rules, and AST rules (tree‑sitter)
- **Deduplicate:** One finding per rule/file/line
- **Report:** Table, JSON, SARIF, and HTML dashboard

## Quick Start

```bash
npx preflight scan .
```

## Installation

```bash
npm install -g preflight
```

Or as a dev dependency:

```bash
npm install -D preflight
```

## Usage

Scan current directory (only `skills.md` / `SKILLS.MD` are analyzed by default):

```bash
preflight scan .
```

Output JSON:

```bash
preflight scan . --format json
```

SARIF for code scanning:

```bash
preflight scan . --format sarif -o results.sarif
```

Fail CI on critical findings:

```bash
preflight scan . --fail-on critical
```

Use custom rules:

```bash
preflight scan . --rules ./my-rules.yml
```

Scan all files (override skills‑only mode):

```bash
preflight scan . --all-files
```

## Dashboard

Serve the local HTML dashboard:

```bash
preflight dashboard
```

Bind to a custom host:

```bash
preflight dashboard --host 0.0.0.0 --port 7700
```

Dashboard assets are bundled locally in `.preflight/scans/assets/` (no CDNs).

## Configuration

Create a project config:

```bash
preflight init
```

This writes:

- `.preflight/settings.json` for defaults
- `.preflight/scans/` for reports

You can also set `scan.onlySkills` in `.preflight/settings.json`:

- `true` (default): only `skills.md` / `SKILLS.MD`
- `false`: scan all files

Ignore paths:

- `.gitignore` and `.preflightignore` are respected

Suppress findings:

- `.preflight/suppressions.json` (rule ID + file path)

## Outputs

- **Table:** human‑readable terminal output
- **JSON:** full machine‑readable results
- **SARIF:** GitHub/GitLab code scanning
- **Dashboard:** standalone HTML report

## Security Model (Short)

Trust boundaries:

- The repo being scanned may be untrusted
- Reports can contain sensitive snippets

Defaults:

- Dashboard binds to `127.0.0.1`
- Symlinks are skipped; files outside scan root are excluded
- Terminal output is sanitized for control sequences
- Only `skills.md` / `SKILLS.MD` are scanned (use `--all-files` to override)

Limitations:

- Default scope is `skills.md` / `SKILLS.MD`
- AST coverage is Python/Bash/JavaScript only
- No data‑flow or taint analysis

## FAQ

Does it scan non‑skills files like `.env` or `README.md`?

Not by default. Use `--all-files` (or set `scan.onlySkills: false`) to include everything.

Does it follow symlinks?

No. Symlinks are skipped and outside‑root paths are excluded.

Is the dashboard remote‑accessible?

No. It binds to `127.0.0.1` by default.

## Roadmap: 10% → 90% Accuracy

Preflight currently has a high false-positive rate due to broad pattern matching and limited context awareness. The roadmap below targets 90%+ precision and recall.

### Phase 1: Reduce False Positives

- **Negative lookahead/lookbehind in rules** — Allow rules to exclude known-safe patterns (e.g., `curl` in a comment vs. `curl` piping to `sh`). Add `excludePatterns` field to rule schema.
- **Context-weighted matching** — Findings inside code blocks, executable regions, or frontmatter `run` fields should score higher than matches in prose/comments/documentation.
- **Confidence scoring per finding** — Replace binary match/no-match with a confidence value (0.0-1.0) based on pattern specificity, context, and co-occurring signals. Filter output by confidence threshold.
- **Expand negative test fixtures** — Every rule must have robust negative cases covering common false-positive scenarios. Target: 5+ negative cases per rule.

### Phase 2: Reduce False Negatives

- **Multi-signal rule composition** — Rules that require 2+ co-occurring patterns before firing (e.g., `env` access + network call in the same file = exfiltration, but either alone is benign).
- **Obfuscation detection** — Detect base64-encoded URLs, string concatenation to build shell commands, hex-encoded payloads, and template literal injection.
- **Expand AST grammars** — Add TypeScript, Ruby, Go, and Rust tree-sitter grammars. TypeScript is highest priority given the AI/agent ecosystem.
- **Cross-block analysis in markdown** — Correlate findings across multiple code blocks within the same skill file (e.g., a variable defined in one block and exfiltrated in another).

### Phase 3: Semantic Analysis

- **Intra-file data flow** — Track how variables flow from source (user input, env vars, secrets) to sink (network calls, exec, file writes) within a single file.
- **Taint propagation for frontmatter** — If a frontmatter field feeds into a code block via templating, flag the full chain.
- **LLM-assisted rule tuning** — Use scan results + human feedback to auto-tune regex specificity and confidence thresholds.

### Phase 4: Ecosystem & Coverage

- **CLAUDE.md / .cursorrules / .github/copilot-instructions.md scanning** — Extend default scope beyond `skills.md` to cover all AI agent instruction files.
- **MCP server manifest analysis** — Parse and validate MCP tool definitions for overly broad permissions, missing auth, and unsafe defaults.
- **CI/CD integration hardening** — GitHub Action, GitLab CI template, and pre-commit hook with incremental scanning (only changed files).
- **Community rule registry** — Allow publishing/consuming shared rule packs for specific frameworks (LangChain, CrewAI, Claude Agent SDK).

## Documentation

- [Rule Reference](docs/rules.md)
- [Custom Rules](docs/custom-rules.md)
- [Integrations](docs/integrations.md)
- [Changelog](CHANGELOG.md)

## License

MIT

## Author

Ian Kiku
