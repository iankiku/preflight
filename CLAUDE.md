# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build          # Build with tsup (ESM bundle → dist/cli.js)
npm run dev            # Run CLI via tsx without building
npm test               # Run all tests (node --test --import tsx)
npm test -- tests/skills-scope.test.ts   # Run a single test file
npm run test-rules     # Validate all rules against positive/negative fixtures
npm run scan           # Run a scan (uses dist/)
npm run rules          # List all loaded rules
```

## Architecture

Pipeline: `discover → analyze → deduplicate → score → report`

**Entry point:** `src/cli.ts` — CLI arg parsing, config loading, pipeline orchestration, dashboard server. This is a single large file (~1600 lines) that handles all commands: `init`, `scan`, `dashboard`, `rules`, `test-rules`.

**Pipeline modules:**

- `src/discover.ts` — File walker. Respects `.gitignore`, `.preflightignore`, and hardcoded ignore list. Default mode scans only `skills.md`/`SKILLS.MD` files; `--all-files` overrides this.
- `src/analyze.ts` — Router that dispatches files to three analyzers based on rule pattern types (regex, frontmatter, ast).
- `src/analyzers/pattern.ts` — Regex matching. Supports content regions (frontmatter, body, scripts/code blocks in markdown). Uses remark to extract code blocks from markdown for `scripts` location.
- `src/analyzers/frontmatter.ts` — YAML frontmatter field checks (exists, equals, contains, matches). Supports dot-notation field paths.
- `src/analyzers/ast.ts` — Tree-sitter queries via `web-tree-sitter` WASM. Grammars live in `src/grammars/`. Supports Python, Bash, JavaScript.
- `src/deduplicate.ts` — Dedup by `ruleId:file:line`, then sort by severity.
- `src/score.ts` — Score starts at 100, deducts per finding (critical: -15, high: -8, medium: -3, low: -1, info: 0).

**Rules system:**

- Built-in rules: `src/rules/builtin/*.yml` (7 YAML files covering prompt-injection, data-exfiltration, code-execution, mcp-security, metadata-abuse, secrets).
- Schema/validation: `src/rules/schema.ts` — Zod schemas. Rule IDs must match `PREFLIGHT-XXX` or `PREFLIGHT-XXXX`.
- Loader: `src/rules/loader.ts` — Loads builtin + custom YAML rules, applies enable/disable filters.
- Fixtures: `src/rules/fixtures/PREFLIGHT-XXX/` — Each rule has `positive.*` (should trigger) and `negative.*` (should not trigger) test files. The `test-rules` command validates all fixtures.

**Reporters:** `src/reporters/` — table (terminal), json, sarif (GitHub/GitLab code scanning), dashboard (standalone HTML), agent (structured JSON + markdown for AI agents).

**Types:** `src/types.ts` — Core type definitions (FileEntry, Rule, Pattern, Finding, ScanResult, etc.).

**Utilities:** `src/utils.ts` — ANSI colors (respects `NO_COLOR`), terminal output sanitization, frontmatter parsing, file classification, line/column helpers.

## Key Conventions

- ESM-only (`"type": "module"` in package.json). All internal imports use `.js` extensions.
- Built with tsup: single entry `src/cli.ts` → `dist/cli.js` with shebang. External deps resolved from node_modules at runtime.
- Tests use Node.js built-in test runner (`node:test` + `node:assert/strict`). No test framework dependency.
- Rule patterns support a shorthand: a plain string in the `patterns` array is treated as a regex pattern.
- Rules can have `requiresContext` (secondary regex gate) and `perFileLimit` (at most one finding per file).
- The `location.include` field on rules controls which content regions are searched: `all`, `frontmatter`, `body`, `scripts`.
- Config lives in `.preflight/settings.json`. CLI flags override config values.
- Dashboard server binds to `127.0.0.1` by default and serves from `.preflight/scans/`.
