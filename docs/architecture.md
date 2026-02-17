# Architecture

Preflight is a 4-stage pipeline scanner built as a single Node.js CLI tool.

```
discover → analyze → deduplicate → report
```

## Pipeline Overview

```
                          ┌─────────────────┐
                          │     CLI (cli.ts) │
                          │   arg parsing    │
                          │   orchestration  │
                          └────────┬─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼               ▼
             ┌────────────┐ ┌──────────┐  ┌─────────────┐
             │  discover   │ │  rules   │  │  reporters   │
             │  (files)    │ │  (YAML)  │  │  (output)    │
             └─────┬──────┘ └────┬─────┘  └──────────────┘
                   │             │
                   ▼             ▼
             ┌────────────────────────┐
             │      analyze.ts        │
             │    (pipeline router)   │
             └───┬──────┬──────┬─────┘
                 │      │      │
                 ▼      ▼      ▼
           ┌────────┐┌────────┐┌────────┐
           │ regex  ││ front- ││  AST   │
           │pattern ││ matter ││treesit │
           └────────┘└────────┘└────────┘
                 │      │      │
                 └──────┴──────┘
                        │
                        ▼
              ┌──────────────────┐
              │   deduplicate    │
              │   + score        │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │    reporters     │
              │ table/json/sarif │
              │ /dashboard       │
              └──────────────────┘
```

## Stage 1: Discover (`discover.ts`)

Walks a directory tree and produces `FileEntry[]` objects.

**Input:** A file path or directory path.

**Process:**
1. If path is a single file, build one `FileEntry` and return
2. If directory, use `glob('**/*')` with ignore patterns
3. Only include files named `skills.md` / `SKILLS.MD` (unless `--all-files` is used)
4. Read `.gitignore` from scan root and merge with defaults
5. Skip binary files, files > 1MB, and excluded extensions
6. For each file:
   - Read content as UTF-8
   - Detect YAML frontmatter (`---` delimited)
   - Parse frontmatter with the `yaml` package
   - Classify language by extension (`.py` → `python`, `.sh` → `bash`, `.js/.ts` → `javascript`)
7. Return array of `FileEntry` objects

**FileEntry shape:**
```typescript
interface FileEntry {
  path: string;              // Absolute path
  relativePath: string;      // Relative to scan root
  content: string;           // Full file content
  extension: string;         // .md, .py, .js, etc.
  hasFrontmatter: boolean;   // YAML frontmatter detected
  frontmatter?: Record<string, unknown>;
  rawFrontmatter?: string;
  body?: string;             // Content after frontmatter
  language?: string;         // python, bash, javascript
}
```

**Default ignore patterns:** `node_modules`, `.git`, `dist`, `build`, `.next`, `__pycache__`, `.venv`, `coverage`, `.nyc_output`

## Stage 2: Analyze (`analyze.ts`)

Routes files to three analysis engines based on rule pattern types.

**Input:** `FileEntry[]` + `Rule[]`

**Routing logic:**
```
regex patterns    → runPatternRules(all files, regex rules)
frontmatter pats  → runFrontmatterRules(files with frontmatter, fm rules)
AST patterns      → runAstRules(files with language, AST rules)
```

### Pattern Analyzer (`analyzers/pattern.ts`)

Runs regex patterns against file content.

**Content regions:** Each rule can scope its search with `location.include`:
- `all` — full file content
- `frontmatter` — raw YAML frontmatter
- `body` — content after frontmatter
- `scripts` — for `.md` files, parses markdown with `remark-parse` to extract code blocks. For code files (`.py`, `.sh`, `.js`), uses the full content.

Each region carries its byte offset within the full file for accurate line/column reporting.

**Matching:** Runs `RegExp.exec()` in a loop with `g` flag. Default flags are `im` (case-insensitive, multiline). The `{match}` placeholder in messages is replaced with the matched text (capped at 100 chars).

### Frontmatter Analyzer (`analyzers/frontmatter.ts`)

Checks YAML frontmatter fields using dot-notation traversal.

**Conditions:** `exists`, `equals`, `contains` (string or array), `matches` (regex).

Only processes files where `hasFrontmatter` is `true`.

### AST Analyzer (`analyzers/ast.ts`)

Runs tree-sitter queries against parsed syntax trees.

**Process:**
1. Initialize tree-sitter WASM runtime (once)
2. Load grammar for the file's language (cached per language)
3. Parse file content into AST
4. For each AST pattern, compile the query and run against the root node
5. Each match capture becomes a finding with precise line/column from the AST node

**Supported grammars:** Python, Bash, JavaScript (WASM files shipped at `src/grammars/`).

**Graceful degradation:** Missing grammars and invalid queries are logged to stderr and skipped — they never crash the scan.

## Stage 3: Deduplicate (`deduplicate.ts`)

Removes duplicate findings and sorts by severity.

**Dedup key:** `${ruleId}:${file}:${startLine}` — same rule, same file, same line = one finding.

**Sort order:** Critical first, then high, medium, low, info. Within same severity, alphabetical by file, then by line number.

## Stage 4: Score (`score.ts`)

Calculates a security score from 0 to 100.

```
score = max(0, 100 - sum(penalties))

Penalties: critical=-15, high=-8, medium=-3, low=-1, info=0
```

## Stage 5: Report

Four output formatters, all pure functions:

| Reporter | Function | Output |
|----------|----------|--------|
| `table.ts` | `formatTable(result)` | Colored terminal output |
| `json.ts` | `formatJson(result)` | `JSON.stringify(result, null, 2)` |
| `sarif.ts` | `formatSarif(result, rules)` | SARIF 2.1.0 JSON |
| `dashboard.ts` | `formatDashboard(result)` | Self-contained HTML |

The dashboard reporter reads `src/dashboard.html` and replaces the `__PREFLIGHT_DATA__` placeholder with the scan result JSON.

**Dashboard server:** `preflight dashboard` serves the report locally and binds to `127.0.0.1` only. Static assets are copied to `.preflight/scans/assets/`.

## Rule System

### Schema (`rules/schema.ts`)

Rules are validated with Zod schemas. The schema handles three pattern types (regex, frontmatter, AST), string shorthand for regex, and optional `type: regex` default.

### Loader (`rules/loader.ts`)

Loads YAML files from:
1. Built-in rules at `src/rules/builtin/*.yml` (7 files, 25 rules)
2. Custom rule files via `--rules` flag

Rules can be filtered with `--enable` (whitelist) or `--disable` (blacklist).

### Rule Files

```
src/rules/builtin/
  prompt-injection.yml     # PREFLIGHT-001 to 005
  data-exfiltration.yml    # PREFLIGHT-006 to 008
  code-execution.yml       # PREFLIGHT-009 to 011, 030 to 032
  metadata-abuse.yml       # PREFLIGHT-012 to 013
  secrets.yml              # PREFLIGHT-014 to 015
  mcp-security.yml         # PREFLIGHT-050 to 052
  ast.yml                  # PREFLIGHT-500, 501, 510, 520
```

## Build System

- **tsup** bundles `src/cli.ts` → `dist/cli.js` (ESM, Node 20 target)
- Dependencies are externalized (resolved from `node_modules` at runtime)
- Static assets (YAML rules, WASM grammars, HTML template) are shipped in `src/` and resolved relative to the package root

## Directory Structure

```
preflight/
  dist/cli.js                  # Built CLI entry point (38KB)
  src/
    cli.ts                     # CLI orchestrator
    types.ts                   # TypeScript types
    utils.ts                   # Colors, helpers
    discover.ts                # File walker
    analyze.ts                 # Pipeline router
    deduplicate.ts             # Finding dedup
    score.ts                   # Score calculation
    dashboard.html             # HTML template
    analyzers/
      pattern.ts               # Regex engine
      frontmatter.ts           # YAML field checker
      ast.ts                   # Tree-sitter engine
    reporters/
      table.ts                 # Terminal output
      json.ts                  # JSON output
      sarif.ts                 # SARIF 2.1.0
      dashboard.ts             # HTML injection
    rules/
      schema.ts                # Zod validation
      loader.ts                # YAML loader
      builtin/                 # 7 rule files (25 rules)
      fixtures/                # 25 test dirs (50 files)
    grammars/                  # Tree-sitter WASM files
      tree-sitter-python.wasm
      tree-sitter-bash.wasm
      tree-sitter-javascript.wasm
  package.json
  tsconfig.json
  tsup.config.ts
```
