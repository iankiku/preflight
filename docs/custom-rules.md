# Writing Custom Rules

ClawSec rules are YAML files with one or more detection patterns. You can extend ClawSec with your own rules to enforce team-specific security policies.

## Quick Start

Create a file called `my-rules.yml`:

```yaml
version: "1.0"
rules:
  - id: CUSTOM-001
    name: hardcoded-database-url
    severity: critical
    category: secrets
    patterns:
      - type: regex
        regex: "postgres://[^\\s]+"
    message: "Hardcoded database URL detected: '{match}'"
    remediation: "Use DATABASE_URL environment variable instead."
```

Run it:

```bash
clawsec scan . --rules ./my-rules.yml
```

## Rule Structure

```yaml
version: "1.0"
rules:
  - id: CLAWSEC-XXX          # Required. Format: CLAWSEC-NNN or CLAWSEC-NNNN
    name: my-rule-name        # Required. Short identifier
    severity: high            # Required. critical | high | medium | low | info
    category: code-execution  # Required. See categories below
    enabled: true             # Optional. Default: true

    patterns:                 # Required. At least one pattern
      - type: regex           # Pattern type (see below)
        regex: "eval\\("
        flags: "i"

    location:                 # Optional. Where to search
      include: [all]          # frontmatter | body | scripts | all

    message: "Found: '{match}'"      # Required. {match} is replaced with the matched text
    remediation: "Use X instead."     # Optional. Fix guidance

    metadata:                 # Optional. Standards mapping
      owasp: "LLM03:2025"
      cwe: "CWE-94"
      references:
        - "https://example.com/advisory"
```

### Categories

| Category | Use for |
|----------|---------|
| `prompt-injection` | Attacks on AI instruction following |
| `data-exfiltration` | Unauthorized data transmission |
| `code-execution` | Dangerous code evaluation patterns |
| `metadata-abuse` | Misuse of skill/agent metadata |
| `secrets` | Hardcoded credentials and keys |
| `supply-chain` | Dependency and build chain risks |
| `misconfiguration` | Insecure configuration settings |

### Rule IDs

IDs must match the format `CLAWSEC-NNN` or `CLAWSEC-NNNN`. For custom rules, use the `CUSTOM-` prefix to avoid collisions with built-in rules:

```yaml
id: CUSTOM-001   # Won't pass schema validation (must be CLAWSEC-XXX)
id: CLAWSEC-900  # OK — use the 900+ range for custom rules
```

---

## Pattern Types

ClawSec supports three pattern engines. Each rule can contain multiple patterns — a finding is created for each individual match.

### 1. Regex Patterns

Match text content using regular expressions.

```yaml
patterns:
  - type: regex
    regex: "eval\\s*\\("
    flags: "im"     # Optional. Default: "im" (case-insensitive, multiline)
```

**Shorthand:** You can omit `type: regex` when using just `regex` and `flags`:

```yaml
patterns:
  - regex: "eval\\s*\\("
    flags: "i"
```

Or use a plain string:

```yaml
patterns:
  - "eval\\("    # Treated as regex with default flags
```

**Flags:**

| Flag | Meaning |
|------|---------|
| `i` | Case-insensitive |
| `m` | Multiline (^ and $ match line boundaries) |
| `s` | Dotall (. matches newlines) |
| `g` | Always added automatically |

**Tips:**
- Escape backslashes in YAML: `\\s` not `\s`
- Use `{match}` in the message to include the matched text
- The `g` flag is always added — every match in the file creates a separate finding
- To match across lines (e.g., in JSON), use `[\\s\\S]*?` instead of `.*`

### 2. Frontmatter Patterns

Check YAML frontmatter fields in files with `---` delimiters.

```yaml
patterns:
  - type: frontmatter
    field: metadata.security.reviewed    # Dot-notation path
    equals: true                         # Check condition
```

**Conditions** (use exactly one):

| Condition | Description | Example |
|-----------|-------------|---------|
| `exists: true` | Field must exist | Check for presence |
| `exists: false` | Field must not exist | Check for absence |
| `equals: <value>` | Exact value match | `equals: true`, `equals: "admin"` |
| `contains: <string>` | String contains substring, or array contains element | `contains: "unsafe"` |
| `matches: <regex>` | Value matches regex (case-insensitive) | `matches: "^v[0-9]+"` |

**Dot notation** traverses nested YAML:

```yaml
# Given this frontmatter:
# ---
# metadata:
#   security:
#     level: public
# ---

patterns:
  - type: frontmatter
    field: metadata.security.level
    equals: public
```

### 3. AST Patterns

Match code structure using tree-sitter queries. More precise than regex for code analysis.

```yaml
patterns:
  - type: ast
    lang: python                    # python | bash | javascript
    query: |
      (call
        function: (identifier) @func
        (#eq? @func "eval")
      )
```

**Supported languages:**

| Language | Grammar | File extensions |
|----------|---------|----------------|
| Python | `tree-sitter-python.wasm` | `.py`, `.pyw` |
| Bash | `tree-sitter-bash.wasm` | `.sh`, `.bash`, `.zsh` |
| JavaScript | `tree-sitter-javascript.wasm` | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |

**Query syntax:** Tree-sitter's S-expression query language. See [tree-sitter query docs](https://tree-sitter.github.io/tree-sitter/using-parsers/queries).

Key predicates:
- `(#eq? @capture "value")` — exact string match
- `(#match? @capture "^regex$")` — regex match
- `(#not-match? @capture "pattern")` — negative regex match

**Example — detect `subprocess.run(shell=True)`:**

```yaml
patterns:
  - type: ast
    lang: python
    query: |
      (call
        function: (attribute
          object: (identifier) @mod
          attribute: (identifier) @fn
        )
        arguments: (argument_list
          (keyword_argument
            name: (identifier) @kwarg
            value: (true) @val
          )
        )
        (#match? @mod "^subprocess$")
        (#match? @fn "^(call|run|Popen)$")
        (#eq? @kwarg "shell")
      )
```

**Tips:**
- If `lang` is omitted, the query runs against all files with a detected language
- AST patterns only run on files where tree-sitter has a grammar
- Queries that fail to compile are silently skipped (check stderr for errors)
- The first capture in a match determines the finding's location

---

## Content Scoping with `location`

Control which parts of a file are searched:

```yaml
location:
  include:
    - frontmatter    # YAML frontmatter only
    - body           # Content after frontmatter (or full file if no frontmatter)
    - scripts        # Code blocks in markdown, or full content of code files
    - all            # Entire file content (default)
```

`scripts` is useful for rules that should only match inside code:

```yaml
# Only match eval() inside code blocks, not in prose
- id: CLAWSEC-009
  name: dangerous-eval
  patterns:
    - regex: "\\beval\\s*\\("
  location:
    include: [scripts]
```

If `location` is omitted, the default is `[all]` — the entire file content is searched.

---

## Multiple Patterns

A rule with multiple patterns creates findings for each pattern that matches. This is useful for catching variations:

```yaml
patterns:
  # Catches Python pickle
  - regex: "pickle\\.loads?\\("
  # Catches marshal (same risk)
  - regex: "marshal\\.loads?\\("
```

Each pattern is independent — they don't need to all match.

---

## File Organization

You can organize rules across multiple YAML files:

```
my-rules/
  auth-rules.yml        # Authentication checks
  api-rules.yml         # API security
  compliance-rules.yml  # Regulatory requirements
```

Load all of them:

```bash
clawsec scan . --rules ./my-rules/auth-rules.yml,./my-rules/api-rules.yml
```

Or load built-in + custom rules together:

```bash
clawsec scan . --rules ./my-rules/auth-rules.yml
# Built-in rules are always included unless you use --enable to filter
```

---

## Testing Custom Rules

Create test fixtures alongside your rules:

```
my-rules/
  auth-rules.yml
  fixtures/
    CLAWSEC-900/
      positive.py      # Should trigger rule
      negative.py      # Should NOT trigger rule
```

Then validate with `test-rules`:

```bash
clawsec test-rules
```

The test runner checks:
- **Positive:** At least one finding with the expected rule ID
- **Negative:** Zero findings with the expected rule ID

---

## Disabling Built-in Rules

```bash
# Disable specific rules
clawsec scan . --disable CLAWSEC-005,CLAWSEC-008

# Enable only specific rules
clawsec scan . --enable CLAWSEC-014,CLAWSEC-015
```

Or set `enabled: false` in the rule YAML:

```yaml
rules:
  - id: CLAWSEC-005
    enabled: false
    # ... rest of rule
```
