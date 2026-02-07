# ClawSec

**Security scanner for AI — prompts, skills, agents, vibecoded projects.**

## 🚀 Quick Start

Run it instantly in your project:

```bash
npx clawsec
```

You'll get a security score and a list of risks immediately:

```
  ClawSec Security Score: 72/100
  ████████░░

   3 critical  ██░░░░░░░░
   5 high      ███░░░░░░░
  12 medium    ██████░░░░

  Top risks:
  CLAWSEC-004   jailbreak-patterns              src/prompts/system.md:14
  CLAWSEC-014   api-key-exposure                config/settings.yaml:8
  CLAWSEC-032   sql-injection                   scripts/migrate.py:23
```

## ✨ What it Does

ClawSec scans your AI projects for 25+ specific security risks:

*   **Prompt Injection**: Jailbreaks, leaks, and overrides.
*   **Secrets**: Exposed API keys and tokens.
*   **Code Execution**: Dangerous `eval`, `exec`, and unsafe shell commands.
*   **Data Exfiltration**: Silent webhooks and data pipes.
*   **MCP Security**: Unvalidated Model Context Protocol inputs.

## 📦 Installation

Install globally to use it anywhere:

```bash
npm install -g clawsec
```

## 🛠️ Usage

**Scan current directory:**
```bash
clawsec
```

**Scan a specific folder:**
```bash
clawsec ./my-agent
```

**Output JSON results:**
```bash
clawsec scan . --format json
```

**CI/CD Mode (Exit on failure):**
```bash
clawsec scan . --fail-on critical
```

## 🤖 CI/CD Integration

Add to **GitHub Actions** to secure every commit:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
- run: npx clawsec scan . --fail-on high
```

## 📄 Documentation

*   [Rule Reference](docs/rules.md)
*   [Custom Rules](docs/custom-rules.md)
*   [Integrations](docs/integrations.md)

---

**Made with love by Ian Kiku**
