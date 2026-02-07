/**
 * ClawSec CLI Entry Point
 * Pipeline orchestrator: config → arg parsing → discovery → analysis → reporting
 */

import { readFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { writeFile, readdir } from 'node:fs/promises';
import { exec } from 'node:child_process';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { discoverFiles } from './discover.js';
import { loadRules } from './rules/loader.js';
import { analyze } from './analyze.js';
import { deduplicate } from './deduplicate.js';
import { calculateScore } from './score.js';
import { formatTable } from './reporters/table.js';
import { formatJson } from './reporters/json.js';
import { formatSarif } from './reporters/sarif.js';
import { formatDashboard } from './reporters/dashboard.js';
import { formatAgentJson, formatAgentMarkdown } from './reporters/agent.js';
import { isSeverityAtLeast, c, severityColor } from './utils.js';
import { isInteractive, link, fileUrl } from './ui.js';
import * as p from '@clack/prompts';
import type { ScanResult, ScanOptions, Severity, Rule, Suppression, SuppressionsFile, Finding } from './types.js';

// ============================================================================
// Version
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, '../package.json'), 'utf-8'));
const VERSION: string = pkg.version;

// ============================================================================
// Config File
// ============================================================================

const CLAWSEC_DIR = '.clawsec';
const SETTINGS_FILENAME = 'settings.json';
const SCANS_DIR = 'scans';

interface ClawSecConfig {
  scan?: {
    paths?: string[];
    ignore?: string[];
    severity?: Severity;
    severities?: Severity[];
    format?: 'table' | 'json' | 'sarif' | 'agent';
  };
  rules?: {
    disable?: string[];
    enable?: string[];
    custom?: string[];
  };
  output?: {
    file?: string;
    dashboard?: boolean;
  };
  ci?: {
    failOn?: Severity;
    scoreThreshold?: number;
  };
}

function clawsecDir(cwd: string): string {
  return path.resolve(cwd, CLAWSEC_DIR);
}

function settingsPath(cwd: string): string {
  return path.join(clawsecDir(cwd), SETTINGS_FILENAME);
}

function scansDir(cwd: string): string {
  return path.join(clawsecDir(cwd), SCANS_DIR);
}

function loadConfig(cwd: string): ClawSecConfig | null {
  const cfgPath = settingsPath(cwd);
  if (!existsSync(cfgPath)) return null;
  try {
    const raw = readFileSync(cfgPath, 'utf-8');
    return JSON.parse(raw) as ClawSecConfig;
  } catch (e) {
    process.stderr.write(`${c.yellow('warning:')} Failed to parse ${CLAWSEC_DIR}/${SETTINGS_FILENAME}: ${e instanceof Error ? e.message : e}\n`);
    return null;
  }
}

// ============================================================================
// Suppressions
// ============================================================================

const SUPPRESSIONS_FILENAME = 'suppressions.json';

function suppressionsPath(cwd: string): string {
  return path.join(clawsecDir(cwd), SUPPRESSIONS_FILENAME);
}

function loadSuppressions(cwd: string): Suppression[] {
  const filePath = suppressionsPath(cwd);
  if (!existsSync(filePath)) return [];
  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as SuppressionsFile;
    if (!Array.isArray(parsed.suppressions)) return [];
    return parsed.suppressions;
  } catch (e) {
    process.stderr.write(
      `${c.yellow('warning:')} Failed to parse ${CLAWSEC_DIR}/${SUPPRESSIONS_FILENAME}: ${e instanceof Error ? e.message : e}\n`,
    );
    return [];
  }
}

function normalizeFindingPath(filePath: string, cwd: string): string {
  if (path.isAbsolute(filePath)) {
    return path.relative(cwd, filePath);
  }
  return filePath;
}

function applySuppressions(
  findings: Finding[],
  suppressions: Suppression[],
  cwd: string,
): { active: Finding[]; suppressedCount: number } {
  if (suppressions.length === 0) {
    return { active: findings, suppressedCount: 0 };
  }

  const suppressionKeys = new Set(
    suppressions.map((s) => `${s.ruleId}::${s.file}`),
  );

  const active: Finding[] = [];
  let suppressedCount = 0;

  for (const finding of findings) {
    const relPath = normalizeFindingPath(finding.location.file, cwd);
    const key = `${finding.ruleId}::${relPath}`;
    if (suppressionKeys.has(key)) {
      suppressedCount++;
    } else {
      active.push(finding);
    }
  }

  return { active, suppressedCount };
}

// ============================================================================
// Help Text
// ============================================================================

const HELP = `
${c.bold('ClawSec')} — Security scanner for AI

${c.bold('USAGE')}
  clawsec                          Quick start guide
  clawsec init                     Set up .clawsec/ in this project
  clawsec scan [path] [options]    Run a security scan
  clawsec dashboard                Serve scan results on local server
  clawsec rules                    List available security rules
  clawsec test-rules               Validate all rules against fixtures
  clawsec help                     Show this help

${c.bold('OPTIONS')}
  -f, --format <fmt>        Output format: table, json, sarif, agent (default: table)
  -o, --output <file>       Write results to file instead of .clawsec/scans/
  -s, --severity <level>    Minimum severity: critical, high, medium, low, info
  --fail-on <level>         Exit code 1 if findings at/above severity
  --score-threshold <n>     Exit code 1 if score below n
  --exclude <patterns>      Exclude paths (comma-separated globs, e.g. "docs/**,tests/**")
  -e, --enable <ids>        Enable only these rules (comma-separated)
  -d, --disable <ids>       Disable these rules (comma-separated)
  -r, --rules <files>       Additional rule files (comma-separated)
  --no-config               Ignore .clawsec/settings.json
  --no-output               Don't write scan results to disk
  -p, --port <n>            Dashboard server port (default: 7700)
  --quiet                   Suppress output except exit code
  -h, --help                Show this help
  -v, --version             Show version

${c.bold('CONFIG')}
  Run ${c.cyan('clawsec init')} to create .clawsec/ with default settings.
  CLI flags override settings.json values.

${c.bold('FILES')}
  .clawsec/
    settings.json            Configuration
    scans/                   Scan results (JSON + HTML)

${c.bold('INSTALL')}
  npm install clawsec -g     Global install
  npm install clawsec -D     Project dev dependency
`.trim();

// ============================================================================
// Arg Parsing
// ============================================================================

const KNOWN_COMMANDS = new Set(['init', 'scan', 'dashboard', 'rules', 'test-rules', 'help']);

interface ParsedArgs {
  command: 'init' | 'scan' | 'dashboard' | 'rules' | 'test-rules' | 'help' | 'default';
  paths: string[];
  format?: 'table' | 'json' | 'sarif' | 'agent';
  output?: string;
  minSeverity?: Severity;
  severities?: Severity[];
  failOn?: Severity;
  scoreThreshold?: number;
  excludePatterns?: string[];
  enableRules?: string[];
  disableRules?: string[];
  ruleFiles?: string[];
  port: number;
  quiet: boolean;
  help: boolean;
  version: boolean;
  noConfig: boolean;
  noOutput: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const result: ParsedArgs = {
    command: 'default',
    paths: [],
    port: 7700,
    quiet: false,
    help: false,
    version: false,
    noConfig: false,
    noOutput: false,
  };

  let i = 0;

  // Check first positional for command
  if (i < argv.length && KNOWN_COMMANDS.has(argv[i])) {
    result.command = argv[i] as ParsedArgs['command'];
    i++;
  }

  while (i < argv.length) {
    const arg = argv[i];

    switch (arg) {
      case '-h':
      case '--help':
        result.help = true;
        break;
      case '-v':
      case '--version':
        result.version = true;
        break;
      case '--quiet':
        result.quiet = true;
        break;
      case '--no-config':
        result.noConfig = true;
        break;
      case '--no-output':
        result.noOutput = true;
        break;
      case '-f':
      case '--format': {
        const val = argv[++i];
        if (val === 'json' || val === 'sarif' || val === 'table' || val === 'agent') {
          result.format = val;
        } else {
          process.stderr.write(`Unknown format: ${val}. Use table, json, sarif, or agent.\n`);
          process.exit(2);
        }
        break;
      }
      case '-o':
      case '--output':
        result.output = argv[++i];
        break;
      case '-s':
      case '--severity':
        result.minSeverity = parseSeverity(argv[++i]);
        break;
      case '--fail-on':
        result.failOn = parseSeverity(argv[++i]);
        break;
      case '--score-threshold':
        result.scoreThreshold = Number(argv[++i]);
        break;
      case '--exclude':
        result.excludePatterns = argv[++i].split(',').map(p => p.trim());
        break;
      case '-e':
      case '--enable':
        result.enableRules = argv[++i].split(',');
        break;
      case '-d':
      case '--disable':
        result.disableRules = argv[++i].split(',');
        break;
      case '-r':
      case '--rules':
        result.ruleFiles = argv[++i].split(',');
        break;
      case '-p':
      case '--port':
        result.port = Number(argv[++i]);
        break;
      default:
        if (arg.startsWith('-')) {
          process.stderr.write(`Unknown flag: ${arg}\n`);
          process.exit(2);
        }
        result.paths.push(arg);
        break;
    }

    i++;
  }

  return result;
}

function parseSeverity(value: string): Severity {
  const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const lower = value?.toLowerCase() as Severity;
  if (!valid.includes(lower)) {
    process.stderr.write(`Invalid severity: ${value}. Use: critical, high, medium, low, info.\n`);
    process.exit(2);
  }
  return lower;
}

// ============================================================================
// Merge Config + Args
// ============================================================================

function mergeConfigWithArgs(config: ClawSecConfig | null, args: ParsedArgs): ParsedArgs {
  if (!config) return args;

  // Config provides defaults, CLI args override
  const merged = { ...args };

  if (config.scan?.paths && merged.paths.length === 0) {
    merged.paths = config.scan.paths;
  }
  if (config.scan?.ignore && !merged.excludePatterns) {
    merged.excludePatterns = config.scan.ignore;
  }
  if (config.scan?.severity && !merged.minSeverity) {
    merged.minSeverity = config.scan.severity;
  }
  if (config.scan?.severities && !merged.severities && !merged.minSeverity) {
    merged.severities = config.scan.severities;
  }
  if (config.scan?.format && !merged.format) {
    merged.format = config.scan.format;
  }
  if (config.rules?.disable && !merged.disableRules) {
    merged.disableRules = config.rules.disable;
  }
  if (config.rules?.enable && !merged.enableRules) {
    merged.enableRules = config.rules.enable;
  }
  if (config.rules?.custom && !merged.ruleFiles) {
    merged.ruleFiles = config.rules.custom;
  }
  if (config.output?.file && !merged.output) {
    merged.output = config.output.file;
  }
  if (config.ci?.failOn && !merged.failOn) {
    merged.failOn = config.ci.failOn;
  }
  if (config.ci?.scoreThreshold !== undefined && merged.scoreThreshold === undefined) {
    merged.scoreThreshold = config.ci.scoreThreshold;
  }

  return merged;
}

// ============================================================================
// Init Command
// ============================================================================

function ensureClawsecDir(cwd: string): void {
  const dir = clawsecDir(cwd);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const scans = scansDir(cwd);
  if (!existsSync(scans)) mkdirSync(scans, { recursive: true });
}

function addToGitignore(cwd: string): void {
  const gitignorePath = path.resolve(cwd, '.gitignore');
  const entry = '.clawsec/';

  if (existsSync(gitignorePath)) {
    const content = readFileSync(gitignorePath, 'utf-8');
    if (content.includes(entry)) return;
    const newline = content.endsWith('\n') ? '' : '\n';
    appendFileSync(gitignorePath, `${newline}${entry}\n`);
  } else {
    appendFileSync(gitignorePath, `${entry}\n`);
  }
}

async function runInit(): Promise<void> {
  if (isInteractive(false)) {
    await runInitInteractive();
  } else {
    await runInitNonInteractive();
  }
}

async function runInitNonInteractive(): Promise<void> {
  const cwd = process.cwd();

  if (existsSync(settingsPath(cwd))) {
    process.stderr.write(`${c.yellow('exists:')} ${CLAWSEC_DIR}/ already initialized\n`);
    process.exit(1);
  }

  ensureClawsecDir(cwd);

  const defaultConfig: ClawSecConfig = {
    scan: {
      paths: ['.'],
      ignore: ['docs/**', '**/fixtures/**'],
      severity: 'low',
      format: 'table',
    },
    rules: {
      disable: [],
      custom: [],
    },
    output: {
      dashboard: true,
    },
    ci: {
      failOn: 'high',
      scoreThreshold: 0,
    },
  };

  await writeFile(settingsPath(cwd), JSON.stringify(defaultConfig, null, 2) + '\n');
  addToGitignore(cwd);

  console.log(`${c.green('created')} ${CLAWSEC_DIR}/`);
  console.log(`  ${c.dim('settings')}  ${CLAWSEC_DIR}/${SETTINGS_FILENAME}`);
  console.log(`  ${c.dim('scans')}     ${CLAWSEC_DIR}/${SCANS_DIR}/`);
  console.log(`  ${c.dim('gitignore')} .clawsec/ added to .gitignore`);
  console.log('');
  console.log('  Run a scan:');
  console.log(`  ${c.cyan('clawsec scan')}`);
  console.log('');
}

async function runInitInteractive(): Promise<void> {
  const cwd = process.cwd();

  p.intro(`${c.bold('ClawSec')}${c.dim(' — Project Setup')}`);

  // Check if already initialized
  if (existsSync(settingsPath(cwd))) {
    p.log.warn('.clawsec/ already exists in this project.');
    const shouldOverwrite = await p.confirm({
      message: 'Overwrite existing configuration?',
    });
    if (p.isCancel(shouldOverwrite) || !shouldOverwrite) {
      p.cancel('Setup cancelled.');
      process.exit(0);
    }
  }

  // Discover top-level directories for scan path selection
  const entries = await readdir(cwd, { withFileTypes: true });
  const dirs = entries
    .filter(e => e.isDirectory())
    .map(e => e.name)
    .filter(d => !d.startsWith('.') && d !== 'node_modules' && d !== 'dist' && d !== 'build' && d !== 'out');

  let scanPaths: string[] = ['.'];

  if (dirs.length > 1) {
    const selectedPaths = await p.multiselect({
      message: 'Which directories should ClawSec scan?',
      options: [
        { value: '.', label: '. (entire project)', hint: 'recommended' },
        ...dirs.map(d => ({ value: d, label: d })),
      ],
      initialValues: ['.'],
      required: true,
    });

    if (p.isCancel(selectedPaths)) {
      p.cancel('Setup cancelled.');
      process.exit(0);
    }

    scanPaths = selectedPaths as string[];
  }

  // Severity levels to report
  const severities = await p.multiselect({
    message: 'Which severity levels should be reported?',
    options: [
      { value: 'critical', label: 'Critical', hint: 'highest risk' },
      { value: 'high', label: 'High' },
      { value: 'medium', label: 'Medium' },
      { value: 'low', label: 'Low' },
      { value: 'info', label: 'Info', hint: 'informational' },
    ],
    initialValues: ['critical', 'high', 'medium', 'low', 'info'],
    required: true,
  });

  if (p.isCancel(severities)) {
    p.cancel('Setup cancelled.');
    process.exit(0);
  }

  // Create files
  const s = p.spinner();
  s.start('Creating .clawsec/ directory');

  ensureClawsecDir(cwd);

  const config: ClawSecConfig = {
    scan: {
      paths: scanPaths,
      ignore: ['docs/**', '**/fixtures/**'],
      severities: severities as Severity[],
      format: 'table',
    },
    rules: {
      disable: [],
      custom: [],
    },
    output: {
      dashboard: true,
    },
    ci: {
      failOn: 'high',
      scoreThreshold: 0,
    },
  };

  await writeFile(settingsPath(cwd), JSON.stringify(config, null, 2) + '\n');
  addToGitignore(cwd);

  s.stop('Created .clawsec/');

  p.note(
    `  settings.json   Configuration\n` +
    `  scans/          Scan results\n` +
    `  .gitignore      Updated`,
    '.clawsec/',
  );

  p.outro(`Next step: ${c.cyan('clawsec scan')}`);
}

// ============================================================================
// Scan Pipeline
// ============================================================================

async function runScan(paths: string[], options: ScanOptions): Promise<{ result: ScanResult; rules: Rule[] }> {
  const startTime = Date.now();
  const scanRoot = path.resolve(paths[0] || '.');

  if (!options.quiet) process.stderr.write('Discovering files...\n');
  const files = await discoverFiles(scanRoot, {
    ignore: options.excludePatterns,
  });
  if (!options.quiet) process.stderr.write(`Found ${files.length} files\n`);

  const { rules, errors: ruleErrors } = await loadRules({
    includeBuiltin: true,
    customFiles: options.ruleFiles,
    enableRules: options.enableRules,
    disableRules: options.disableRules,
  });
  if (!options.quiet) process.stderr.write(`Loaded ${rules.length} rules\n`);

  const rawFindings = await analyze(files, rules);
  const findings = deduplicate(rawFindings);

  // Apply suppressions (from .clawsec/suppressions.json)
  const cwd = process.cwd();
  const suppressions = loadSuppressions(cwd);
  const { active: unsuppressed, suppressedCount } = applySuppressions(findings, suppressions, cwd);

  if (!options.quiet && suppressedCount > 0) {
    process.stderr.write(c.dim(`Suppressed ${suppressedCount} findings\n`));
  }

  let filtered = unsuppressed;
  if (options.minSeverity) {
    filtered = unsuppressed.filter(f => isSeverityAtLeast(f.severity, options.minSeverity!));
  } else if (options.severities) {
    const allowed = new Set(options.severities);
    filtered = unsuppressed.filter(f => allowed.has(f.severity));
  }

  const score = calculateScore(filtered);

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: filtered.length };
  for (const f of filtered) summary[f.severity]++;

  const result: ScanResult = {
    timestamp: new Date().toISOString(),
    duration: Date.now() - startTime,
    scanRoot,
    filesScanned: files.length,
    rulesApplied: rules.length,
    score,
    findings: filtered,
    summary,
    errors: ruleErrors.map(e => ({ message: e })),
    suppressedCount,
    suppressions: suppressions.length > 0 ? suppressions : undefined,
  };

  return { result, rules };
}

async function runScanWithProgress(
  paths: string[],
  options: ScanOptions,
): Promise<{ result: ScanResult; rules: Rule[] }> {
  const startTime = Date.now();
  const scanRoot = path.resolve(paths[0] || '.');

  p.intro(`${c.bold('ClawSec')}${c.dim(' — Security Scan')}`);

  const s = p.spinner();

  // Phase 1: File discovery
  s.start('Discovering files...');
  const files = await discoverFiles(scanRoot, {
    ignore: options.excludePatterns,
  });
  s.stop(`Found ${c.bold(String(files.length))} files`);

  // Phase 2: Rule loading
  s.start('Loading security rules...');
  const { rules, errors: ruleErrors } = await loadRules({
    includeBuiltin: true,
    customFiles: options.ruleFiles,
    enableRules: options.enableRules,
    disableRules: options.disableRules,
  });
  const ruleStatus = ruleErrors.length > 0
    ? `${ruleErrors.length} warnings`
    : 'all valid';
  s.stop(`Loaded ${c.bold(String(rules.length))} rules (${ruleStatus})`);

  // Phase 3: Analysis
  s.start(`Analyzing ${files.length} files against ${rules.length} rules...`);
  const rawFindings = await analyze(files, rules);
  const findings = deduplicate(rawFindings);

  // Apply suppressions
  const cwd = process.cwd();
  const suppressions = loadSuppressions(cwd);
  const { active: unsuppressed, suppressedCount } = applySuppressions(findings, suppressions, cwd);

  let filtered = unsuppressed;
  if (options.minSeverity) {
    filtered = unsuppressed.filter(f => isSeverityAtLeast(f.severity, options.minSeverity!));
  } else if (options.severities) {
    const allowed = new Set(options.severities);
    filtered = unsuppressed.filter(f => allowed.has(f.severity));
  }

  const score = calculateScore(filtered);
  s.stop(`Analysis complete — ${c.bold(String(filtered.length))} findings`);

  // Phase 4: Summary
  if (filtered.length > 0) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of filtered) counts[f.severity]++;

    const parts: string[] = [];
    if (counts.critical > 0) parts.push(c.red(`${counts.critical} critical`));
    if (counts.high > 0) parts.push(c.magenta(`${counts.high} high`));
    if (counts.medium > 0) parts.push(c.yellow(`${counts.medium} medium`));
    if (counts.low > 0) parts.push(c.blue(`${counts.low} low`));
    if (counts.info > 0) parts.push(c.dim(`${counts.info} info`));

    p.log.warn(parts.join(c.dim(', ')));
  } else {
    p.log.success('No security findings detected!');
  }

  if (suppressedCount > 0) {
    p.log.info(c.dim(`${suppressedCount} findings suppressed`));
  }

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: filtered.length };
  for (const f of filtered) summary[f.severity]++;

  const result: ScanResult = {
    timestamp: new Date().toISOString(),
    duration: Date.now() - startTime,
    scanRoot,
    filesScanned: files.length,
    rulesApplied: rules.length,
    score,
    findings: filtered,
    summary,
    errors: ruleErrors.map(e => ({ message: e })),
    suppressedCount,
    suppressions: suppressions.length > 0 ? suppressions : undefined,
  };

  return { result, rules };
}

// ============================================================================
// Rules Command
// ============================================================================

async function runRulesCommand(): Promise<void> {
  const { rules, errors } = await loadRules({ includeBuiltin: true });

  if (errors.length > 0) {
    for (const err of errors) {
      process.stderr.write(`${c.yellow('warning:')} ${err}\n`);
    }
  }

  const byCategory = new Map<string, Rule[]>();
  for (const rule of rules) {
    const list = byCategory.get(rule.category) ?? [];
    list.push(rule);
    byCategory.set(rule.category, list);
  }

  console.log(`\n${c.bold('ClawSec Rules')} (${rules.length} total)\n`);

  for (const [category, categoryRules] of byCategory) {
    console.log(`  ${c.bold(c.cyan(category))}`);
    for (const rule of categoryRules) {
      const colorFn = severityColor[rule.severity] ?? ((t: string) => t);
      const sev = colorFn(rule.severity.toUpperCase().padEnd(8));
      const enabled = rule.enabled !== false ? c.green('on') : c.dim('off');
      console.log(`    ${c.dim(rule.id)}  ${sev}  ${enabled}  ${rule.name}`);
    }
    console.log('');
  }
}

// ============================================================================
// Test-Rules Command
// ============================================================================

async function runTestRules(): Promise<number> {
  const fixturesDir = path.resolve(__dirname, '..', 'src', 'rules', 'fixtures');
  const { rules, errors: ruleErrors } = await loadRules({ includeBuiltin: true });

  if (ruleErrors.length > 0) {
    for (const err of ruleErrors) {
      process.stderr.write(`${c.yellow('warning:')} ${err}\n`);
    }
  }

  const { readdirSync } = await import('node:fs');

  // Find fixture directories that contain any positive.* file
  function findFixtureFile(dir: string, prefix: string): string | null {
    try {
      const entries = readdirSync(path.join(fixturesDir, dir));
      const match = entries.find(f => f.startsWith(prefix + '.'));
      return match ? path.join(fixturesDir, dir, match) : null;
    } catch {
      return null;
    }
  }

  let fixtureDirs: string[];
  try {
    fixtureDirs = readdirSync(fixturesDir, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name)
      .filter(d => findFixtureFile(d, 'positive') !== null);
  } catch {
    process.stderr.write(`No fixtures directory found at ${fixturesDir}\n`);
    return 2;
  }

  let passed = 0;
  let failed = 0;

  console.log(`\n${c.bold('ClawSec Rule Tests')}\n`);

  for (const dir of fixtureDirs.sort()) {
    const ruleId = dir;
    const rule = rules.find(r => r.id === ruleId);
    if (!rule) {
      console.log(`  ${c.yellow('?')} ${ruleId} — no matching rule found`);
      failed++;
      continue;
    }

    const positivePath = findFixtureFile(dir, 'positive')!;
    const negativePath = findFixtureFile(dir, 'negative');

    // Test positive case — expect at least 1 finding
    const positiveFiles = await discoverFiles(positivePath);
    const positiveFindings = await analyze(positiveFiles, [rule]);
    const positiveMatch = positiveFindings.some(f => f.ruleId === ruleId);

    if (positiveMatch) {
      console.log(`  ${c.green('✓')} ${ruleId} positive`);
      passed++;
    } else {
      console.log(`  ${c.red('✗')} ${ruleId} positive — expected finding, got none`);
      failed++;
    }

    // Test negative case — expect 0 findings (if file exists)
    if (negativePath) {
      const negativeFiles = await discoverFiles(negativePath);
      const negativeFindings = await analyze(negativeFiles, [rule]);
      const negativeMatch = negativeFindings.some(f => f.ruleId === ruleId);

      if (!negativeMatch) {
        console.log(`  ${c.green('✓')} ${ruleId} negative`);
        passed++;
      } else {
        console.log(`  ${c.red('✗')} ${ruleId} negative — expected no finding, got ${negativeFindings.filter(f => f.ruleId === ruleId).length}`);
        failed++;
      }
    }
  }

  console.log(`\n  ${c.bold('Results:')} ${c.green(`${passed} passed`)}, ${failed > 0 ? c.red(`${failed} failed`) : c.dim('0 failed')}\n`);
  return failed > 0 ? 1 : 0;
}

// ============================================================================
// Dashboard Server Command
// ============================================================================

function createDashboardServer(cwd: string): ReturnType<typeof createServer> {
  const scans = scansDir(cwd);
  const htmlPath = path.join(scans, 'report.html');

  return createServer(async (req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
      if (!existsSync(htmlPath)) {
        res.writeHead(404);
        res.end('No report found. Run clawsec scan first.');
        return;
      }
      const html = readFileSync(htmlPath, 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } else if (req.url === '/api/latest') {
      const latestPath = path.join(scans, 'latest.json');
      if (existsSync(latestPath)) {
        const json = readFileSync(latestPath, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(json);
      } else {
        res.writeHead(404);
        res.end('{}');
      }
    } else if (req.url === '/api/scans') {
      try {
        const files = await readdir(scans);
        const jsonFiles = files.filter(f => f.endsWith('.json')).sort().reverse();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(jsonFiles));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
      }
    } else if (req.url === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    } else if (req.url === '/api/suppressions' && req.method === 'POST') {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', async () => {
        try {
          const parsed = JSON.parse(body);
          if (!parsed.version || !Array.isArray(parsed.suppressions)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid suppressions format' }));
            return;
          }
          const supPath = suppressionsPath(cwd);
          ensureClawsecDir(cwd);
          await writeFile(supPath, JSON.stringify(parsed, null, 2) + '\n');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ saved: parsed.suppressions.length }));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
    } else if (req.url === '/api/suppressions' && req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      res.end();
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
}

function openBrowser(url: string): void {
  const openCmd =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'start'
        : 'xdg-open';
  exec(`${openCmd} ${url}`);
}

function startDashboardServer(cwd: string, port: number): Promise<number> {
  const server = createDashboardServer(cwd);

  return new Promise((resolve) => {
    server.listen(port, () => {
      resolve(port);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        // Port taken, try next
        server.listen(0, () => {
          const addr = server.address();
          const actualPort = typeof addr === 'object' && addr ? addr.port : port;
          resolve(actualPort);
        });
      }
    });
  });
}

async function runDashboard(port: number): Promise<void> {
  const cwd = process.cwd();
  const scans = scansDir(cwd);

  if (!existsSync(scans)) {
    process.stderr.write(`${c.red('error:')} No .clawsec/scans/ directory found. Run ${c.cyan('clawsec init')} first.\n`);
    process.exit(2);
  }

  const htmlPath = path.join(scans, 'report.html');
  if (!existsSync(htmlPath)) {
    process.stderr.write(`${c.red('error:')} No scan report found. Run ${c.cyan('clawsec scan')} first.\n`);
    process.exit(2);
  }

  const actualPort = await startDashboardServer(cwd, port);

  console.log('');
  console.log(`  ${c.bold('ClawSec Dashboard')}`);
  console.log(`  ${c.cyan(`http://localhost:${actualPort}`)}`);
  console.log('');
  console.log(`  ${c.dim('Press Ctrl+C to stop')}`);
  console.log('');

  openBrowser(`http://localhost:${actualPort}`);
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatOutput(result: ScanResult, rules: Rule[], format: 'table' | 'json' | 'sarif' | 'agent'): string {
  switch (format) {
    case 'json':
      return formatJson(result);
    case 'sarif':
      return formatSarif(result, rules);
    case 'agent':
      return formatAgentJson(result, VERSION);
    case 'table':
      return formatTable(result);
  }
}

const FILLED = '\u2588'; // █
const EMPTY = '\u2591';  // ░

function compactScoreBar(score: number): string {
  const blocks = Math.round(score / 10);
  const colorFn = score >= 90 ? c.green : score >= 70 ? c.yellow : c.red;
  return colorFn(FILLED.repeat(blocks)) + c.dim(EMPTY.repeat(10 - blocks));
}

function compactSevBar(filled: number, total: number): string {
  const width = 10;
  const blocks = total > 0 ? Math.round((filled / total) * width) : 0;
  return FILLED.repeat(blocks) + EMPTY.repeat(width - blocks);
}

function formatCompactSummary(result: ScanResult): string {
  const { findings, summary, score, filesScanned, rulesApplied, duration } = result;
  const lines: string[] = [''];

  if (findings.length === 0) {
    lines.push(c.green(c.bold('  All clear! Score: 100/100')));
    lines.push('');
    lines.push(c.dim(`  Scanned ${filesScanned} files with ${rulesApplied} rules in ${duration}ms`));
    lines.push('');
    return lines.join('\n');
  }

  // Score
  const colorFn = score >= 90 ? c.green : score >= 70 ? c.yellow : c.red;
  lines.push(c.bold(`  ClawSec Security Score: ${colorFn(`${score}/100`)}`));
  lines.push(`  ${compactScoreBar(score)}`);
  lines.push('');

  // Severity bars
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const count = summary[sev];
    if (count === 0) continue;
    const colorize = severityColor[sev] ?? c.dim;
    lines.push(`  ${colorize(String(count).padStart(2))} ${sev.padEnd(8)}  ${colorize(compactSevBar(count, summary.total))}`);
  }
  lines.push('');

  // Top risks — compact, NO code snippets
  const sorted = [...findings].sort((a, b) => {
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });
  const top = sorted.slice(0, 5);

  lines.push(c.bold('  Top risks:'));
  for (const f of top) {
    const colorize = severityColor[f.severity] ?? c.dim;
    const sev = colorize(f.severity.toUpperCase().padEnd(8));
    const name = f.ruleName;
    const file = c.dim(f.location.file.split('/').slice(-2).join('/') + ':' + f.location.startLine);
    lines.push(`    ${sev}  ${name}`);
    lines.push(`    ${c.dim(' '.repeat(8))}  ${file}`);
  }

  if (findings.length > 5) {
    lines.push(c.dim(`    ... and ${findings.length - 5} more`));
  }
  lines.push('');

  // Footer
  lines.push(c.dim(`  Scanned ${filesScanned} files with ${rulesApplied} rules in ${duration}ms`));
  if (result.suppressedCount && result.suppressedCount > 0) {
    lines.push(c.dim(`  ${result.suppressedCount} findings suppressed`));
  }
  lines.push('');

  return lines.join('\n');
}

// ============================================================================
// Exit Code
// ============================================================================

function computeExitCode(result: ScanResult, args: ParsedArgs): number {
  if (args.failOn) {
    const hasFailure = result.findings.some(f => isSeverityAtLeast(f.severity, args.failOn!));
    if (hasFailure) return 1;
  }

  if (args.scoreThreshold !== undefined && result.score < args.scoreThreshold) {
    return 1;
  }

  return 0;
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  const rawArgs = parseArgs(process.argv.slice(2));

  if (rawArgs.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (rawArgs.version) {
    console.log(`clawsec ${VERSION}`);
    process.exit(0);
  }

  // Load config (unless --no-config or init command)
  const config = (!rawArgs.noConfig && rawArgs.command !== 'init')
    ? loadConfig(process.cwd())
    : null;

  if (config && !rawArgs.quiet && !isInteractive(rawArgs.quiet)) {
    process.stderr.write(`${c.dim('Using')} ${CLAWSEC_DIR}/${SETTINGS_FILENAME}\n`);
  }

  const args = mergeConfigWithArgs(config, rawArgs);

  try {
    switch (args.command) {
      case 'init': {
        await runInit();
        process.exit(0);
        break;
      }

      case 'rules': {
        await runRulesCommand();
        process.exit(0);
        break;
      }

      case 'test-rules': {
        const code = await runTestRules();
        process.exit(code);
        break;
      }

      case 'scan': {
        const cwd = process.cwd();
        const format = args.format || 'table';
        const options: ScanOptions = {
          paths: args.paths,
          format,
          output: args.output,
          minSeverity: args.minSeverity,
          severities: args.severities,
          failOn: args.failOn,
          scoreThreshold: args.scoreThreshold,
          excludePatterns: args.excludePatterns,
          enableRules: args.enableRules,
          disableRules: args.disableRules,
          ruleFiles: args.ruleFiles,
          quiet: args.quiet,
        };

        const interactive = isInteractive(args.quiet) && format === 'table';
        let result: ScanResult;
        let rules: Rule[];

        if (interactive) {
          ({ result, rules } = await runScanWithProgress(args.paths, options));
        } else {
          ({ result, rules } = await runScan(args.paths, options));
        }

        // Output to terminal
        if (!args.quiet) {
          if (interactive) {
            // Compact summary — details go to HTML/JSON
            console.log(formatCompactSummary(result));
          } else if (format === 'table') {
            console.log(formatTable(result));
          } else if (format === 'json') {
            console.log(formatJson(result));
          } else if (format === 'sarif') {
            console.log(formatSarif(result, rules));
          } else if (format === 'agent') {
            console.log(formatAgentJson(result, VERSION));
          }
        }

        // Write scan artifacts to disk
        if (!args.noOutput) {
          ensureClawsecDir(cwd);
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

          if (args.output) {
            const outputContent = format === 'sarif'
              ? formatSarif(result, rules)
              : format === 'agent'
                ? formatAgentJson(result, VERSION)
                : formatJson(result);
            await writeFile(args.output, outputContent);
            if (interactive) {
              p.log.step(c.dim(`Wrote ${path.relative(cwd, args.output)}`));
            } else if (!args.quiet) {
              process.stderr.write(`${c.dim('Wrote')} ${path.relative(cwd, args.output)}\n`);
            }
          } else {
            // Write timestamped scan + latest.json
            const jsonPath = path.join(scansDir(cwd), `scan-${timestamp}.json`);
            await writeFile(jsonPath, formatJson(result));
            await writeFile(path.join(scansDir(cwd), 'latest.json'), formatJson(result));

            // Write SARIF if requested
            if (format === 'sarif') {
              const sarifPath = path.join(scansDir(cwd), `scan-${timestamp}.sarif`);
              await writeFile(sarifPath, formatSarif(result, rules));
            }

            // Write agent reports if requested
            let agentJsonPath: string | undefined;
            let agentMdPath: string | undefined;
            if (format === 'agent') {
              agentJsonPath = path.join(scansDir(cwd), 'agent-report.json');
              agentMdPath = path.join(scansDir(cwd), 'agent-report.md');
              await writeFile(agentJsonPath, formatAgentJson(result, VERSION));
              await writeFile(agentMdPath, formatAgentMarkdown(result, VERSION));
            }

            // Write dashboard HTML
            const writeDashboard = config?.output?.dashboard !== false;
            let dashboardPath: string | undefined;
            if (writeDashboard) {
              dashboardPath = path.join(scansDir(cwd), 'report.html');
              await writeFile(dashboardPath, formatDashboard(result));
            }

            if (interactive) {
              if (agentJsonPath) {
                p.log.step(`Agent report: ${c.cyan(path.relative(cwd, agentJsonPath))}`);
                p.log.step(`Agent report: ${c.cyan(path.relative(cwd, agentMdPath!))}`);
              }
              if (dashboardPath) {
                // Start dashboard server so Mark Safe and future features work
                const actualPort = await startDashboardServer(cwd, args.port);
                const dashUrl = `http://localhost:${actualPort}`;
                const clickable = link(c.cyan(dashUrl), dashUrl);
                p.log.step(`Dashboard: ${clickable}`);
                openBrowser(dashUrl);
              }
            } else if (!args.quiet) {
              process.stderr.write(`${c.dim('Wrote')} ${CLAWSEC_DIR}/${SCANS_DIR}/latest.json\n`);
              if (agentJsonPath) {
                process.stderr.write(`${c.dim('Agent JSON')} ${path.relative(cwd, agentJsonPath)}\n`);
                process.stderr.write(`${c.dim('Agent MD')} ${path.relative(cwd, agentMdPath!)}\n`);
              }
              if (dashboardPath) {
                const absPath = path.resolve(dashboardPath);
                const clickable = link(`${CLAWSEC_DIR}/${SCANS_DIR}/report.html`, fileUrl(absPath));
                process.stderr.write(`${c.dim('Dashboard')} ${clickable}\n`);
              }
            }
          }
        }

        // Outro with score
        if (interactive) {
          const scoreColorFn = result.score >= 90 ? c.green
            : result.score >= 70 ? c.yellow
            : c.red;
          p.outro(
            `Score: ${scoreColorFn(result.score + '/100')}` +
            c.dim(` | ${result.filesScanned} files | ${result.duration}ms`) +
            c.dim(' | Ctrl+C to stop'),
          );

          // Keep alive for dashboard server; exit with proper code on Ctrl+C
          const exitCode = computeExitCode(result, args);
          process.on('SIGINT', () => process.exit(exitCode));
          process.on('SIGTERM', () => process.exit(exitCode));
        } else {
          process.exit(computeExitCode(result, args));
        }
        break;
      }

      case 'dashboard': {
        await runDashboard(args.port);
        break;
      }

      case 'help': {
        if (isInteractive(args.quiet)) {
          p.intro(`${c.bold('ClawSec')}${c.dim(' v' + VERSION)}`);
          console.log(HELP);
          p.outro('');
        } else {
          console.log(HELP);
        }
        process.exit(0);
        break;
      }

      case 'default': {
        if (isInteractive(args.quiet)) {
          p.intro(`${c.bold('ClawSec')}${c.dim(' v' + VERSION)}`);
          p.note(
            `Security scanner for AI agents, prompts, and vibecoded projects.\n\n` +
            `Get started:\n` +
            `  ${c.cyan('clawsec init')}           Set up .clawsec/ in this project\n` +
            `  ${c.cyan('clawsec scan')} [path]    Run a security scan\n` +
            `  ${c.cyan('clawsec rules')}          List available rules\n` +
            `  ${c.cyan('clawsec dashboard')}      View results in browser\n\n` +
            `All options:\n` +
            `  ${c.cyan('clawsec help')}           Show detailed help`,
            'Quick Start',
          );
          p.outro(c.dim('https://github.com/agentsauthority/clawsec'));
        } else {
          console.log(HELP);
        }
        process.exit(0);
        break;
      }
    }
  } catch (error) {
    process.stderr.write(
      `${c.red('error:')} ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exit(2);
  }
}

main();
