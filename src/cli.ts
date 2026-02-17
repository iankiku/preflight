/**
 * Preflight CLI Entry Point
 * Pipeline orchestrator: config → arg parsing → discovery → analysis → reporting
 */

import { readFileSync, existsSync, mkdirSync, appendFileSync, copyFileSync, readdirSync } from 'node:fs';
import { writeFile, readdir } from 'node:fs/promises';
import { exec } from 'node:child_process';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

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
import { isSeverityAtLeast, c, severityColor, sanitizeForTerminal } from './utils.js';
import { isInteractive, link, fileUrl } from './ui.js';
import * as p from '@clack/prompts';
import type { ScanResult, ScanOptions, Severity, Rule, Suppression, SuppressionsFile, Finding } from './types.js';

// ============================================================================
// Version
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, '../package.json'), 'utf-8'));
const PKG_ROOT = path.resolve(__dirname, '..');
const VERSION: string = pkg.version;

// ============================================================================
// Config File
// ============================================================================

const PREFLIGHT_DIR = '.preflight';
const SETTINGS_FILENAME = 'settings.json';
const SCANS_DIR = 'scans';

interface PreflightConfig {
  scan?: {
    paths?: string[];
    ignore?: string[];
    severity?: Severity;
    severities?: Severity[];
    format?: 'table' | 'json' | 'sarif' | 'agent';
    onlySkills?: boolean;
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

function resolveProjectName(scanRoot: string): string {
  const root = path.extname(scanRoot) ? path.dirname(scanRoot) : scanRoot;
  try {
    const pkgPath = path.join(root, 'package.json');
    if (existsSync(pkgPath)) {
      const pkgRaw = readFileSync(pkgPath, 'utf-8');
      const pkgJson = JSON.parse(pkgRaw) as { name?: string };
      if (pkgJson.name && typeof pkgJson.name === 'string') return pkgJson.name;
    }
  } catch {
    // ignore
  }

  const yamlCandidates = ['project.yml', 'project.yaml'];
  for (const filename of yamlCandidates) {
    try {
      const yamlPath = path.join(root, filename);
      if (!existsSync(yamlPath)) continue;
      const raw = readFileSync(yamlPath, 'utf-8');
      const parsed = parseYaml(raw) as { name?: string } | undefined;
      if (parsed && typeof parsed.name === 'string') return parsed.name;
    } catch {
      // ignore
    }
  }

  return path.basename(root) || 'Project';
}

function preflightDir(cwd: string): string {
  return path.resolve(cwd, PREFLIGHT_DIR);
}

function settingsPath(cwd: string): string {
  return path.join(preflightDir(cwd), SETTINGS_FILENAME);
}

function scansDir(cwd: string): string {
  return path.join(preflightDir(cwd), SCANS_DIR);
}

function copyDashboardAssets(cwd: string): void {
  const assetsSrc = path.resolve(PKG_ROOT, 'src', 'assets');
  const assetsDest = path.join(scansDir(cwd), 'assets');
  if (!existsSync(assetsSrc)) return;
  if (!existsSync(assetsDest)) mkdirSync(assetsDest, { recursive: true });

  for (const file of readdirSync(assetsSrc)) {
    const from = path.join(assetsSrc, file);
    const to = path.join(assetsDest, file);
    copyFileSync(from, to);
  }
}

function loadConfig(cwd: string): PreflightConfig | null {
  const cfgPath = settingsPath(cwd);
  if (!existsSync(cfgPath)) return null;
  try {
    const raw = readFileSync(cfgPath, 'utf-8');
    return JSON.parse(raw) as PreflightConfig;
  } catch (e) {
    process.stderr.write(`${c.yellow('warning:')} Failed to parse ${PREFLIGHT_DIR}/${SETTINGS_FILENAME}: ${e instanceof Error ? e.message : e}\n`);
    return null;
  }
}

// ============================================================================
// Suppressions
// ============================================================================

const SUPPRESSIONS_FILENAME = 'suppressions.json';

function suppressionsPath(cwd: string): string {
  return path.join(preflightDir(cwd), SUPPRESSIONS_FILENAME);
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
      `${c.yellow('warning:')} Failed to parse ${PREFLIGHT_DIR}/${SUPPRESSIONS_FILENAME}: ${e instanceof Error ? e.message : e}\n`,
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
${c.bold('Preflight')} — Security scanner for AI

${c.bold('USAGE')}
  preflight                          Quick start guide
  preflight init                     Set up .preflight/ in this project
  preflight scan [path] [options]    Run a security scan
  preflight dashboard                Serve scan results on local server
  preflight rules                    List available security rules
  preflight test-rules               Validate all rules against fixtures
  preflight help                     Show this help

${c.bold('OPTIONS')}
  -f, --format <fmt>        Output format: table, json, sarif, agent (default: table)
  -o, --output <file>       Write results to file instead of .preflight/scans/
  -s, --severity <level>    Minimum severity: critical, high, medium, low, info
  --fail-on <level>         Exit code 1 if findings at/above severity
  --score-threshold <n>     Exit code 1 if score below n
  --exclude <patterns>      Exclude paths (comma-separated globs, e.g. "docs/**,tests/**")
  -e, --enable <ids>        Enable only these rules (comma-separated)
  -d, --disable <ids>       Disable these rules (comma-separated)
  -r, --rules <files>       Additional rule files (comma-separated)
  --all-files               Scan all files (disable skills-only mode)
  --no-config               Ignore .preflight/settings.json
  --no-output               Don't write scan results to disk
  -p, --port <n>            Dashboard server port (default: 7700)
  --host <host>             Dashboard server host (default: 127.0.0.1)
  --quiet                   Suppress output except exit code
  -h, --help                Show this help
  -v, --version             Show version

${c.bold('CONFIG')}
  Run ${c.cyan('preflight init')} to create .preflight/ with default settings.
  CLI flags override settings.json values.

${c.bold('SCOPE')}
  Default: only files named ${c.cyan('skills.md')} or ${c.cyan('SKILLS.MD')} are scanned.
  Use ${c.cyan('--all-files')} to scan everything.

${c.bold('FILES')}
  .preflight/
    settings.json            Configuration
    scans/                   Scan results (JSON + HTML)

${c.bold('INSTALL')}
  npm install preflight -g     Global install
  npm install preflight -D     Project dev dependency
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
  allFiles?: boolean;
  port: number;
  host: string;
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
    host: '127.0.0.1',
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
      case '--all-files':
        result.allFiles = true;
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
      case '--host':
        result.host = argv[++i];
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

function mergeConfigWithArgs(config: PreflightConfig | null, args: ParsedArgs): ParsedArgs {
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
  if (config.scan?.onlySkills !== undefined && merged.allFiles === undefined) {
    merged.allFiles = !config.scan.onlySkills;
  }

  return merged;
}

function buildScanOptions(args: ParsedArgs): ScanOptions {
  return {
    paths: args.paths,
    format: args.format || 'table',
    output: args.output,
    minSeverity: args.minSeverity,
    severities: args.severities,
    failOn: args.failOn,
    scoreThreshold: args.scoreThreshold,
    excludePatterns: args.excludePatterns,
    enableRules: args.enableRules,
    disableRules: args.disableRules,
    ruleFiles: args.ruleFiles,
    onlySkills: args.allFiles ? false : true,
    quiet: args.quiet,
  };
}

// ============================================================================
// Init Command
// ============================================================================

function ensurePreflightDir(cwd: string): void {
  const dir = preflightDir(cwd);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const scans = scansDir(cwd);
  if (!existsSync(scans)) mkdirSync(scans, { recursive: true });
}

function addToGitignore(cwd: string): void {
  const gitignorePath = path.resolve(cwd, '.gitignore');
  const entry = '.preflight/';

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
    process.stderr.write(`${c.yellow('exists:')} ${PREFLIGHT_DIR}/ already initialized\n`);
    process.exit(1);
  }

  ensurePreflightDir(cwd);

  const defaultConfig: PreflightConfig = {
    scan: {
      paths: ['.'],
      ignore: ['docs/**', '**/fixtures/**'],
      severity: 'low',
      format: 'table',
      onlySkills: true,
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

  console.log(`${c.green('created')} ${PREFLIGHT_DIR}/`);
  console.log(`  ${c.dim('settings')}  ${PREFLIGHT_DIR}/${SETTINGS_FILENAME}`);
  console.log(`  ${c.dim('scans')}     ${PREFLIGHT_DIR}/${SCANS_DIR}/`);
  console.log(`  ${c.dim('gitignore')} .preflight/ added to .gitignore`);
  console.log('');
  console.log('  Run a scan:');
  console.log(`  ${c.cyan('preflight scan')}`);
  console.log('');
}

async function runInitInteractive(): Promise<void> {
  const cwd = process.cwd();

  p.intro(`${c.bold('Preflight')}${c.dim(' — Project Setup')}`);

  // Check if already initialized
  if (existsSync(settingsPath(cwd))) {
    p.log.warn('.preflight/ already exists in this project.');
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
      message: 'Which directories should Preflight scan?',
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
  s.start('Creating .preflight/ directory');

  ensurePreflightDir(cwd);

  const config: PreflightConfig = {
    scan: {
      paths: scanPaths,
      ignore: ['docs/**', '**/fixtures/**'],
      severities: severities as Severity[],
      format: 'table',
      onlySkills: true,
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

  s.stop('Created .preflight/');

  p.note(
    `  settings.json   Configuration\n` +
    `  scans/          Scan results\n` +
    `  .gitignore      Updated`,
    '.preflight/',
  );

  p.outro(`Next step: ${c.cyan('preflight scan')}`);
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
    onlySkills: options.onlySkills,
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

  // Apply suppressions (from .preflight/suppressions.json)
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
    projectName: resolveProjectName(scanRoot),
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

type ScanStatusUpdate = {
  phase: 'start' | 'discover' | 'rules' | 'analyze' | 'finalize' | 'done';
  message: string;
  progress: number;
  meta?: Record<string, number | string>;
};

async function runScanWithStatus(
  paths: string[],
  options: ScanOptions,
  onStatus: (update: ScanStatusUpdate) => void,
): Promise<{ result: ScanResult; rules: Rule[] }> {
  const startTime = Date.now();
  const scanRoot = path.resolve(paths[0] || '.');

  onStatus({ phase: 'start', message: 'Starting scan', progress: 5 });

  onStatus({ phase: 'discover', message: 'Discovering files', progress: 15 });
  const files = await discoverFiles(scanRoot, {
    ignore: options.excludePatterns,
    onlySkills: options.onlySkills,
  });
  onStatus({
    phase: 'discover',
    message: `Found ${files.length} files`,
    progress: 25,
    meta: { filesScanned: files.length },
  });

  onStatus({ phase: 'rules', message: 'Loading rules', progress: 35 });
  const { rules, errors: ruleErrors } = await loadRules({
    includeBuiltin: true,
    customFiles: options.ruleFiles,
    enableRules: options.enableRules,
    disableRules: options.disableRules,
  });
  onStatus({
    phase: 'rules',
    message: `Loaded ${rules.length} rules`,
    progress: 45,
    meta: { rulesApplied: rules.length },
  });

  onStatus({
    phase: 'analyze',
    message: `Analyzing ${files.length} files`,
    progress: 65,
  });
  const rawFindings = await analyze(files, rules);
  const findings = deduplicate(rawFindings);

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
  onStatus({
    phase: 'analyze',
    message: `Analysis complete — ${filtered.length} findings`,
    progress: 80,
    meta: { findings: filtered.length },
  });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: filtered.length };
  for (const f of filtered) summary[f.severity]++;

  const result: ScanResult = {
    timestamp: new Date().toISOString(),
    duration: Date.now() - startTime,
    scanRoot,
    projectName: resolveProjectName(scanRoot),
    filesScanned: files.length,
    rulesApplied: rules.length,
    score,
    findings: filtered,
    summary,
    errors: ruleErrors.map(e => ({ message: e })),
    suppressedCount,
    suppressions: suppressions.length > 0 ? suppressions : undefined,
  };

  onStatus({ phase: 'finalize', message: 'Writing report', progress: 92 });

  return { result, rules };
}

async function runScanWithProgress(
  paths: string[],
  options: ScanOptions,
): Promise<{ result: ScanResult; rules: Rule[] }> {
  const startTime = Date.now();
  const scanRoot = path.resolve(paths[0] || '.');

  p.intro(`${c.bold('Preflight')}${c.dim(' — Security Scan')}`);

  const s = p.spinner();

  // Phase 1: File discovery
  s.start('Discovering files...');
  const files = await discoverFiles(scanRoot, {
    ignore: options.excludePatterns,
    onlySkills: options.onlySkills,
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
    projectName: resolveProjectName(scanRoot),
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

  console.log(`\n${c.bold('Preflight Rules')} (${rules.length} total)\n`);

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

  console.log(`\n${c.bold('Preflight Rule Tests')}\n`);

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
    const positiveFiles = await discoverFiles(positivePath, { onlySkills: false });
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
      const negativeFiles = await discoverFiles(negativePath, { onlySkills: false });
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
  const assetsDir = path.join(scans, 'assets');
  let scanInProgress = false;

  function sendSse(
    res: import('node:http').ServerResponse,
    event: string,
    payload: Record<string, unknown>,
  ): void {
    if ((res as any).writableEnded) return;
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  }

  return createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/' || url.pathname === '/index.html') {
      if (!existsSync(htmlPath)) {
        res.writeHead(404);
        res.end('No report found. Run preflight scan first.');
        return;
      }
      const html = readFileSync(htmlPath, 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } else if (url.pathname.startsWith('/assets/')) {
      const rel = url.pathname.replace('/assets/', '');
      const filePath = path.join(assetsDir, rel);
      const normalized = path.normalize(filePath);
      if (!normalized.startsWith(assetsDir) || !existsSync(normalized)) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = path.extname(normalized);
      const contentType =
        ext === '.js' ? 'application/javascript; charset=utf-8'
          : ext === '.ttf' ? 'font/ttf'
            : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(readFileSync(normalized));
    } else if (url.pathname === '/api/latest') {
      const latestPath = path.join(scans, 'latest.json');
      if (existsSync(latestPath)) {
        const json = readFileSync(latestPath, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(json);
      } else {
        res.writeHead(404);
        res.end('{}');
      }
    } else if (url.pathname === '/api/scans') {
      try {
        const files = await readdir(scans);
        const jsonFiles = files.filter(f => f.endsWith('.json')).sort().reverse();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(jsonFiles));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
      }
    } else if (url.pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    } else if (url.pathname === '/api/scan' && req.method === 'GET') {
      if (scanInProgress) {
        res.writeHead(409, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Scan already running');
        return;
      }

      scanInProgress = true;
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      res.write(':ok\n\n');

      try {
        const config = loadConfig(cwd);
        const baseArgs: ParsedArgs = {
          command: 'scan',
          paths: [],
          format: 'table',
          output: undefined,
          minSeverity: undefined,
          severities: undefined,
          failOn: undefined,
          scoreThreshold: undefined,
          excludePatterns: undefined,
          enableRules: undefined,
          disableRules: undefined,
          ruleFiles: undefined,
          port: 7700,
          host: '127.0.0.1',
          quiet: true,
          help: false,
          version: false,
          noConfig: false,
          noOutput: false,
        };
        const merged = mergeConfigWithArgs(config, baseArgs);
        merged.quiet = true;
        merged.format = 'table';

        const { result, rules } = await runScanWithStatus(merged.paths, buildScanOptions(merged), (update) => {
          sendSse(res, 'status', update);
        });

        ensurePreflightDir(cwd);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const jsonPath = path.join(scansDir(cwd), `scan-${timestamp}.json`);
        await writeFile(jsonPath, formatJson(result));
        await writeFile(path.join(scansDir(cwd), 'latest.json'), formatJson(result));
        await writeFile(path.join(scansDir(cwd), 'report.html'), formatDashboard(result));
        copyDashboardAssets(cwd);

        sendSse(res, 'done', {
          message: `Scan complete — ${result.summary.total} findings`,
          filesScanned: result.filesScanned,
          findings: result.summary.total,
        });
      } catch (error) {
        sendSse(res, 'error', {
          message: error instanceof Error ? error.message : 'Scan failed',
        });
      } finally {
        scanInProgress = false;
        res.end();
      }
    } else if (url.pathname === '/api/suppressions' && req.method === 'POST') {
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
          ensurePreflightDir(cwd);
          await writeFile(supPath, JSON.stringify(parsed, null, 2) + '\n');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ saved: parsed.suppressions.length }));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
    } else if (url.pathname === '/api/suppressions' && req.method === 'OPTIONS') {
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

function startDashboardServer(cwd: string, port: number, host: string): Promise<number> {
  const server = createDashboardServer(cwd);

  return new Promise((resolve) => {
    server.listen(port, host, () => {
      resolve(port);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        // Port taken, try next
        server.listen(0, host, () => {
          const addr = server.address();
          const actualPort = typeof addr === 'object' && addr ? addr.port : port;
          resolve(actualPort);
        });
      }
    });
  });
}

async function runDashboard(port: number, host: string): Promise<void> {
  const cwd = process.cwd();
  const scans = scansDir(cwd);

  if (!existsSync(scans)) {
    process.stderr.write(`${c.red('error:')} No .preflight/scans/ directory found. Run ${c.cyan('preflight init')} first.\n`);
    process.exit(2);
  }

  const htmlPath = path.join(scans, 'report.html');
  if (!existsSync(htmlPath)) {
    process.stderr.write(`${c.red('error:')} No scan report found. Run ${c.cyan('preflight scan')} first.\n`);
    process.exit(2);
  }

  copyDashboardAssets(cwd);

  const actualPort = await startDashboardServer(cwd, port, host);

  console.log('');
  console.log(`  ${c.bold('Preflight Dashboard')}`);
  const displayHost = host === '0.0.0.0' ? 'localhost' : host;
  console.log(`  ${c.cyan(`http://${displayHost}:${actualPort}`)}`);
  console.log('');
  console.log(`  ${c.dim('Press Ctrl+C to stop')}`);
  console.log('');

  openBrowser(`http://${displayHost}:${actualPort}`);
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
  lines.push(c.bold(`  Preflight Security Score: ${colorFn(`${score}/100`)}`));
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
    const name = sanitizeForTerminal(f.ruleName);
    const safeFile = sanitizeForTerminal(f.location.file);
    const file = c.dim(safeFile.split('/').slice(-2).join('/') + ':' + f.location.startLine);
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
    console.log(`preflight ${VERSION}`);
    process.exit(0);
  }

  // Load config (unless --no-config or init command)
  const config = (!rawArgs.noConfig && rawArgs.command !== 'init')
    ? loadConfig(process.cwd())
    : null;

  if (config && !rawArgs.quiet && !isInteractive(rawArgs.quiet)) {
    process.stderr.write(`${c.dim('Using')} ${PREFLIGHT_DIR}/${SETTINGS_FILENAME}\n`);
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
        const options = buildScanOptions(args);
        const format = options.format || 'table';

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
          ensurePreflightDir(cwd);
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
              copyDashboardAssets(cwd);
            }

            if (interactive) {
              if (agentJsonPath) {
                p.log.step(`Agent report: ${c.cyan(path.relative(cwd, agentJsonPath))}`);
                p.log.step(`Agent report: ${c.cyan(path.relative(cwd, agentMdPath!))}`);
              }
              if (dashboardPath) {
                // Start dashboard server so Mark Safe and future features work
                const actualPort = await startDashboardServer(cwd, args.port, args.host);
                const dashHost = args.host === '0.0.0.0' ? 'localhost' : args.host;
                const dashUrl = `http://${dashHost}:${actualPort}`;
                const clickable = link(c.cyan(dashUrl), dashUrl);
                p.log.step(`Dashboard: ${clickable}`);
                openBrowser(dashUrl);
              }
            } else if (!args.quiet) {
              process.stderr.write(`${c.dim('Wrote')} ${PREFLIGHT_DIR}/${SCANS_DIR}/latest.json\n`);
              if (agentJsonPath) {
                process.stderr.write(`${c.dim('Agent JSON')} ${path.relative(cwd, agentJsonPath)}\n`);
                process.stderr.write(`${c.dim('Agent MD')} ${path.relative(cwd, agentMdPath!)}\n`);
              }
              if (dashboardPath) {
                const absPath = path.resolve(dashboardPath);
                const clickable = link(`${PREFLIGHT_DIR}/${SCANS_DIR}/report.html`, fileUrl(absPath));
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
        await runDashboard(args.port, args.host);
        break;
      }

      case 'help': {
        if (isInteractive(args.quiet)) {
          p.intro(`${c.bold('Preflight')}${c.dim(' v' + VERSION)}`);
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
          p.intro(`${c.bold('Preflight')}${c.dim(' v' + VERSION)}`);
          p.note(
            `Security scanner for AI agents, prompts, and vibecoded projects.\n\n` +
            `Get started:\n` +
            `  ${c.cyan('preflight init')}           Set up .preflight/ in this project\n` +
            `  ${c.cyan('preflight scan')} [path]    Run a security scan\n` +
            `  ${c.cyan('preflight rules')}          List available rules\n` +
            `  ${c.cyan('preflight dashboard')}      View results in browser\n\n` +
            `All options:\n` +
            `  ${c.cyan('preflight help')}           Show detailed help`,
            'Quick Start',
          );
          p.outro(c.dim('https://github.com/iankiku/preflight'));
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
