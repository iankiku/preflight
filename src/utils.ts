/**
 * ClawSec Utilities
 * ANSI colors, file classification, hashing
 */

import { createHash } from 'node:crypto';

// ============================================================================
// ANSI Colors (respects NO_COLOR env)
// ============================================================================

const noColor = !!process.env['NO_COLOR'];

function color(code: string, text: string): string {
  if (noColor) return text;
  return `\x1b[${code}m${text}\x1b[0m`;
}

export const c = {
  bold: (t: string) => color('1', t),
  dim: (t: string) => color('2', t),
  red: (t: string) => color('31', t),
  green: (t: string) => color('32', t),
  yellow: (t: string) => color('33', t),
  blue: (t: string) => color('34', t),
  magenta: (t: string) => color('35', t),
  cyan: (t: string) => color('36', t),
  bgRed: (t: string) => color('41', t),
  bgMagenta: (t: string) => color('45', t),
};

export const severityColor: Record<string, (t: string) => string> = {
  critical: (t: string) => c.bgRed(c.bold(t)),
  high: (t: string) => c.magenta(t),
  medium: (t: string) => c.yellow(t),
  low: (t: string) => c.blue(t),
  info: (t: string) => c.dim(t),
};

// ============================================================================
// File Classification
// ============================================================================

const LANGUAGE_MAP: Record<string, string> = {
  '.py': 'python',
  '.pyw': 'python',
  '.sh': 'bash',
  '.bash': 'bash',
  '.zsh': 'bash',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'javascript',
  '.tsx': 'javascript',
};

export function getLanguage(extension: string): string | undefined {
  return LANGUAGE_MAP[extension];
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  'coverage',
  '.nyc_output',
]);

export function shouldSkipDir(dirName: string): boolean {
  return SKIP_DIRS.has(dirName);
}

const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
  '.woff', '.woff2', '.ttf', '.eot',
  '.zip', '.tar', '.gz', '.bz2',
  '.exe', '.dll', '.so', '.dylib',
  '.wasm',
  '.pdf', '.doc', '.docx',
  '.lock',
]);

export function shouldSkipFile(extension: string): boolean {
  return SKIP_EXTENSIONS.has(extension);
}

// ============================================================================
// Frontmatter Detection
// ============================================================================

const FRONTMATTER_REGEX = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

export function parseFrontmatter(content: string): {
  hasFrontmatter: boolean;
  rawFrontmatter?: string;
  body?: string;
} {
  const match = content.match(FRONTMATTER_REGEX);
  if (!match) return { hasFrontmatter: false };
  return {
    hasFrontmatter: true,
    rawFrontmatter: match[1],
    body: match[2],
  };
}

// ============================================================================
// Hashing
// ============================================================================

export function hashString(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 12);
}

export function findingId(ruleId: string, file: string, line: number, col: number): string {
  return hashString(`${ruleId}:${file}:${line}:${col}`);
}

// ============================================================================
// Line/Column Helpers
// ============================================================================

export function getLineNumber(text: string, position: number): number {
  const upTo = text.slice(0, position);
  return (upTo.match(/\n/g) || []).length + 1;
}

export function getColumnNumber(text: string, position: number): number {
  const upTo = text.slice(0, position);
  const lastNewline = upTo.lastIndexOf('\n');
  return position - lastNewline;
}

// ============================================================================
// Context Lines
// ============================================================================

export function getContextLines(
  content: string,
  startLine: number,
  endLine: number,
  beforeCount = 3,
  afterCount = 5,
): { before: string[]; after: string[] } {
  const allLines = content.split('\n');
  const matchStart = startLine - 1;
  const matchEnd = endLine;

  const beforeStart = Math.max(0, matchStart - beforeCount);
  const afterEnd = Math.min(allLines.length, matchEnd + afterCount);

  return {
    before: allLines.slice(beforeStart, matchStart),
    after: allLines.slice(matchEnd, afterEnd),
  };
}

// ============================================================================
// Severity
// ============================================================================

import type { Severity } from './types.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

export function isSeverityAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
