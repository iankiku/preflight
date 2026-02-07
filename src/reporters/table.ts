/**
 * Table Reporter
 * Beautiful terminal output — the "whoa moment" from the PRD
 */

import type { ScanResult, Finding, Severity } from '../types.js';
import { c, severityColor } from '../utils.js';

const FILLED = '\u2588'; // █
const EMPTY = '\u2591';  // ░

function scoreColor(score: number): (t: string) => string {
  if (score >= 90) return c.green;
  if (score >= 70) return c.yellow;
  if (score >= 50) return c.yellow;
  return c.red;
}

function bar(filled: number, total: number): string {
  const width = 10;
  const blocks = total > 0 ? Math.round((filled / total) * width) : 0;
  return FILLED.repeat(blocks) + EMPTY.repeat(width - blocks);
}

function scoreBar(score: number): string {
  const blocks = Math.round(score / 10);
  const colorFn = scoreColor(score);
  return colorFn(FILLED.repeat(blocks)) + c.dim(EMPTY.repeat(10 - blocks));
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + '\u2026';
}

export function formatTable(result: ScanResult): string {
  const { findings, summary, score, filesScanned, rulesApplied, duration } = result;
  const lines: string[] = [];

  // Empty line for breathing room
  lines.push('');

  // No findings — all clear
  if (findings.length === 0) {
    lines.push(c.green(c.bold('  All clear! Score: 100/100')));
    lines.push('');
    if (result.suppressedCount && result.suppressedCount > 0) {
      lines.push(c.dim(`  ${result.suppressedCount} findings suppressed (marked safe)`));
    }
    lines.push(c.dim(`  Scanned ${filesScanned} files with ${rulesApplied} rules in ${duration}ms`));
    lines.push('');
    return lines.join('\n');
  }

  // Score headline
  const colorFn = scoreColor(score);
  lines.push(c.bold(`  ClawSec Security Score: ${colorFn(`${score}/100`)}`));
  lines.push(`  ${scoreBar(score)}`);
  lines.push('');

  // Severity summary — only show severities with findings
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const count = summary[sev];
    if (count === 0) continue;
    const label = sev.padEnd(8);
    const colorize = severityColor[sev] ?? c.dim;
    const sevBar = bar(count, summary.total);
    lines.push(`  ${colorize(String(count).padStart(2))} ${label}  ${colorize(sevBar)}`);
  }
  lines.push('');

  // Top findings (up to 10), sorted by severity
  const sorted = [...findings].sort((a, b) => {
    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[a.severity] - order[b.severity];
  });
  const top = sorted.slice(0, 10);

  lines.push(c.bold('  Top risks:'));
  for (const f of top) {
    const id = c.dim(f.ruleId.padEnd(13));
    const name = c.bold(truncate(f.ruleName, 30).padEnd(30));
    const loc = c.blue(`${f.location.file}:${f.location.startLine}`);
    const editorLink = c.cyan(`vscode://file/${f.location.file}:${f.location.startLine}`);
    lines.push(`  ${id} ${name}  ${loc}`);

    // Context preview with surrounding lines
    const pad = ' '.repeat(14);
    const ctxBefore = f.location.contextBefore || [];
    const ctxAfter = f.location.contextAfter || [];
    const snippetLines = f.location.snippet ? f.location.snippet.split('\n') : [];
    const matchStart = f.location.startLine;

    if (ctxBefore.length > 0 || snippetLines.length > 0) {
      // Lines before
      for (let i = 0; i < ctxBefore.length; i++) {
        const ln = matchStart - ctxBefore.length + i;
        lines.push(`${pad}${c.dim(String(ln).padStart(4) + ' │ ' + truncate(ctxBefore[i], 72))}`);
      }
      // Matched line(s) — highlighted
      for (let i = 0; i < snippetLines.length; i++) {
        const ln = matchStart + i;
        lines.push(`${pad}${c.red(c.bold(String(ln).padStart(4) + ' │ ' + truncate(snippetLines[i], 72)))}`);
      }
      // Lines after
      const afterStart = matchStart + snippetLines.length;
      for (let i = 0; i < Math.min(ctxAfter.length, 3); i++) {
        const ln = afterStart + i;
        lines.push(`${pad}${c.dim(String(ln).padStart(4) + ' │ ' + truncate(ctxAfter[i], 72))}`);
      }
    } else if (f.location.snippet) {
      const snippet = truncate(f.location.snippet.split('\n')[0].trim(), 80);
      lines.push(`${pad}${c.dim(snippet)}`);
    }
    // Editor link
    lines.push(`${pad}${c.dim('Open: ')}${editorLink}`);
    lines.push('');
  }

  if (findings.length > 10) {
    lines.push(c.dim(`  ... and ${findings.length - 10} more findings`));
  }
  lines.push('');

  // Footer
  lines.push(c.dim(`  Scanned ${filesScanned} files with ${rulesApplied} rules in ${duration}ms`));
  if (result.suppressedCount && result.suppressedCount > 0) {
    lines.push(c.dim(`  ${result.suppressedCount} findings suppressed (marked safe)`));
  }
  lines.push(`  Dashboard ${c.cyan('\u2192')} ${c.cyan('.clawsec-report.html')}`);
  lines.push('');

  return lines.join('\n');
}
