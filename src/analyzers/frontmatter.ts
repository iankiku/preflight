/**
 * Frontmatter Analyzer
 * Checks YAML frontmatter fields against rule conditions
 */

import type { FileEntry, Rule, FrontmatterPattern, Finding } from '../types.js';
import { findingId, getContextLines } from '../utils.js';

// ============================================================================
// Dot-notation field traversal
// ============================================================================

function getNestedField(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

// ============================================================================
// Condition matching
// ============================================================================

function matchesCondition(pattern: FrontmatterPattern, value: unknown): boolean {
  if (pattern.exists !== undefined) {
    if (pattern.exists ? value !== undefined : value === undefined) return true;
  }

  if (pattern.equals !== undefined) {
    if (value === pattern.equals) return true;
  }

  if (pattern.contains !== undefined) {
    if (typeof value === 'string' && value.includes(pattern.contains)) return true;
    if (Array.isArray(value) && value.some((v) => String(v).includes(pattern.contains!))) return true;
  }

  if (pattern.matches !== undefined) {
    if (typeof value === 'string') {
      try {
        if (new RegExp(pattern.matches, 'i').test(value)) return true;
      } catch {
        // Invalid regex — skip
      }
    }
  }

  return false;
}

// ============================================================================
// Public API
// ============================================================================

export function runFrontmatterRules(files: FileEntry[], rules: Rule[]): Finding[] {
  const frontmatterRules = rules.filter((r) =>
    r.patterns.some((p) => p.type === 'frontmatter'),
  );

  if (frontmatterRules.length === 0) return [];

  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.hasFrontmatter || !file.frontmatter) continue;

    for (const rule of frontmatterRules) {
      // Context gate
      if (rule.requiresContext) {
        try {
          if (!new RegExp(rule.requiresContext, 'im').test(file.content)) continue;
        } catch {
          continue;
        }
      }

      let matched = false;
      for (const pattern of rule.patterns) {
        if (pattern.type !== 'frontmatter') continue;
        if (rule.perFileLimit && matched) break;

        const value = getNestedField(file.frontmatter, pattern.field);

        if (matchesCondition(pattern, value)) {
          const snippet = `${pattern.field}: ${JSON.stringify(value)}`;
          const ctx = getContextLines(file.content, 2, 2);
          findings.push({
            id: findingId(rule.id, file.path, 2, 1),
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            message: rule.message.replace(/\{match\}/g, snippet),
            location: {
              file: file.path,
              startLine: 2,
              endLine: 2,
              startColumn: 1,
              snippet,
              contextBefore: ctx.before,
              contextAfter: ctx.after,
            },
            remediation: rule.remediation,
            metadata: rule.metadata,
          });
          matched = true;
        }
      }
    }
  }

  return findings;
}
