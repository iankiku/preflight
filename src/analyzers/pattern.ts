/**
 * Pattern Analyzer — regex pattern matching against file content
 * Pure function: no class, no registry, no BaseAnalyzer.
 */

import { unified } from 'unified';
import remarkParse from 'remark-parse';
import { visit } from 'unist-util-visit';
import { minimatch } from 'minimatch';
import { findingId, getLineNumber, getColumnNumber, getContextLines } from '../utils.js';
import type { FileEntry, Rule, Finding, RegexPattern, RuleLocation } from '../types.js';

// ============================================================================
// Content Region — a slice of file content with its offset in the full file
// ============================================================================

interface ContentRegion {
  content: string;
  /** Byte offset of this region within the full file.content */
  offset: number;
}

// ============================================================================
// Public API
// ============================================================================

export function runPatternRules(files: FileEntry[], rules: Rule[]): Finding[] {
  const regexRules = rules.filter(hasRegexPattern);
  if (regexRules.length === 0) return [];

  const findings: Finding[] = [];

  for (const file of files) {
    // Track which rules have already matched this file (for perFileLimit)
    const matchedRulesForFile = new Set<string>();

    for (const rule of regexRules) {
      // Per-file dedup: skip if this rule already matched this file
      if (rule.perFileLimit && matchedRulesForFile.has(rule.id)) continue;

      // File exclusion: skip if file matches any exclusion glob pattern
      if (shouldExcludeFile(file, rule.location?.exclude)) continue;

      // Context gate: skip this rule for this file if requiresContext doesn't match
      if (rule.requiresContext) {
        try {
          if (!new RegExp(rule.requiresContext, 'im').test(file.content)) continue;
        } catch {
          // Invalid context regex — skip the rule
          continue;
        }
      }

      for (const pattern of rule.patterns) {
        if (pattern.type !== 'regex') continue;
        if (rule.perFileLimit && matchedRulesForFile.has(rule.id)) break;

        const regions = getContentRegions(file, rule.location);
        for (const region of regions) {
          if (rule.perFileLimit && matchedRulesForFile.has(rule.id)) break;
          matchRegexInRegion(file, rule, pattern, region, findings, rule.perFileLimit ? matchedRulesForFile : undefined);
        }
      }
    }
  }

  return findings;
}

// ============================================================================
// Filtering
// ============================================================================

function hasRegexPattern(rule: Rule): boolean {
  return rule.patterns.some((p) => p.type === 'regex');
}

/**
 * Check if a file should be excluded from a rule based on location.exclude patterns.
 * Uses minimatch for glob matching against the file's relative path.
 */
function shouldExcludeFile(file: FileEntry, excludePatterns?: string[]): boolean {
  if (!excludePatterns || excludePatterns.length === 0) return false;
  return excludePatterns.some(pattern =>
    minimatch(file.relativePath, pattern, { dot: true }) ||
    minimatch(file.path, pattern, { dot: true })
  );
}

// ============================================================================
// Content Region Resolution
// ============================================================================

function getContentRegions(file: FileEntry, location?: RuleLocation): ContentRegion[] {
  const include = location?.include ?? ['all'];
  const regions: ContentRegion[] = [];

  for (const loc of include) {
    switch (loc) {
      case 'all':
        regions.push({ content: file.content, offset: 0 });
        break;

      case 'frontmatter':
        if (file.hasFrontmatter && file.rawFrontmatter) {
          const offset = file.content.indexOf(file.rawFrontmatter);
          regions.push({
            content: file.rawFrontmatter,
            offset: offset !== -1 ? offset : 0,
          });
        }
        break;

      case 'body': {
        const body = file.hasFrontmatter ? file.body : file.content;
        if (body) {
          const offset = file.content.indexOf(body);
          regions.push({
            content: body,
            offset: offset !== -1 ? offset : 0,
          });
        }
        break;
      }

      case 'scripts':
        resolveScriptsRegions(file, regions);
        break;
    }
  }

  return regions;
}

function resolveScriptsRegions(file: FileEntry, regions: ContentRegion[]): void {
  const isMarkdown = file.extension === '.md';

  if (isMarkdown) {
    // Parse markdown body (or full content) to extract code blocks
    const source = file.body ?? file.content;
    const tree = unified().use(remarkParse).parse(source);
    const sourceOffset = file.body ? file.content.indexOf(file.body) : 0;

    visit(tree, 'code', (node: any) => {
      if (node.value) {
        // Locate the code block content in the full file for accurate offset
        const blockOffset = file.content.indexOf(node.value, sourceOffset !== -1 ? sourceOffset : 0);
        regions.push({
          content: node.value,
          offset: blockOffset !== -1 ? blockOffset : 0,
        });
      }
    });
  }

  // For code files (language is set), search the entire content
  if (file.language) {
    regions.push({ content: file.content, offset: 0 });
  }
}

// ============================================================================
// Regex Matching
// ============================================================================

function matchRegexInRegion(
  file: FileEntry,
  rule: Rule,
  pattern: RegexPattern,
  region: ContentRegion,
  findings: Finding[],
  /** When provided, adds rule.id on first match and stops — enables per-file dedup. */
  limitSet?: Set<string>,
): void {
  try {
    const userFlags = pattern.flags || 'im';
    const flags = userFlags.includes('g') ? userFlags : 'g' + userFlags;
    const regex = new RegExp(pattern.regex, flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(region.content)) !== null) {
      const absolutePos = region.offset + match.index;
      const matchText = match[0];
      const startLine = getLineNumber(file.content, absolutePos);
      const endLine = getLineNumber(file.content, absolutePos + matchText.length);
      const startColumn = getColumnNumber(file.content, absolutePos);

      // Exclude-pattern suppression: skip if the matched line also matches any exclude regex
      if (pattern.excludePatterns && pattern.excludePatterns.length > 0) {
        const lines = file.content.split('\n');
        const matchedLine = lines[startLine - 1] || '';
        const excluded = pattern.excludePatterns.some((ep) => {
          try { return new RegExp(ep, 'i').test(matchedLine); } catch { return false; }
        });
        if (excluded) {
          if (match.index === regex.lastIndex) regex.lastIndex++;
          continue;
        }
      }

      const id = findingId(rule.id, file.path, startLine, startColumn);
      const snippet = matchText.slice(0, 200);
      const message = rule.message.replace(/\{match\}/g, matchText.slice(0, 100));
      const ctx = getContextLines(file.content, startLine, endLine);

      findings.push({
        id,
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        message,
        location: {
          file: file.path,
          startLine,
          endLine,
          startColumn,
          snippet,
          contextBefore: ctx.before,
          contextAfter: ctx.after,
        },
        remediation: rule.remediation,
        metadata: rule.metadata,
      });

      // Per-file limit: record the match and stop immediately
      if (limitSet) {
        limitSet.add(rule.id);
        return;
      }

      // Prevent infinite loop on zero-length matches
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  } catch {
    // Invalid regex — skip silently
  }
}
