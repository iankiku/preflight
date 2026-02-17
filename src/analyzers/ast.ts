/**
 * Tree-sitter AST Analyzer
 * Semantic code pattern analysis using tree-sitter queries
 */

import { Parser, Language, Query } from 'web-tree-sitter';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findingId, getContextLines } from '../utils.js';
import type { FileEntry, Rule, AstPattern, Finding } from '../types.js';

// ============================================================================
// Grammar Resolution
// ============================================================================

// When bundled into dist/cli.js, __dirname = dist/
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const GRAMMARS_DIR = path.resolve(PKG_ROOT, 'src', 'grammars');

// ============================================================================
// Module-Level Parser Cache
// ============================================================================

let initialized = false;
const parsers = new Map<string, Parser>();
const languages = new Map<string, Language>();

async function ensureInit(): Promise<void> {
  if (initialized) return;
  await Parser.init();
  initialized = true;
}

async function getParser(lang: string): Promise<Parser | null> {
  if (parsers.has(lang)) return parsers.get(lang)!;
  try {
    const wasmPath = path.join(GRAMMARS_DIR, `tree-sitter-${lang}.wasm`);
    const language = await Language.load(wasmPath);
    const parser = new Parser();
    parser.setLanguage(language);
    parsers.set(lang, parser);
    languages.set(lang, language);
    return parser;
  } catch (e) {
    console.error(
      `[preflight] Could not load grammar for ${lang}: ${e instanceof Error ? e.message : e}`,
    );
    return null;
  }
}

// ============================================================================
// AST Rule Runner
// ============================================================================

export async function runAstRules(
  files: FileEntry[],
  rules: Rule[],
): Promise<Finding[]> {
  const astRules = rules.filter((r) =>
    r.patterns.some((p) => p.type === 'ast'),
  );
  if (astRules.length === 0) return [];

  await ensureInit();

  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.language) continue;

    const parser = await getParser(file.language);
    if (!parser) continue;

    const tree = parser.parse(file.content);
    if (!tree) continue;

    const language = languages.get(file.language)!;

    for (const rule of astRules) {
      // Context gate
      if (rule.requiresContext) {
        try {
          if (!new RegExp(rule.requiresContext, 'im').test(file.content)) continue;
        } catch {
          continue;
        }
      }

      let ruleMatched = false;
      for (const pattern of rule.patterns) {
        if (pattern.type !== 'ast') continue;
        if (rule.perFileLimit && ruleMatched) break;

        const astPattern = pattern as AstPattern;
        if (astPattern.lang && astPattern.lang !== file.language) continue;

        let query: Query | null = null;
        try {
          query = new Query(language, astPattern.query);
          const matches = query.matches(tree.rootNode);

          for (const match of matches) {
            if (match.captures.length === 0) continue;
            if (rule.perFileLimit && ruleMatched) break;

            const node = match.captures[0].node;
            const startLine = node.startPosition.row + 1;
            const endLine = node.endPosition.row + 1;
            const startColumn = node.startPosition.column + 1;
            const endColumn = node.endPosition.column + 1;
            const snippet = node.text;

            const ctx = getContextLines(file.content, startLine, endLine);
            findings.push({
              id: findingId(rule.id, file.relativePath, startLine, startColumn),
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              category: rule.category,
              message: rule.message.replace(/\{match\}/g, snippet.slice(0, 100)),
              location: {
                file: file.relativePath,
                startLine,
                endLine,
                startColumn,
                endColumn,
                snippet: snippet.slice(0, 200),
                contextBefore: ctx.before,
                contextAfter: ctx.after,
              },
              remediation: rule.remediation,
              metadata: rule.metadata,
            });
            ruleMatched = true;
          }
        } catch (e) {
          console.error(
            `[preflight] Query error for rule ${rule.id} on ${file.relativePath}: ${e instanceof Error ? e.message : e}`,
          );
        } finally {
          if (query?.delete) query.delete();
        }
      }
    }

    tree.delete();
  }

  return findings;
}
