/**
 * ClawSec Analyze Pipeline Router
 * Dispatches files to the appropriate analyzers based on rule pattern types
 */

import type { FileEntry, Finding, Rule } from './types.js';
import { runPatternRules } from './analyzers/pattern.js';
import { runFrontmatterRules } from './analyzers/frontmatter.js';
import { runAstRules } from './analyzers/ast.js';

export async function analyze(files: FileEntry[], rules: Rule[]): Promise<Finding[]> {
  const patternRules = rules.filter(r => r.patterns.some(p => p.type === 'regex'));
  const fmRules = rules.filter(r => r.patterns.some(p => p.type === 'frontmatter'));
  const astRules = rules.filter(r => r.patterns.some(p => p.type === 'ast'));

  const patternFindings = runPatternRules(files, patternRules);

  const fmFiles = files.filter(f => f.hasFrontmatter);
  const fmFindings = runFrontmatterRules(fmFiles, fmRules);

  const codeFiles = files.filter(f => f.language);
  const astFindings = await runAstRules(codeFiles, astRules);

  return [...patternFindings, ...fmFindings, ...astFindings];
}
