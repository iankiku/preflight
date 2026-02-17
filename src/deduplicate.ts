/**
 * Preflight Finding Deduplication
 * Removes duplicate findings and sorts by severity, file, line
 */

import type { Finding } from './types.js';
import { compareSeverity } from './utils.js';

export function deduplicate(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.location.file}:${finding.location.startLine}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(finding);
    }
  }

  return unique.sort((a, b) => {
    const bySeverity = compareSeverity(a.severity, b.severity);
    if (bySeverity !== 0) return bySeverity;

    const byFile = a.location.file.localeCompare(b.location.file);
    if (byFile !== 0) return byFile;

    return a.location.startLine - b.location.startLine;
  });
}
