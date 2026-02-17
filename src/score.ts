/**
 * Preflight Security Score Calculator
 * Starts at 100, deducts per finding by severity
 */

import type { Finding, Severity } from './types.js';

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 15,
  high: 8,
  medium: 3,
  low: 1,
  info: 0,
};

export function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY_PENALTY[finding.severity];
  }
  return Math.max(0, score);
}
