/**
 * SARIF Reporter
 * Output scan results as SARIF 2.1.0 for GitHub Code Scanning
 */

import type { ScanResult, Finding, Rule, Severity } from '../types.js';

const SEVERITY_TO_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function formatSarif(result: ScanResult, rules: Rule[]): string {
  // Build unique rules referenced by findings
  const referencedRuleIds = new Set(result.findings.map(f => f.ruleId));
  const ruleList = rules.filter(r => referencedRuleIds.has(r.id));
  const ruleIndexMap = new Map<string, number>();
  ruleList.forEach((r, i) => ruleIndexMap.set(r.id, i));

  const reportingDescriptors = ruleList.map(r => {
    const descriptor: Record<string, unknown> = {
      id: r.id,
      name: r.name,
      shortDescription: { text: r.message },
      properties: { tags: [r.category] },
    };

    if (r.metadata?.cwe) {
      const cweNumber = r.metadata.cwe.replace(/\D/g, '');
      if (cweNumber) {
        descriptor.helpUri = `https://cwe.mitre.org/data/definitions/${cweNumber}.html`;
      }
    }

    return descriptor;
  });

  const results = result.findings.map(f => {
    const sarifResult: Record<string, unknown> = {
      ruleId: f.ruleId,
      ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
      level: SEVERITY_TO_LEVEL[f.severity],
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.location.file,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.location.startLine,
              startColumn: f.location.startColumn ?? 1,
              endLine: f.location.endLine,
              endColumn: f.location.endColumn ?? 1,
            },
          },
        },
      ],
    };

    return sarifResult;
  });

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Preflight',
            version: '1.0.0',
            informationUri: 'https://github.com/iankiku/preflight',
            rules: reportingDescriptors,
          },
        },
        results,
        properties: { 'preflight-score': result.score },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
