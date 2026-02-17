/**
 * Preflight Core Types
 * Type definitions for the v1.0 pipeline scanner
 */

// ============================================================================
// Severity and Categories
// ============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'prompt-injection'
  | 'data-exfiltration'
  | 'code-execution'
  | 'metadata-abuse'
  | 'secrets'
  | 'supply-chain'
  | 'misconfiguration';

// ============================================================================
// File Discovery Types
// ============================================================================

export interface FileEntry {
  /** Absolute file path */
  path: string;
  /** Path relative to scan root */
  relativePath: string;
  /** File contents (UTF-8) */
  content: string;
  /** File extension (e.g., '.md', '.py', '.js') */
  extension: string;
  /** Whether file has YAML frontmatter (--- delimited) */
  hasFrontmatter: boolean;
  /** Parsed frontmatter fields (if hasFrontmatter) */
  frontmatter?: Record<string, unknown>;
  /** Raw frontmatter YAML string (if hasFrontmatter) */
  rawFrontmatter?: string;
  /** Body content after frontmatter (if hasFrontmatter) */
  body?: string;
  /** Programming language for code files (python, bash, javascript) */
  language?: string;
}

// ============================================================================
// Rule Types
// ============================================================================

export interface RegexPattern {
  type: 'regex';
  regex: string;
  flags?: string;
}

export interface FrontmatterPattern {
  type: 'frontmatter';
  field: string;
  equals?: unknown;
  contains?: string;
  matches?: string;
  exists?: boolean;
}

export interface AstPattern {
  type: 'ast';
  query: string;
  lang?: string;
}

export type Pattern = RegexPattern | FrontmatterPattern | AstPattern;

export interface RuleLocation {
  include?: ('frontmatter' | 'body' | 'scripts' | 'all')[];
  exclude?: string[];
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  category: Category;
  patterns: Pattern[];
  location?: RuleLocation;
  /** Secondary context regex — rule only fires when the full file content also matches this pattern. */
  requiresContext?: string;
  /** If true, report at most one finding per file for this rule (default: false). */
  perFileLimit?: boolean;
  message: string;
  remediation?: string;
  metadata?: {
    owasp?: string;
    cwe?: string;
    references?: string[];
  };
  enabled?: boolean;
}

export interface RuleFile {
  version?: string;
  rules: Rule[];
}

// ============================================================================
// Finding Types
// ============================================================================

export interface FindingLocation {
  file: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: string;
  /** Lines before the match for context display */
  contextBefore?: string[];
  /** Lines after the match for context display */
  contextAfter?: string[];
}

export interface Finding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: Category;
  message: string;
  location: FindingLocation;
  remediation?: string;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Suppression Types
// ============================================================================

export interface Suppression {
  ruleId: string;
  file: string;
  suppressedAt: string;
  reason?: string;
}

export interface SuppressionsFile {
  version: '1';
  suppressions: Suppression[];
}

// ============================================================================
// Scan Result Types
// ============================================================================

export interface ScanResult {
  timestamp: string;
  duration: number;
  scanRoot: string;
  projectName?: string;
  filesScanned: number;
  rulesApplied: number;
  score: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  errors: ScanError[];
  suppressedCount?: number;
  suppressions?: Suppression[];
}

export interface ScanError {
  file?: string;
  message: string;
  code?: string;
}

// ============================================================================
// CLI Types
// ============================================================================

export interface ScanOptions {
  paths: string[];
  format?: 'json' | 'sarif' | 'table' | 'html' | 'agent';
  output?: string;
  minSeverity?: Severity;
  severities?: Severity[];
  failOn?: Severity;
  scoreThreshold?: number;
  excludePatterns?: string[];
  enableRules?: string[];
  disableRules?: string[];
  ruleFiles?: string[];
  onlySkills?: boolean;
  quiet?: boolean;
}
