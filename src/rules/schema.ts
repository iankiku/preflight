/**
 * Rule Schema
 * Zod validation schemas for Preflight security rules
 */

import { z } from 'zod';

// ============================================================================
// Enums
// ============================================================================

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

export const CategorySchema = z.enum([
  'prompt-injection',
  'data-exfiltration',
  'code-execution',
  'metadata-abuse',
  'secrets',
  'supply-chain',
  'misconfiguration',
]);

export const LocationTypeSchema = z.enum(['frontmatter', 'body', 'scripts', 'all']);

// ============================================================================
// Pattern Schemas
// ============================================================================

export const RegexPatternSchema = z.object({
  type: z.literal('regex').optional().default('regex'),
  regex: z.string().min(1),
  flags: z.string().optional(),
  /** Regex patterns that suppress a match when found on the same line */
  excludePatterns: z.array(z.string()).optional(),
});

export const FrontmatterPatternSchema = z.object({
  type: z.literal('frontmatter'),
  field: z.string().min(1),
  equals: z.unknown().optional(),
  contains: z.string().optional(),
  matches: z.string().optional(),
  exists: z.boolean().optional(),
});

export const AstPatternSchema = z.object({
  type: z.literal('ast'),
  query: z.string().min(1),
  lang: z.string().optional(),
});

// Support shorthand: just a string is treated as regex
export const PatternSchema = z.union([
  z.string().transform((s) => ({ type: 'regex' as const, regex: s })),
  RegexPatternSchema.transform((p) => ({ ...p, type: 'regex' as const })),
  FrontmatterPatternSchema,
  AstPatternSchema,
]);

// ============================================================================
// Location Schema
// ============================================================================

export const RuleLocationSchema = z.object({
  include: z.array(LocationTypeSchema).optional(),
  exclude: z.array(z.string()).optional(),
});

// ============================================================================
// Metadata Schema
// ============================================================================

export const RuleMetadataSchema = z.object({
  owasp: z.string().optional(),
  cwe: z.string().optional(),
  references: z.array(z.string()).optional(),
});

// ============================================================================
// Rule Schema
// ============================================================================

export const RuleSchema = z.object({
  id: z.string().regex(/^PREFLIGHT-\d{3,4}$/, 'Rule ID must be PREFLIGHT-XXX or PREFLIGHT-XXXX format'),
  name: z.string().min(1),
  severity: SeveritySchema,
  category: CategorySchema,
  patterns: z.array(PatternSchema).min(1),
  location: RuleLocationSchema.optional(),
  requiresContext: z.string().optional(),
  perFileLimit: z.boolean().optional(),
  message: z.string().min(1),
  remediation: z.string().optional(),
  metadata: RuleMetadataSchema.optional(),
  enabled: z.boolean().optional().default(true),
});

// ============================================================================
// Rule File Schema
// ============================================================================

export const RuleFileSchema = z.object({
  version: z.string().optional(),
  rules: z.array(RuleSchema),
});

// ============================================================================
// Type Exports
// ============================================================================

export type SeverityType = z.infer<typeof SeveritySchema>;
export type CategoryType = z.infer<typeof CategorySchema>;
export type PatternType = z.infer<typeof PatternSchema>;
export type RuleType = z.infer<typeof RuleSchema>;
export type RuleFileType = z.infer<typeof RuleFileSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

export function validateRule(rule: unknown): RuleType {
  return RuleSchema.parse(rule);
}

export function validateRuleFile(file: unknown): RuleFileType {
  return RuleFileSchema.parse(file);
}

export function safeValidateRule(rule: unknown): { success: true; data: RuleType } | { success: false; error: z.ZodError } {
  const result = RuleSchema.safeParse(rule);
  return result;
}

export function safeValidateRuleFile(file: unknown): { success: true; data: RuleFileType } | { success: false; error: z.ZodError } {
  const result = RuleFileSchema.safeParse(file);
  return result;
}
