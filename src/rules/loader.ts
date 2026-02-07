/**
 * Rule Loader
 * Load and validate security rules from YAML files
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { validateRuleFile, safeValidateRuleFile, type RuleType } from './schema.js';
import type { Rule } from '../types.js';

// ============================================================================
// Built-in Rules Path
// ============================================================================

// When bundled into dist/cli.js, __dirname = dist/
// Static assets live at src/rules/builtin/ relative to package root
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const BUILTIN_RULES_DIR = path.resolve(PKG_ROOT, 'src', 'rules', 'builtin');

// ============================================================================
// Rule Loading
// ============================================================================

/**
 * Load rules from a YAML file
 */
export async function loadRuleFile(filePath: string): Promise<Rule[]> {
  const content = await fs.readFile(filePath, 'utf-8');
  const parsed = parseYaml(content);
  const validated = validateRuleFile(parsed);
  return validated.rules.map(normalizeRule);
}

/**
 * Safely load rules from a YAML file (returns errors instead of throwing)
 */
export async function safeLoadRuleFile(filePath: string): Promise<{ rules: Rule[]; errors: string[] }> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = parseYaml(content);
    const result = safeValidateRuleFile(parsed);

    if (!result.success) {
      return {
        rules: [],
        errors: result.error.errors.map((e) => `${filePath}: ${e.path.join('.')}: ${e.message}`),
      };
    }

    return {
      rules: result.data.rules.map(normalizeRule),
      errors: [],
    };
  } catch (error) {
    return {
      rules: [],
      errors: [`${filePath}: ${error instanceof Error ? error.message : String(error)}`],
    };
  }
}

/**
 * Load all built-in rules
 */
export async function loadBuiltinRules(): Promise<Rule[]> {
  const rules: Rule[] = [];

  try {
    const entries = await fs.readdir(BUILTIN_RULES_DIR);
    const ymlFiles = entries.filter((f) => f.endsWith('.yml'));

    for (const file of ymlFiles) {
      const filePath = path.join(BUILTIN_RULES_DIR, file);
      const fileRules = await loadRuleFile(filePath);
      rules.push(...fileRules);
    }
  } catch {
    // Builtin directory may not exist yet
  }

  return rules;
}

/**
 * Load rules from multiple sources
 */
export async function loadRules(options: {
  includeBuiltin?: boolean;
  customFiles?: string[];
  enableRules?: string[];
  disableRules?: string[];
}): Promise<{ rules: Rule[]; errors: string[] }> {
  const { includeBuiltin = true, customFiles = [], enableRules, disableRules } = options;

  const allRules: Rule[] = [];
  const errors: string[] = [];

  // Load built-in rules
  if (includeBuiltin) {
    try {
      const builtinRules = await loadBuiltinRules();
      allRules.push(...builtinRules);
    } catch (error) {
      errors.push(`Failed to load built-in rules: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Load custom rule files
  for (const filePath of customFiles) {
    const result = await safeLoadRuleFile(filePath);
    allRules.push(...result.rules);
    errors.push(...result.errors);
  }

  // Filter rules based on enable/disable lists
  let filteredRules = allRules;

  if (enableRules && enableRules.length > 0) {
    const enableSet = new Set(enableRules);
    filteredRules = filteredRules.filter((r) => enableSet.has(r.id));
  }

  if (disableRules && disableRules.length > 0) {
    const disableSet = new Set(disableRules);
    filteredRules = filteredRules.filter((r) => !disableSet.has(r.id));
  }

  // Filter out disabled rules
  filteredRules = filteredRules.filter((r) => r.enabled !== false);

  return { rules: filteredRules, errors };
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Convert Zod-validated rule to internal Rule type
 */
function normalizeRule(rule: RuleType): Rule {
  return {
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    category: rule.category,
    patterns: rule.patterns.map((p) => {
      if (typeof p === 'string') {
        return { type: 'regex' as const, regex: p };
      }
      return p as Rule['patterns'][number];
    }),
    location: rule.location,
    requiresContext: rule.requiresContext,
    perFileLimit: rule.perFileLimit,
    message: rule.message,
    remediation: rule.remediation,
    metadata: rule.metadata,
    enabled: rule.enabled,
  };
}

/**
 * Get rule by ID
 */
export function getRuleById(rules: Rule[], id: string): Rule | undefined {
  return rules.find((r) => r.id === id);
}

/**
 * Get rules by category
 */
export function getRulesByCategory(rules: Rule[], category: Rule['category']): Rule[] {
  return rules.filter((r) => r.category === category);
}

/**
 * Get rules by severity
 */
export function getRulesBySeverity(rules: Rule[], severity: Rule['severity']): Rule[] {
  return rules.filter((r) => r.severity === severity);
}
