/**
 * Preflight File Discovery Engine
 * Walks directories, classifies files, and builds FileEntry objects for the scan pipeline.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { glob } from 'glob';
import { minimatch } from 'minimatch';
import { parse as parseYaml } from 'yaml';
import type { FileEntry } from './types.js';
import { shouldSkipFile, parseFrontmatter, getLanguage } from './utils.js';

const MAX_FILE_SIZE = 1_048_576; // 1 MB
const SKILLS_FILES = new Set(['skills.md', 'skill.md']);

// NOTE: The glob call uses `dot: false`, so dotfiles/dotdirs (e.g. .git, .env,
// .eslintrc) are already excluded from matching. Dotfile patterns below are kept
// as defense-in-depth in case `dot` is ever changed.
const DEFAULT_IGNORE = [
  // Dependencies & package managers
  '**/node_modules/**',
  '**/vendor/**',

  // Build output
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/.output/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/*.d.ts',

  // Version control
  '**/.git/**',

  // Preflight own output
  '**/.preflight/**',

  // Python
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.tox/**',

  // Test directories & files
  '**/__tests__/**',
  '**/*.test.*',
  '**/*.spec.*',
  '**/tests/**',
  '**/test/**',

  // Coverage & caches
  '**/coverage/**',
  '**/.nyc_output/**',
  '**/.cache/**',
  '**/.turbo/**',
  '**/.parcel-cache/**',

  // Environment / secrets
  '**/.env',
  '**/.env.*',

  // Config files (non-dotfile)
  '**/tsconfig*.json',
  '**/jest.config.*',
  '**/vitest.config.*',
  '**/webpack.config.*',
  '**/vite.config.*',
  '**/rollup.config.*',
  '**/eslint.config.*',
  '**/prettier.config.*',
  '**/tailwind.config.*',
  '**/postcss.config.*',
  '**/next.config.*',
  '**/babel.config.*',
  '**/turbo.json',
  '**/nx.json',

  // Config files (dotfile — redundant with dot:false, kept for safety)
  '**/.eslintrc*',
  '**/.prettierrc*',
  '**/.babelrc',
];

interface ParsedIgnore {
  ignore: string[];
  negate: string[];
}

function parseGitignorePatterns(content: string): ParsedIgnore {
  const ignore: string[] = [];
  const negate: string[] = [];

  const lines = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));

  for (const pattern of lines) {
    const isNegation = pattern.startsWith('!');
    let cleaned = isNegation ? pattern.slice(1) : pattern;
    // Strip leading slash — it means "relative to repo root" which maps to scan root
    if (cleaned.startsWith('/')) cleaned = cleaned.slice(1);
    // Directory patterns (trailing /) should match all contents
    if (cleaned.endsWith('/')) {
      cleaned = cleaned + '**';
    }
    // If pattern doesn't already contain a glob wildcard prefix, wrap it so glob matches at any depth
    if (!cleaned.startsWith('**/')) {
      cleaned = `**/${cleaned}`;
    }
    if (isNegation) {
      negate.push(cleaned);
    } else {
      ignore.push(cleaned);
    }
  }

  return { ignore, negate };
}

async function buildFileEntry(
  absolutePath: string,
  scanRoot: string,
  scanRootReal: string,
  onlySkills: boolean,
): Promise<FileEntry | null> {
  const baseName = path.basename(absolutePath).toLowerCase();
  if (onlySkills && !SKILLS_FILES.has(baseName)) return null;
  const ext = path.extname(absolutePath);

  if (shouldSkipFile(ext)) return null;

  try {
    const stat = await fs.lstat(absolutePath);
    if (stat.isSymbolicLink()) return null;
    if (!stat.isFile() || stat.size > MAX_FILE_SIZE) return null;
  } catch {
    return null;
  }

  // Ensure the file resolves within the scan root (prevents symlink traversal)
  try {
    const realPath = await fs.realpath(absolutePath);
    const rel = path.relative(scanRootReal, realPath);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
  } catch {
    return null;
  }

  let content: string;
  try {
    content = await fs.readFile(absolutePath, 'utf-8');
  } catch {
    return null;
  }

  const fm = parseFrontmatter(content);
  const language = getLanguage(ext);

  const entry: FileEntry = {
    path: absolutePath,
    relativePath: path.relative(scanRoot, absolutePath),
    content,
    extension: ext,
    hasFrontmatter: fm.hasFrontmatter,
    language,
  };

  if (fm.hasFrontmatter && fm.rawFrontmatter !== undefined) {
    entry.rawFrontmatter = fm.rawFrontmatter;
    entry.body = fm.body;
    try {
      entry.frontmatter = parseYaml(fm.rawFrontmatter) as Record<string, unknown>;
    } catch {
      // Malformed YAML — still keep the raw string, just skip parsed object
    }
  }

  return entry;
}

export async function discoverFiles(
  targetPath: string,
  options?: { ignore?: string[]; onlySkills?: boolean },
): Promise<FileEntry[]> {
  const resolved = path.resolve(targetPath);
  const onlySkills = options?.onlySkills !== false;

  // Single file path
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) {
      const scanRoot = path.dirname(resolved);
      const scanRootReal = await fs.realpath(scanRoot).catch(() => scanRoot);
      const entry = await buildFileEntry(resolved, scanRoot, scanRootReal, onlySkills);
      return entry ? [entry] : [];
    }
  } catch {
    return [];
  }

  // Directory — discover all files
  const scanRoot = resolved;
  const scanRootReal = await fs.realpath(scanRoot).catch(() => scanRoot);

  const ignorePatterns = [...DEFAULT_IGNORE];
  const negatePatterns: string[] = [];

  // Read .gitignore from scan root
  try {
    const gitignoreContent = await fs.readFile(path.join(scanRoot, '.gitignore'), 'utf-8');
    const parsed = parseGitignorePatterns(gitignoreContent);
    ignorePatterns.push(...parsed.ignore);
    negatePatterns.push(...parsed.negate);
  } catch {
    // No .gitignore — that's fine
  }

  // Read .preflightignore from scan root
  try {
    const preflightignoreContent = await fs.readFile(path.join(scanRoot, '.preflightignore'), 'utf-8');
    const parsed = parseGitignorePatterns(preflightignoreContent);
    ignorePatterns.push(...parsed.ignore);
    negatePatterns.push(...parsed.negate);
  } catch {
    // No .preflightignore — that's fine
  }

  // Merge user-supplied ignore patterns
  if (options?.ignore) {
    ignorePatterns.push(...options.ignore);
  }

  // First pass: glob with ignore patterns (negation not supported by glob ignore)
  let filePaths = await glob('**/*', {
    cwd: scanRoot,
    ignore: ignorePatterns,
    nodir: true,
    dot: false,
  });

  // Second pass: re-include files matching negation patterns from .gitignore / .preflightignore
  if (negatePatterns.length > 0) {
    const allPaths = await glob('**/*', {
      cwd: scanRoot,
      ignore: DEFAULT_IGNORE,
      nodir: true,
      dot: false,
    });
    const existingSet = new Set(filePaths);
    for (const rel of allPaths) {
      if (!existingSet.has(rel) && negatePatterns.some((p) => minimatch(rel, p))) {
        filePaths.push(rel);
      }
    }
  }

  const entries: FileEntry[] = [];

  // Process in parallel batches for performance
  const results = await Promise.all(
    filePaths.map((relPath) => buildFileEntry(path.join(scanRoot, relPath), scanRoot, scanRootReal, onlySkills)),
  );

  for (const entry of results) {
    if (entry) entries.push(entry);
  }

  return entries;
}
