/**
 * ClawSec File Discovery Engine
 * Walks directories, classifies files, and builds FileEntry objects for the scan pipeline.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { glob } from 'glob';
import { parse as parseYaml } from 'yaml';
import type { FileEntry } from './types.js';
import { shouldSkipFile, parseFrontmatter, getLanguage } from './utils.js';

const MAX_FILE_SIZE = 1_048_576; // 1 MB

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

  // ClawSec own output
  '**/.clawsec/**',

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

function parseGitignorePatterns(content: string): string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((pattern) => {
      // Strip leading slash — it means "relative to repo root" which maps to scan root
      let cleaned = pattern.startsWith('/') ? pattern.slice(1) : pattern;
      // Directory patterns (trailing /) should match all contents
      if (cleaned.endsWith('/')) {
        cleaned = cleaned + '**';
      }
      // If pattern doesn't already contain a glob wildcard prefix, wrap it so glob matches at any depth
      if (!cleaned.startsWith('**/') && !cleaned.startsWith('!')) {
        return `**/${cleaned}`;
      }
      return cleaned;
    })
    // Drop negation patterns — glob ignore doesn't support them well
    .filter((p) => !p.startsWith('!'));
}

async function buildFileEntry(
  absolutePath: string,
  scanRoot: string,
): Promise<FileEntry | null> {
  const ext = path.extname(absolutePath);

  if (shouldSkipFile(ext)) return null;

  try {
    const stat = await fs.stat(absolutePath);
    if (!stat.isFile() || stat.size > MAX_FILE_SIZE) return null;
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
  options?: { ignore?: string[] },
): Promise<FileEntry[]> {
  const resolved = path.resolve(targetPath);

  // Single file path
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) {
      const scanRoot = path.dirname(resolved);
      const entry = await buildFileEntry(resolved, scanRoot);
      return entry ? [entry] : [];
    }
  } catch {
    return [];
  }

  // Directory — discover all files
  const scanRoot = resolved;

  const ignorePatterns = [...DEFAULT_IGNORE];

  // Read .gitignore from scan root
  try {
    const gitignoreContent = await fs.readFile(path.join(scanRoot, '.gitignore'), 'utf-8');
    ignorePatterns.push(...parseGitignorePatterns(gitignoreContent));
  } catch {
    // No .gitignore — that's fine
  }

  // Read .clawsecignore from scan root
  try {
    const clawsecignoreContent = await fs.readFile(path.join(scanRoot, '.clawsecignore'), 'utf-8');
    ignorePatterns.push(...parseGitignorePatterns(clawsecignoreContent));
  } catch {
    // No .clawsecignore — that's fine
  }

  // Merge user-supplied ignore patterns
  if (options?.ignore) {
    ignorePatterns.push(...options.ignore);
  }

  const filePaths = await glob('**/*', {
    cwd: scanRoot,
    ignore: ignorePatterns,
    nodir: true,
    dot: false,
  });

  const entries: FileEntry[] = [];

  // Process in parallel batches for performance
  const results = await Promise.all(
    filePaths.map((relPath) => buildFileEntry(path.join(scanRoot, relPath), scanRoot)),
  );

  for (const entry of results) {
    if (entry) entries.push(entry);
  }

  return entries;
}
