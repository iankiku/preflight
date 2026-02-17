import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { discoverFiles } from '../src/discover.js';

test('discoverFiles only scans skills.md by default', async () => {
  const scanRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'preflight-scope-'));
  const skillsFile = path.join(scanRoot, 'skills.md');
  const otherFile = path.join(scanRoot, 'README.md');

  await fs.writeFile(skillsFile, 'ok');
  await fs.writeFile(otherFile, 'ignore');

  const entries = await discoverFiles(scanRoot);
  const scannedPaths = new Set(entries.map((e) => e.path));

  assert.equal(scannedPaths.has(skillsFile), true);
  assert.equal(scannedPaths.has(otherFile), false);
});

test('discoverFiles can scan all files when onlySkills is false', async () => {
  const scanRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'preflight-scope-all-'));
  const skillsFile = path.join(scanRoot, 'skills.md');
  const otherFile = path.join(scanRoot, 'README.md');

  await fs.writeFile(skillsFile, 'ok');
  await fs.writeFile(otherFile, 'include');

  const entries = await discoverFiles(scanRoot, { onlySkills: false });
  const scannedPaths = new Set(entries.map((e) => e.path));

  assert.equal(scannedPaths.has(skillsFile), true);
  assert.equal(scannedPaths.has(otherFile), true);
});
