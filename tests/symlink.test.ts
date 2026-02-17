import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { discoverFiles } from '../src/discover.js';

test('discoverFiles skips symlinks and paths outside scan root', async () => {
  const scanRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'preflight-root-'));
  const outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'preflight-out-'));

  const realFile = path.join(scanRoot, 'skills.md');
  const outsideFile = path.join(outsideRoot, 'skills.md');
  const nestedDir = path.join(scanRoot, 'nested');
  const linkFile = path.join(nestedDir, 'skills.md');

  await fs.mkdir(nestedDir);
  await fs.writeFile(realFile, 'ok');
  await fs.writeFile(outsideFile, 'secret');
  await fs.symlink(outsideFile, linkFile);

  const entries = await discoverFiles(scanRoot);
  const scannedPaths = new Set(entries.map((e) => e.path));

  assert.equal(scannedPaths.has(realFile), true);
  assert.equal(scannedPaths.has(linkFile), false);
  assert.equal(scannedPaths.has(outsideFile), false);
});
