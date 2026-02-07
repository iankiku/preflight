/**
 * Dashboard Reporter
 * Injects scan data into the HTML dashboard template
 */

import type { ScanResult } from '../types.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function formatDashboard(result: ScanResult): string {
  // When bundled into dist/cli.js, resolve from package root
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const pkgRoot = path.resolve(__dirname, '..');
  const templatePath = path.resolve(pkgRoot, 'src', 'dashboard.html');
  const template = fs.readFileSync(templatePath, 'utf-8');
  // Escape </script> in JSON to prevent breaking the HTML template
  const jsonData = JSON.stringify(result).replace(/<\//g, '<\\/');
  // Use function replacement to prevent $ in JSON being interpreted as replacement patterns
  return template.replace('__CLAWSEC_DATA__', () => jsonData);
}
