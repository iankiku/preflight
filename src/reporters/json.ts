/**
 * JSON Reporter
 * Output scan results as formatted JSON
 */

import type { ScanResult } from '../types.js';

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
