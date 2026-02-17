import test from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeForTerminal } from '../src/utils.js';

test('sanitizeForTerminal strips ANSI and control characters', () => {
  const input = '\u001b[31mred\u001b[0m\u0007';
  assert.equal(sanitizeForTerminal(input), 'red');
});

test('sanitizeForTerminal strips OSC sequences', () => {
  const input = '\u001b]8;;http://example.com\u0007link\u001b]8;;\u0007';
  assert.equal(sanitizeForTerminal(input), 'link');
});
