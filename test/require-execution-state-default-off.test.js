'use strict';

/**
 * Roadmap 891 — confirm requireExecutionStateMatch default remains OFF/absent.
 * Docs/recommendation only changed; no behavioral default flip.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

describe('891: requireExecutionStateMatch default remains off', () => {
  it('types.ts: field is optional; Default remains off', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src/types.ts'), 'utf8');
    assert.match(src, /requireExecutionStateMatch\?:\s*boolean\s*\|\s*'warn'/);
    assert.match(src, /Default remains off/i);
    // Must not hard-default to true or 'warn' on the type
    assert.ok(!/requireExecutionStateMatch\s*=\s*true/.test(src));
    assert.ok(!/requireExecutionStateMatch\s*=\s*'warn'/.test(src));
  });

  it('guard.ts: only runs recheck when mode is true or warn (absent = off)', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src/guard.ts'), 'utf8');
    assert.match(
      src,
      /if\s*\(\s*execStateMode\s*===\s*true\s*\|\|\s*execStateMode\s*===\s*'warn'\s*\)/,
    );
    assert.match(src, /Default stays off/i);
  });

  it('README documents warn as first-class opt-in pre-flip observation mode', () => {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
    assert.match(readme, /first-class opt-in warn telemetry|safe pre-flip observation/i);
    assert.match(readme, /requireExecutionStateMatch:\s*'warn'/);
    assert.match(readme, /execution_state_drift_observed/);
    assert.match(readme, /execution_state_unmeasurable/);
    assert.match(readme, /default remains OFF/i);
    assert.match(readme, /proceeds/i);
  });
});
