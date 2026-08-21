'use strict';

/**
 * guard@8 — requireExecutionStateMatch default is ON (fail-closed).
 * Explicit opt-down remains: 'warn' | false.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

describe('guard@8: requireExecutionStateMatch default is ON', () => {
  it('types.ts: default is fail-closed (absent → true)', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src/types.ts'), 'utf8');
    assert.match(src, /requireExecutionStateMatch\?:\s*boolean\s*\|\s*'warn'/);
    assert.match(src, /default fail-closed/i);
  });

  it('guard.ts: absent defaults to true; recheck unless explicit false', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src/guard.ts'), 'utf8');
    assert.match(src, /config\.requireExecutionStateMatch === undefined\s*\n\s*\? true/);
    assert.match(src, /execStateMode !== false/);
    assert.match(src, /default ON \(absent → true\)/);
  });

  it('README documents default ON and opt-down ladder', () => {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
    assert.match(readme, /default ON/i);
    assert.match(readme, /requireExecutionStateMatch:\s*'warn'/);
    assert.match(readme, /execution_state_drift_observed/);
    assert.match(readme, /execution_state_unmeasurable/);
    assert.match(readme, /Opt-down/i);
  });
});
