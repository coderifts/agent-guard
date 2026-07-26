'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

// The frozen invariants are tsc-verified: forbidden GuardOutcome / ApprovedVerdict /
// UnavailableVerdict states must be UNREPRESENTABLE. tsconfig.typetest.json compiles the
// @ts-expect-error fixtures; it exits 0 iff every forbidden state errors (and no other errors leak).
test('forbidden states do NOT compile (ts-expect-error fixtures pass)', () => {
  try {
    execFileSync('npx', ['tsc', '-p', 'tsconfig.typetest.json'], { cwd: path.join(__dirname, '..'), stdio: 'pipe' });
  } catch (e) {
    const out = (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : '');
    assert.fail('type-forbidden fixtures failed: a forbidden state became representable OR a fixture is wrong:\n' + out);
  }
});
