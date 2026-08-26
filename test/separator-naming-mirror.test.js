'use strict';
/**
 * THE MIRRORS MUST NOT DRIFT FROM THE APP IN NAME OR IN BYTE.
 *
 * These files are kept faithful to coderifts-app BY EYE - no compiler links them. When the app
 * renamed its 0x1F constant from NUL to US (90c39cc), leaving the mirrors on the old name would
 * have made a reviewer diffing them see a difference that was not one.
 *
 * The rename mattered because the misnomer was load-bearing: three constants were all called NUL
 * and only one was (0x00), which is how a published document came to give 0x1F as the separator
 * for a preimage that actually uses 0x00.
 *
 * This test pins the NAME, the BYTE, and - most importantly - that renaming moved no digest.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = path.join(__dirname, '..', 'src');
const MIRRORS = ['execution-time-fingerprint.ts', 'enforcement-gate.ts'];
/** Raw control characters: invisible in an editor, and they break grep. */
const CTRL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;

const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');

function separatorOf(file) {
  const src = read(file);
  const m = src.match(/const\s+US\s*=\s*'((?:[^'\\]|\\.)*)'/);
  assert.ok(m, file + ": no `const US` declaration found");
  // eslint-disable-next-line no-eval
  return { value: eval("'" + m[1] + "'"), literal: m[1] };
}

describe('separator constants mirror the app in name and byte', () => {
  for (const f of MIRRORS) {
    it(f + ': US holds U+001F and the old NUL name is gone', () => {
      assert.equal(separatorOf(f).value, '\x1f');
      assert.equal(/\bconst NUL\b/.test(read(f)), false,
        '0x1F must not be called NUL (0x00) - that misnomer produced a wrong published recipe');
    });

    it(f + ': written as an escape, never a raw control byte', () => {
      // A raw control byte is invisible in an editor and makes grep fail silently - that is what
      // hid the defect in the app for hours.
      assert.equal(CTRL.test(separatorOf(f).literal), false);
      assert.equal(CTRL.test(read(f)), false, f + ' contains a raw control character somewhere');
    });
  }

  it('both mirrors agree with each other on the byte', () => {
    assert.equal(separatorOf(MIRRORS[0]).value, separatorOf(MIRRORS[1]).value);
  });
});

describe('THE RENAME MOVED NO DIGEST', () => {
  const g = require('../dist/cjs/index.js');
  const BEFORE = '{"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{"/u":{"get":{"responses":{"200":{"description":"ok"}}}}}}';
  const AFTER = '{"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{}}';
  const ARTS = [{ id: 'openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }];

  it('computeCanonicalBundleFingerprint still reproduces the RECEIPT_FORMAT 2.0 vector', () => {
    assert.equal(g.computeCanonicalBundleFingerprint(ARTS, { operation: 'merge' }),
      'sha256:049650f2d0496f39ad0ec09e57fa1841e9636255f031e99751435b1bc70443df');
  });

  it('the exported computeBundleFingerprint agrees with it, as one preimage must', () => {
    assert.equal(g.computeBundleFingerprint(ARTS, { operation: 'merge' }),
      g.computeCanonicalBundleFingerprint(ARTS, { operation: 'merge' }));
  });

  it('computeArtifactDigest is unchanged by the rename', () => {
    assert.equal(g.computeArtifactDigest(ARTS),
      'sha256:6ddd4c077bd922926e115394301379de3b39698c3065ff2107f0c85274010817');
  });
});
