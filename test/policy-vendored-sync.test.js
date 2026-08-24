'use strict';

/**
 * Vendored-sync: CODERIFTS_POLICY must stay byte-identical to the app canonical
 * text (`getCanonicalRuleText()` in src/agent-host-rule.js).
 *
 * Checkout resolution:
 *   1. CODERIFTS_APP_DIR
 *   2. $HOME/coderifts-app
 *
 * Missing checkout → fail loud (never skip) — same spirit as ID825/ID840.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { CODERIFTS_POLICY, POLICY_MARKER } = require('../dist/cjs/index.js');

function resolveAppRoot() {
  const fromEnv = process.env.CODERIFTS_APP_DIR
    && String(process.env.CODERIFTS_APP_DIR).trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.join(process.env.HOME || os.homedir(), 'coderifts-app');
}

function assertAppCheckoutAvailable(root = resolveAppRoot()) {
  const abs = path.resolve(root);
  if (!fs.existsSync(abs)) {
    assert.fail(
      `coderifts-app checkout missing at ${abs}. `
        + 'Set CODERIFTS_APP_DIR or clone it at $HOME/coderifts-app. '
        + 'The CODERIFTS_POLICY vendored-sync check must NOT skip when the app repo is unavailable.',
    );
  }
  const st = fs.statSync(abs);
  if (!st.isDirectory()) {
    assert.fail(
      `coderifts-app path ${abs} exists but is not a directory. `
        + 'The CODERIFTS_POLICY vendored-sync check must NOT skip.',
    );
  }
  return abs;
}

describe('CODERIFTS_POLICY vendored-sync (agent-guard ↔ app)', () => {
  it('constant is byte-identical to app getCanonicalRuleText()', () => {
    const appRoot = assertAppCheckoutAvailable();
    const rulePath = path.join(appRoot, 'src', 'agent-host-rule.js');
    assert.ok(fs.existsSync(rulePath), `app canonical missing at ${rulePath}`);
    const { getCanonicalRuleText } = require(rulePath);
    const appText = getCanonicalRuleText();
    assert.equal(
      CODERIFTS_POLICY,
      appText,
      'CODERIFTS_POLICY drifted from app getCanonicalRuleText(). '
        + 'Re-vendor from coderifts-app/src/agent-host-rule.js. Do not hand-edit only one side.',
    );
    assert.ok(appText.includes(POLICY_MARKER));
  });

  it('fails loudly when the app checkout is missing (no silent skip)', () => {
    const prev = process.env.CODERIFTS_APP_DIR;
    const missing = path.join(os.tmpdir(), `coderifts-app-missing-${Date.now()}`);
    process.env.CODERIFTS_APP_DIR = missing;
    try {
      assert.throws(
        () => assertAppCheckoutAvailable(),
        (err) => {
          assert.match(err.message, /missing/i);
          assert.match(err.message, /must NOT skip/i);
          return true;
        },
      );
    } finally {
      if (prev === undefined) delete process.env.CODERIFTS_APP_DIR;
      else process.env.CODERIFTS_APP_DIR = prev;
    }
  });
});
