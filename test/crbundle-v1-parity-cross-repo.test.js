/**
 * ID842 follow-up — cross-repo crbundle.v1 fingerprint parity gate (Option 1).
 *
 * Freezes BOTH input (artifacts+context) AND expected_fingerprint so either repo's
 * computeBundleFingerprint / computeCanonicalBundleFingerprint cannot silently drift.
 *
 * Fixture path (vendored pair, must stay byte-identical):
 *   test/fixtures/crbundle-v1-parity.frozen.json  (this repo + coderifts-app)
 *
 * Checkout resolution for the sibling app repo:
 *   1. CODERIFTS_APP_DIR
 *   2. $HOME/coderifts-app
 *
 * Missing checkout → fail loud (never skip) — same spirit as ID825/ID840 vendored-sync.
 */
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { computeCanonicalBundleFingerprint } = require('../dist/cjs/index.js');

const GUARD_ROOT = path.join(__dirname, '..');
const FIXTURE_REL = path.join('test', 'fixtures', 'crbundle-v1-parity.frozen.json');
const GUARD_FIXTURE = path.join(GUARD_ROOT, FIXTURE_REL);

/** Pinned CONTRACT hash — also stored inside the fixture JSON. */
const PINNED_EXPECTED =
  'sha256:7298f7d99309d45b6bf0ad1eb66edc8921d2cdc80f396500bef9e1cfbdf024bc';

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
        + 'The crbundle.v1 parity vendored-sync check must NOT skip when the app repo is unavailable.',
    );
  }
  const st = fs.statSync(abs);
  if (!st.isDirectory()) {
    assert.fail(
      `coderifts-app path ${abs} exists but is not a directory. `
        + 'The crbundle.v1 parity vendored-sync check must NOT skip.',
    );
  }
  return abs;
}

function loadFixture(filePath = GUARD_FIXTURE) {
  assert.ok(fs.existsSync(filePath), `frozen fixture missing at ${filePath}`);
  const raw = fs.readFileSync(filePath, 'utf8');
  const doc = JSON.parse(raw);
  assert.equal(doc.schema, 'crbundle.v1.parity-fixture');
  assert.equal(doc.domain, 'crbundle.v1');
  assert.ok(Array.isArray(doc.artifacts) && doc.artifacts.length > 0);
  assert.ok(doc.context && typeof doc.context === 'object');
  assert.equal(typeof doc.expected_fingerprint, 'string');
  return doc;
}

// 1394 — LIVE when the app checkout is present, RECORDED against the pinned snapshot when it is
// not. Never a silent skip: a comparison that did not happen must not read as one that passed.
const rec = require('../lib/recorded-app-sync');
const LIVE = rec.generatorsPresent();
const MODE = LIVE ? 'LIVE' : 'RECORDED';

describe('crbundle.v1 frozen parity fixture (guard computeCanonicalBundleFingerprint)', () => {
  it('fixture exists and pins the CONTRACT expected_fingerprint', () => {
    const doc = loadFixture();
    assert.equal(doc.expected_fingerprint, PINNED_EXPECTED);
    assert.equal(doc.id, 'id842-shared-parity-a');
  });

  it('guard computeCanonicalBundleFingerprint matches the frozen expected_fingerprint exactly', () => {
    const doc = loadFixture();
    const actual = computeCanonicalBundleFingerprint(doc.artifacts, doc.context);
    assert.equal(
      actual,
      doc.expected_fingerprint,
      'guard computeCanonicalBundleFingerprint drifted from frozen CONTRACT hash — '
        + 'if intentional, bump expected_fingerprint in BOTH repos together '
        + `(app + agent-guard ${FIXTURE_REL})`,
    );
    assert.equal(actual, PINNED_EXPECTED);
  });

  it('gate bites: one-byte wrong expected_fingerprint fails the equality check', () => {
    const doc = loadFixture();
    const actual = computeCanonicalBundleFingerprint(doc.artifacts, doc.context);
    assert.equal(actual, doc.expected_fingerprint, 'precondition: fixture matches algorithm');

    const last = doc.expected_fingerprint.slice(-1);
    const flipped = last === 'c' ? 'd' : 'c';
    const wrong = doc.expected_fingerprint.slice(0, -1) + flipped;
    assert.notEqual(wrong, doc.expected_fingerprint);
    assert.notEqual(actual, wrong, 'one-byte hash change must not match primitive output');
    assert.throws(
      () => assert.equal(actual, wrong),
      (err) => {
        assert.ok(err && /!=|equal|Expected/i.test(String(err.message || err)));
        return true;
      },
    );
  });
});

describe(`crbundle.v1 parity fixture vendored-sync (agent-guard ↔ app) ${rec.modeBanner(MODE)}`, () => {
  it('agent-guard fixture is byte-identical to app fixture', () => {
    // 1394: RECORDED reads the pinned snapshot; LIVE reads the app and ALSO checks the snapshot.
    const appFixture = LIVE
      ? path.join(assertAppCheckoutAvailable(), FIXTURE_REL)
      : rec.snapshotPath('crbundle-v1-parity.frozen.json');
    assert.ok(
      fs.existsSync(appFixture),
      `app frozen fixture missing at ${appFixture} — copy ${FIXTURE_REL} into both repos`,
    );
    assert.ok(fs.existsSync(GUARD_FIXTURE), `guard frozen fixture missing at ${GUARD_FIXTURE}`);

    const guardBytes = fs.readFileSync(GUARD_FIXTURE);
    const appBytes = fs.readFileSync(appFixture);
    assert.equal(
      guardBytes.equals(appBytes),
      true,
      `crbundle-v1-parity.frozen.json drift: agent-guard vs app at ${appFixture}\n`
        + 'Fixture is CANONICAL as a vendored pair — keep byte-identical in BOTH repos.\n'
        + `Sync: cp ${FIXTURE_REL} <other-repo>/${FIXTURE_REL}\n`
        + 'Do not hand-edit only one side (ID842 / ID825).',
    );
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

  it('one-byte fixture-file divergence would fail the byte-identity gate', () => {
    // 1394: RECORDED reads the pinned snapshot; LIVE reads the app and ALSO checks the snapshot.
    const appFixture = LIVE
      ? path.join(assertAppCheckoutAvailable(), FIXTURE_REL)
      : rec.snapshotPath('crbundle-v1-parity.frozen.json');
    const guardBytes = fs.readFileSync(GUARD_FIXTURE);
    const appBytes = fs.readFileSync(appFixture);
    assert.equal(guardBytes.equals(appBytes), true, 'precondition: fixtures already in sync');

    const stale = Buffer.from(appBytes);
    const idx = Math.max(0, stale.length - 4);
    stale[idx] = stale[idx] ^ 0x01;
    assert.equal(guardBytes.equals(stale), false, 'one-byte-stale buffer must not equal guard fixture');
  });
});

module.exports = {
  resolveAppRoot,
  assertAppCheckoutAvailable,
  GUARD_FIXTURE,
  FIXTURE_REL,
  PINNED_EXPECTED,
};
