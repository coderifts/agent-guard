'use strict';
/**
 * THE EXPORTED computeBundleFingerprint must match the REAL app producer.
 *
 * THE DEFECT THIS CLOSES. `computeBundleFingerprint` is what a third party reaches for by name,
 * and until now it built its OWN preimage — omitting the artifact COUNT and the entire trailing
 * context block. On identical inputs it returned sha256:1a0e7470… where the server returned
 * sha256:049650f2…, so a consumer checking a receipt's `fp` against their own change set saw a
 * mismatch and had no way to know the verifier was at fault. A verifier that is quietly wrong is
 * worse than one that is honestly absent.
 *
 * WHY THE EXISTING GATE DID NOT CATCH IT — the part worth remembering. test/crbundle-v1-parity-
 * cross-repo.test.js opens by saying it keeps "computeBundleFingerprint / computeCanonical-
 * BundleFingerprint" from silently drifting, but it only ever imports and exercises the CANONICAL
 * one. The exported name was never executed by any parity test. A gate whose docstring claims
 * more coverage than its imports is how a fork survives in plain sight, so this file tests the
 * EXPORT specifically, and by requiring the app's real implementation rather than a frozen hash.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { computeBundleFingerprint, computeCanonicalBundleFingerprint } = require('../dist/cjs/index.js');

function resolveAppRoot() {
  const fromEnv = process.env.CODERIFTS_APP_DIR && String(process.env.CODERIFTS_APP_DIR).trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.join(process.env.HOME || os.homedir(), 'coderifts-app');
}

/**
 * The app side of the comparison.
 *
 * LIVE — the app's REAL producer, required and called. Never a copy, never a frozen constant.
 *
 * RECORDED — the seven GOLDEN OUTPUTS that producer emitted at the pinned commit. The 74 kB
 * governance engine is NOT vendored into this public repo (1394 revised): it is core product
 * logic, and publishing it is irreversible while the open-core position is undecided.
 *
 * WHAT RECORDED NO LONGER CATCHES, said plainly: a change in the app AFTER the recording. It
 * proves the Guard still agrees with what the app produced at that commit, not with what the app
 * produces today. LIVE catches that, and LIVE also fails if this recording went stale — so the
 * drift is caught wherever a checkout exists, which is every place that could act on it.
 */
function loadAppProducer() {
  if (!LIVE) {
    const recorded = JSON.parse(rec.snapshotText('change-set.fingerprints.json'));
    const byName = new Map(recorded.vectors.map((v) => [v.name, v.fingerprint]));
    assert.equal(byName.size, CASES.length,
      'the recorded vectors and the case list disagree — regenerate scripts/extract-app-invariants.js');
    return (artifacts, context, name) => {
      const fp = byName.get(name);
      assert.ok(fp, `no recorded fingerprint for case ${JSON.stringify(name)}`);
      return fp;
    };
  }
  const root = resolveAppRoot();
  const mod = path.join(root, 'src', 'change-set.js');
  if (!fs.existsSync(mod)) {
    assert.fail(
      `coderifts-app checkout missing at ${root} (looked for src/change-set.js). `
      + 'Set CODERIFTS_APP_DIR or clone it at $HOME/coderifts-app. This cross-check must NOT skip '
      + 'when the app repo is unavailable — a skipped parity test is how the published function '
      + 'drifted from the server in the first place.',
    );
  }
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const { computeBundleFingerprint: appFn } = require(mod);
  assert.equal(typeof appFn, 'function', 'app change-set.js must export computeBundleFingerprint');
  return appFn;
}

const { CASES } = require('./lib/bundle-fingerprint-cases.js');


// 1394 — LIVE when the app checkout is present, RECORDED against the pinned snapshot when it is
// not. Never a silent skip: a comparison that did not happen must not read as one that passed.
const rec = require('../lib/recorded-app-sync');
const LIVE = rec.generatorsPresent();
const MODE = LIVE ? 'LIVE' : 'RECORDED';

describe('exported computeBundleFingerprint ↔ app producer (cross-repo, unskippable)', () => {
  const appFn = loadAppProducer();

  for (const c of CASES) {
    it(`matches the app byte for byte — ${c.name}`, () => {
      const mine = computeBundleFingerprint(c.artifacts, c.context);
      const theirs = appFn(c.artifacts, c.context, c.name);
      assert.equal(mine, theirs,
        `exported computeBundleFingerprint diverged from the app producer for: ${c.name}`);
      assert.match(mine, /^sha256:[0-9a-f]{64}$/);
    });
  }

  it('THE EXPORT AND THE CANONICAL FUNCTION ARE THE SAME PREIMAGE, not two that agree', () => {
    for (const c of CASES) {
      assert.equal(
        computeBundleFingerprint(c.artifacts, c.context),
        computeCanonicalBundleFingerprint(c.artifacts, c.context),
        `${c.name}: the package must carry exactly ONE crbundle.v1 preimage`,
      );
    }
  });

  it('REGRESSION: the old arity-1 preimage would NOT have matched', () => {
    // Reconstructed exactly as it shipped in 10.0.0 — no count element, no context block.
    const NUL = '\x1f';
    const crypto = require('node:crypto');
    const sha = (x) => crypto.createHash('sha256').update(String(x), 'utf8').digest('hex');
    const specStr = (v) => (v == null ? '' : (typeof v === 'string' ? v : JSON.stringify(v)));
    const stale = (artifacts) => {
      const parts = artifacts.slice()
        .sort((a, b) => (`${a.type}${NUL}${a.id}` < `${b.type}${NUL}${b.id}` ? -1 : 1))
        .map((a) => [a.type, a.id, sha(specStr(a.before)), sha(specStr(a.after))].join(NUL));
      return `sha256:${sha(parts.join(NUL))}`;
    };
    const c = CASES[0];
    assert.notEqual(stale(c.artifacts), appFn(c.artifacts, c.context, c.name),
      'if the old form matched, this whole fix would be unnecessary — the fixture must exercise the defect');
    assert.equal(computeBundleFingerprint(c.artifacts, c.context), appFn(c.artifacts, c.context, c.name));
  });

  it('THE CONTEXT IS LOAD-BEARING: omitting it changes the digest', () => {
    const a = CASES[0].artifacts;
    assert.notEqual(computeBundleFingerprint(a, { operation: 'merge' }), computeBundleFingerprint(a),
      'a caller who omits context must not silently get the with-context answer');
  });

  it('each context field independently affects the digest — none is decorative', () => {
    const a = CASES[0].artifacts;
    const base = { operation: 'merge' };
    const seen = new Set([computeBundleFingerprint(a, base)]);
    for (const f of ['environment', 'repository', 'branch', 'pull_request', 'policy_profile']) {
      const fp = computeBundleFingerprint(a, { ...base, [f]: 'x' });
      assert.equal(seen.has(fp), false, `${f} does not change the digest — the preimage is wrong`);
      seen.add(fp);
    }
  });

  it('submission ORDER is not significant — a bundle is a set keyed by (type, id)', () => {
    const [x, y] = CASES[4].artifacts;
    assert.equal(
      computeBundleFingerprint([x, y], { operation: 'deploy' }),
      computeBundleFingerprint([y, x], { operation: 'deploy' }),
    );
  });

  it('it is time-free: two calls a moment apart agree', () => {
    const c = CASES[0];
    assert.equal(computeBundleFingerprint(c.artifacts, c.context), computeBundleFingerprint(c.artifacts, c.context));
  });
});
