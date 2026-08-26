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

/** The app's REAL producer. Never a copy, never a frozen constant — the thing itself. */
function loadAppProducer() {
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

const OPENAPI_BEFORE = JSON.stringify({
  openapi: '3.0.0', info: { title: 't', version: '1.0.0' },
  paths: { '/u': { get: { responses: { 200: { description: 'ok' } } } } },
});
const OPENAPI_AFTER = JSON.stringify({
  openapi: '3.0.0', info: { title: 't', version: '1.0.0' }, paths: {},
});

/** Cases chosen so every element of the preimage is exercised at least once. */
const CASES = Object.freeze([
  { name: 'operation only (the live authorize shape)',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: { operation: 'merge' } },
  { name: 'no context at all',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: undefined },
  { name: 'empty context object',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: {} },
  { name: 'every context field populated',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: {
      operation: 'merge', environment: 'production', repository: 'acme/api',
      branch: 'main', pull_request: 42, policy_profile: 'strict',
    } },
  { name: 'multiple artifacts, submitted out of order',
    artifacts: [
      { id: 'b.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER },
      { id: 'a.yaml', type: 'openapi', before: OPENAPI_AFTER, after: OPENAPI_BEFORE },
    ],
    context: { operation: 'deploy' } },
  { name: 'mixed artifact types',
    artifacts: [
      { id: 'x', type: 'graphql', before: 'type Q { a: Int }', after: 'type Q { }' },
      { id: 'x', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER },
    ],
    context: { operation: 'merge', repository: 'acme/api' } },
  { name: 'null and empty artifact sides',
    artifacts: [{ id: 'n', type: 'openapi', before: null, after: '' }],
    context: { operation: 'merge' } },
]);

describe('exported computeBundleFingerprint ↔ app producer (cross-repo, unskippable)', () => {
  const appFn = loadAppProducer();

  for (const c of CASES) {
    it(`matches the app byte for byte — ${c.name}`, () => {
      const mine = computeBundleFingerprint(c.artifacts, c.context);
      const theirs = appFn(c.artifacts, c.context);
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
    assert.notEqual(stale(c.artifacts), appFn(c.artifacts, c.context),
      'if the old form matched, this whole fix would be unnecessary — the fixture must exercise the defect');
    assert.equal(computeBundleFingerprint(c.artifacts, c.context), appFn(c.artifacts, c.context));
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
