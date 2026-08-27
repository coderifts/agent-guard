'use strict';

/**
 * 1093 — the CAS conditioned on a token it fetched itself.
 *
 * This is a TIMING test, not a classification one: it reproduces the interleaving rather than
 * asserting a predicate. The window is between the T2 recheck and the adapter's own token read,
 * so the interfering write happens INSIDE executeFactory, which is the only place it can land.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  guardToolCall,
  createFsVersionToken,
  writeFileIfUnchanged,
  wrapWriteWithFsCas,
  measureFsAuthorizationToken,
  computeBodyHash,
  computeArtifactDigest,
  computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');

const BEFORE = 'openapi: 3.0.0\nrequired: [id]\n';
const AFTER = 'openapi: 3.0.0\nrequired: [id, tenant]\n';
const INTERFERING = 'openapi: 3.0.0\nrequired: [id, ANOTHER_WRITER]\n';

function tmpFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cas-t1-'));
  const file = path.join(dir, 'openapi.yaml');
  fs.writeFileSync(file, contents);
  return { dir, file };
}

function envelopeFor(artifacts) {
  const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'tool_call' });
  return {
    spec_version: 'decision-result.v1.1', decision: 'ALLOW', safe_for_agent: true,
    execution_action: 'CONTINUE', decision_id: 'd', correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z', expires_at: '2099-01-01T00:00:00Z',
    fingerprint: fp, input_fingerprint: fp, analysis_complete: true,
    artifact_digest: computeArtifactDigest(artifacts), operation: 'tool_call',
    receipt: { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' },
  };
}
function clientFor(env) {
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet(r); },
    async preflightChangeSet() {
      return { decision: 'ALLOW', execution_action: 'CONTINUE', decision_result: env };
    },
    async verifyReceipt() {
      return { valid: true, status: 'VERIFIED_CURRENT', payload: { fp: env.fingerprint, bh: computeBodyHash(env) } };
    },
  };
}

describe('1093 — the CAS conditions on the AUTHORIZATION-time token', () => {
  it('TIMING: a writer landing after T2 makes the write REFUSE, and it does not land', async () => {
    const { dir, file } = tmpFile(BEFORE);
    try {
      const artifacts = [{ id: 'openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
      const env = envelopeFor(artifacts);
      const args = { path: file, contents: AFTER };

      // T1: measured before preflight, exactly where the runner takes it.
      const t1 = await measureFsAuthorizationToken(args);
      assert.equal(typeof t1, 'string', 'T1 token must be measurable');

      const out = await guardToolCall(
        { toolName: 'apply_openapi', arguments: args, filesTouched: [file], artifacts },
        async (_e, redacted) => {
          // INSIDE executeFactory: T1 and T2 are behind us. This is the window.
          fs.writeFileSync(file, INTERFERING);
          return wrapWriteWithFsCas(redacted.arguments, () => { throw new Error('unreachable'); }, { expected_token: t1 });
        },
        { client: clientFor(env), requireExecutionStateMatch: true },
        {},
      );

      assert.equal(out.result.status, 'refused');
      assert.equal(out.result.reason, 'stale_version_token');
      assert.equal(fs.readFileSync(file, 'utf8'), INTERFERING, 'the write must NOT have landed');
      assert.notEqual(fs.readFileSync(file, 'utf8'), AFTER);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('CONTROL: with no interleaving the same call commits', async () => {
    const { dir, file } = tmpFile(BEFORE);
    try {
      const artifacts = [{ id: 'openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
      const env = envelopeFor(artifacts);
      const args = { path: file, contents: AFTER };
      const t1 = await measureFsAuthorizationToken(args);
      const out = await guardToolCall(
        { toolName: 'apply_openapi', arguments: args, filesTouched: [file], artifacts },
        async (_e, redacted) => wrapWriteWithFsCas(redacted.arguments, () => { throw new Error('unreachable'); }, { expected_token: t1 }),
        { client: clientFor(env), requireExecutionStateMatch: true },
        {},
      );
      assert.equal(out.result.status, 'committed');
      assert.equal(fs.readFileSync(file, 'utf8'), AFTER);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('REGRESSION GUARD: a self-fetched token would have committed the same interleaving', async () => {
    // Reproduces the 12.0.0 behaviour directly against the adapter, so the fix cannot silently
    // regress to reading the token at write time and still look correct.
    const { dir, file } = tmpFile(BEFORE);
    try {
      fs.writeFileSync(file, INTERFERING);              // the interfering state
      const selfFetched = await createFsVersionToken(file); // read AFTER it landed — the old bug
      const r = await writeFileIfUnchanged({ path: file, expected_token: selfFetched, content: AFTER });
      assert.equal(r.status, 'committed', 'this is exactly what the old code did');
      assert.equal(fs.readFileSync(file, 'utf8'), AFTER, 'and it clobbered the interfering write');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('no authorization token → NO CAS claim (never a self-fetched substitute)', async () => {
    const { dir, file } = tmpFile(BEFORE);
    try {
      let hostRan = false;
      const out = await wrapWriteWithFsCas({ path: file, contents: AFTER }, () => { hostRan = true; return 'HOST'; });
      assert.equal(hostRan, true, 'the host write still runs');
      assert.equal(out, 'HOST', 'and no ExecuteIfUnchangedOutcome is fabricated');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('measureFsAuthorizationToken returns null for calls it cannot measure', async () => {
    assert.equal(await measureFsAuthorizationToken(null), null);
    assert.equal(await measureFsAuthorizationToken({ path: '/x/y.yaml' }), null, 'no contents → not a full-file write');
    assert.equal(await measureFsAuthorizationToken({ contents: 'x' }), null, 'no path');
  });
});
