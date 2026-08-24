'use strict';

/**
 * S1 remainder — FS CAS default-wire when args.path + full-file contents are both present.
 * Edit fragments and path-only mutators stay host-execute (no invented committed envelope).
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  withCodeRifts,
  inferFsPathFromArgs,
  inferFullFileWriteContent,
  wrapWriteWithFsCas,
  computeCanonicalBundleFingerprint,
  computeBodyHash,
} = require('../dist/cjs/index.js');

function signedFor(env) { return { fp: env.fingerprint, bh: computeBodyHash(env) }; }
function boundVerify(env) { return { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(env) }; }

const BEFORE = 'openapi: 3.0.0\npaths: {}\n';
const AFTER = 'openapi: 3.0.0\npaths:\n  /x:\n    get: {}\n';

function envelope(fp) {
  return {
    spec_version: 'decision-result.v1.1',
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    decision_id: 'dec_cas',
    correlation_id: 'c',
    evaluated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 900000).toISOString(),
    fingerprint: fp,
    input_fingerprint: fp,
    operation: 'tool_call',
    receipt: { token: 'tok', format_version: 'crchain.v1', key_id: 'k', issued_at: 'x' },
  };
}
function mockClient(fp) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) { return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' }); },
    async preflightChangeSet() {
      const resp = { decision: 'ALLOW', decision_result: envelope(fp) };
      lastEnv = resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      return lastEnv ? boundVerify(lastEnv) : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

let tmpRoot;
before(async () => {
  tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'coderifts-cas-default-'));
});
after(async () => {
  if (tmpRoot) await fsp.rm(tmpRoot, { recursive: true, force: true });
});

describe('inferFsPathFromArgs', () => {
  it('reads a non-empty path string', () => {
    assert.equal(inferFsPathFromArgs({ path: 'api/openapi.yaml' }), 'api/openapi.yaml');
  });
  it('rejects URLs and empty / missing path (not an fs target)', () => {
    assert.equal(inferFsPathFromArgs({ path: 'https://example.com/openapi.yaml' }), null);
    assert.equal(inferFsPathFromArgs({ path: '  ' }), null);
    assert.equal(inferFsPathFromArgs({ file: 'x' }), null);
    assert.equal(inferFsPathFromArgs(null), null);
  });
});

describe('inferFullFileWriteContent', () => {
  it('takes Write-style contents', () => {
    assert.equal(inferFullFileWriteContent({ path: 'a.yaml', contents: AFTER }), AFTER);
  });
  it('does not treat Edit fragments as a full-file body', () => {
    assert.equal(inferFullFileWriteContent({
      path: 'a.yaml',
      old_string: 'a',
      new_string: 'b',
    }), null);
  });
});

describe('wrapWriteWithFsCas — real adapter vs honest degradation', () => {
  it('path + contents on an existing file: writeFileIfUnchanged committed (host write skipped)', async () => {
    const p = path.join(tmpRoot, 'wired.yaml');
    await fsp.writeFile(p, BEFORE, 'utf8');
    let hostRan = false;
    const cas = await wrapWriteWithFsCas(
      { path: p, contents: AFTER },
      async () => { hostRan = true; return { ok: true }; },
    );
    assert.equal(hostRan, false, 'default-wire performs the FS adapter write, not a wrap of host execute');
    assert.equal(cas && cas.status, 'committed');
    assert.equal(await fsp.readFile(p, 'utf8'), AFTER);
  });

  it('path but no full-file body: host write, no invented CAS envelope', async () => {
    const p = path.join(tmpRoot, 'edit-only.yaml');
    await fsp.writeFile(p, BEFORE, 'utf8');
    const out = await wrapWriteWithFsCas(
      { path: p, old_string: 'a', new_string: 'b' },
      async () => ({ edited: true }),
    );
    assert.deepEqual(out, { edited: true });
    assert.equal(out && out.status, undefined);
    assert.equal(await fsp.readFile(p, 'utf8'), BEFORE);
  });

  it('no path: raw write, no CAS', async () => {
    const out = await wrapWriteWithFsCas(null, async () => 7);
    assert.equal(out, 7);
  });
});

describe('binder default-wire — withCodeRifts mutator with path+contents', () => {
  it('Write to an existing contract file returns CAS committed', async () => {
    const p = path.join(tmpRoot, 'openapi.yaml');
    await fsp.writeFile(p, BEFORE, 'utf8');
    const artifacts = [{ id: 'openapi:openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
    const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'tool_call' });
    const { tools } = withCodeRifts({
      tools: [{
        name: 'Write',
        description: 'w',
        mutationClass: 'mutating',
        inputSchema: { type: 'object', properties: { path: { type: 'string' }, contents: { type: 'string' } } },
        execute: async () => { throw new Error('host execute must not run when FS adapter is default-wired'); },
      }],
      client: mockClient(fp),
      operation: 'tool_call',
    });
    const write = tools.find((t) => t.name === 'Write');
    const outcome = await write.execute({
      path: p,
      contents: AFTER,
      artifacts,
    });
    assert.equal(outcome.executed, true, outcome.verdict && outcome.verdict.cause);
    assert.ok(outcome.result);
    assert.equal(outcome.result.status, 'committed');
    assert.equal(await fsp.readFile(p, 'utf8'), AFTER);
    assert.ok(outcome.cas_evidence);
    assert.equal(outcome.cas_evidence.class, 'host_claimed');
  });

  it('mutator without path: no CAS envelope (honest absence)', async () => {
    const artifacts = [{ id: 'openapi:spec.yaml', type: 'openapi', before: BEFORE, after: AFTER }];
    const fp = computeCanonicalBundleFingerprint(artifacts, { operation: 'tool_call' });
    const { tools } = withCodeRifts({
      tools: [{
        name: 'notify_consumers',
        description: 'n',
        mutationClass: 'mutating',
        inputSchema: {},
        execute: async () => ({ shipped: true }),
      }],
      client: mockClient(fp),
      operation: 'tool_call',
    });
    const notify = tools.find((t) => t.name === 'notify_consumers');
    const outcome = await notify.execute({ artifacts });
    assert.equal(outcome.executed, true, outcome.verdict && outcome.verdict.cause);
    assert.deepEqual(outcome.result, { shipped: true });
    assert.equal(outcome.result && outcome.result.status, undefined);
    assert.equal(outcome.commit_observation.status, 'not_observed');
  });
});
