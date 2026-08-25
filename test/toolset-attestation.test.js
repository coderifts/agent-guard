'use strict';

/**
 * cr.toolset.attest.v1 issuance (guard side).
 *
 * Cross-repo checks require the REAL app kernel at $HOME/coderifts-app. They SKIP LOUDLY when it
 * is absent rather than passing vacuously — an unproven mirror must not read as a proven one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const {
  TOOLSET_ATTEST_VERSION,
  TOOLSET_ATTEST_SIGNING_PREFIX,
  TOOLSET_ATTEST_ENVELOPE_TAG,
  TOOLSET_ATTEST_STATEMENT,
  computeToolsetDigest,
  declarationEntriesFromTools,
  toolsetAttestSigningInput,
  tryIssueToolsetAttestation,
  kidFromToolsetAttestation,
} = require('../dist/cjs/index.js');

const APP_KERNEL = path.join(process.env.HOME, 'coderifts-app', 'src', 'verdict-core', 'toolset-attestation.js');
let kernel = null;
try { kernel = require(APP_KERNEL); } catch { /* surfaced by the skips below, never silently */ }

function hostKey(kid = 'decl-k1') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    kid,
    signer: (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey),
    registry: { keys: [{ kid, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active' }] },
  };
}

/** A protected-tool table as guardToolRegistry returns it. */
const TOOLS = () => ([
  { name: 'write_file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } }, execute: async () => {}, _coderifts: { guarded: true, mutationClass: 'mutating' } },
  { name: 'run_shell', inputSchema: { type: 'object' }, execute: async () => {}, _coderifts: { guarded: true, mutationClass: 'mutating_shell' } },
  { name: 'git_push', execute: async () => {}, _coderifts: { guarded: true, mutationClass: 'mutating_vcs' } },
  { name: 'read_file', inputSchema: { type: 'object' }, execute: async () => {}, _coderifts: { guarded: false, mutationClass: 'readonly' } },
]);

const CFG = (k, over) => Object.assign({
  kid: k.kid, signer: k.signer, declarer: 'acme-platform-team',
  framework: 'langgraph', frameworkVersion: '0.2.1',
}, over || {});

// ── generation from the real table ─────────────────────────────────────────

describe('the declaration is GENERATED from the tool table, never typed', () => {
  it('entries come from registered tools: name, schema digest, mutation class', () => {
    const entries = declarationEntriesFromTools(TOOLS());
    assert.equal(entries.length, 4);
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));
    assert.equal(byName.write_file.mutation_class, 'mutating');
    assert.equal(byName.read_file.mutation_class, 'readonly');
    assert.ok(byName.write_file.input_schema_digest.startsWith('sha256:'));
  });

  it('every mutating_* collapses to the envelope class `mutating`', () => {
    const entries = declarationEntriesFromTools(TOOLS());
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));
    assert.equal(byName.run_shell.mutation_class, 'mutating', 'mutating_shell -> mutating');
    assert.equal(byName.git_push.mutation_class, 'mutating', 'mutating_vcs -> mutating');
  });

  it('a tool with no inputSchema declares no schema digest rather than a fabricated one', () => {
    const entries = declarationEntriesFromTools(TOOLS());
    const gitPush = entries.find((e) => e.name === 'git_push');
    assert.equal('input_schema_digest' in gitPush, false);
  });

  it('the schema digest is stable across key reordering (re-serialisation is not a change)', () => {
    const a = declarationEntriesFromTools([{ name: 't', inputSchema: { a: 1, b: 2 }, execute: async () => {}, _coderifts: { guarded: true, mutationClass: 'mutating' } }]);
    const b = declarationEntriesFromTools([{ name: 't', inputSchema: { b: 2, a: 1 }, execute: async () => {}, _coderifts: { guarded: true, mutationClass: 'mutating' } }]);
    assert.equal(a[0].input_schema_digest, b[0].input_schema_digest);
  });

  it('a changed schema changes the digest', () => {
    const a = declarationEntriesFromTools(TOOLS());
    const changed = TOOLS();
    changed[0].inputSchema = { type: 'object', properties: { path: { type: 'number' } } };
    const b = declarationEntriesFromTools(changed);
    assert.notEqual(a[0].input_schema_digest, b[0].input_schema_digest);
  });
});

// ── custody ────────────────────────────────────────────────────────────────

describe('custody mirrors monitoring and coverage — one story, not a third', () => {
  it('absent config yields no token (byte-identical to not calling it)', async () => {
    assert.equal(await tryIssueToolsetAttestation({ config: null, tools: TOOLS() }), undefined);
    assert.equal(await tryIssueToolsetAttestation({ tools: TOOLS() }), undefined);
  });

  it('a signer that throws yields NO token, never an unsigned one', async () => {
    const cfg = CFG(hostKey(), { signer: () => { throw new Error('hsm offline'); } });
    assert.equal(await tryIssueToolsetAttestation({ config: cfg, tools: TOOLS() }), undefined);
  });

  it('a null or empty signature yields no token', async () => {
    for (const signer of [() => null, () => Buffer.alloc(0)]) {
      const cfg = CFG(hostKey(), { signer });
      assert.equal(await tryIssueToolsetAttestation({ config: cfg, tools: TOOLS() }), undefined);
    }
  });

  it('a missing declarer yields no token — accountability needs a name', async () => {
    const cfg = CFG(hostKey(), { declarer: '' });
    assert.equal(await tryIssueToolsetAttestation({ config: cfg, tools: TOOLS() }), undefined);
  });

  it('an unpaired framework refuses to mint rather than emit a token the kernel rejects', async () => {
    const only = CFG(hostKey(), { frameworkVersion: undefined });
    assert.equal(await tryIssueToolsetAttestation({ config: only, tools: TOOLS() }), undefined);
    const onlyV = CFG(hostKey(), { framework: undefined });
    assert.equal(await tryIssueToolsetAttestation({ config: onlyV, tools: TOOLS() }), undefined);
  });

  it('an empty tool table yields no token', async () => {
    assert.equal(await tryIssueToolsetAttestation({ config: CFG(hostKey()), tools: [] }), undefined);
  });

  it('a pipe in a signed field yields no token', async () => {
    const cfg = CFG(hostKey(), { declarer: 'acme|team' });
    assert.equal(await tryIssueToolsetAttestation({ config: cfg, tools: TOOLS() }), undefined);
  });
});

// ── envelope ───────────────────────────────────────────────────────────────

describe('the emitted envelope', () => {
  it('is 4 pipe segments tagged cr.toolset.attest.v1, and names the kid', async () => {
    const k = hostKey();
    const tok = await tryIssueToolsetAttestation({ config: CFG(k), tools: TOOLS(), guardVersion: '9.7.0' });
    const seg = tok.split('|');
    assert.equal(seg.length, 4);
    assert.equal(seg[0], TOOLSET_ATTEST_ENVELOPE_TAG);
    assert.equal(kidFromToolsetAttestation(tok), k.kid);
  });

  it('carries the exact declared sentence, not one of its own', async () => {
    const tok = await tryIssueToolsetAttestation({ config: CFG(hostKey()), tools: TOOLS() });
    const body = JSON.parse(Buffer.from(tok.split('|')[2], 'base64url').toString('utf8'));
    assert.equal(body.statement, TOOLSET_ATTEST_STATEMENT);
    assert.equal(body.v, TOOLSET_ATTEST_VERSION);
  });

  it('carries guard_version and the framework pair', async () => {
    const tok = await tryIssueToolsetAttestation({ config: CFG(hostKey()), tools: TOOLS(), guardVersion: '9.7.0' });
    const body = JSON.parse(Buffer.from(tok.split('|')[2], 'base64url').toString('utf8'));
    assert.equal(body.guard_version, '9.7.0');
    assert.equal(body.framework, 'langgraph');
    assert.equal(body.framework_version, '0.2.1');
  });

  it('counts match the generated set (3 mutating of 4)', async () => {
    const tok = await tryIssueToolsetAttestation({ config: CFG(hostKey()), tools: TOOLS() });
    const body = JSON.parse(Buffer.from(tok.split('|')[2], 'base64url').toString('utf8'));
    assert.equal(body.tool_count, 4);
    assert.equal(body.mutating_count, 3);
  });
});

// ── the digest MUST be the kernel's digest ─────────────────────────────────

describe('set_digest is byte-identical to the app kernel', () => {
  it('computeToolsetDigest equals kernel computeSetDigest on the generated entries', (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — byte-identity UNPROVEN');
    const entries = declarationEntriesFromTools(TOOLS());
    const mine = computeToolsetDigest(entries);
    const theirs = kernel.computeSetDigest(entries);
    assert.equal(mine.ok, true);
    assert.equal(theirs.ok, true);
    assert.equal(mine.digest, theirs.digest, 'a divergent digest would mint false UNBOUND');
    assert.equal(mine.tool_count, theirs.tool_count);
    assert.equal(mine.mutating_count, theirs.mutating_count);
  });

  it('digests agree across many shapes, orders and schema presence', (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — byte-identity UNPROVEN');
    const shapes = [
      [{ name: 'a', mutation_class: 'mutating' }],
      [{ name: 'b', mutation_class: 'readonly', input_schema_digest: 'sha256:ff' }],
      [{ name: 'z', mutation_class: 'mutating' }, { name: 'a', mutation_class: 'readonly' }],
      declarationEntriesFromTools(TOOLS()),
      declarationEntriesFromTools(TOOLS().reverse()),
    ];
    for (const s of shapes) {
      assert.equal(computeToolsetDigest(s).digest, kernel.computeSetDigest(s).digest, JSON.stringify(s));
    }
  });

  it('rejection reasons agree too — the guard refuses what the kernel refuses', (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — parity UNPROVEN');
    const bad = [
      [],
      [{ name: 'dup', mutation_class: 'mutating' }, { name: 'dup', mutation_class: 'readonly' }],
      [{ name: 'x', mutation_class: 'mutating_shell' }],
      [{ name: 'pipe|name', mutation_class: 'mutating' }],
      [{ name: 'x', mutation_class: 'mutating', input_schema_digest: 'md5:zz' }],
    ];
    for (const b of bad) {
      const mine = computeToolsetDigest(b);
      const theirs = kernel.computeSetDigest(b);
      assert.equal(mine.ok, false, JSON.stringify(b));
      assert.equal(theirs.ok, false, JSON.stringify(b));
      assert.equal(mine.reason, theirs.reason, 'same refusal reason: ' + JSON.stringify(b));
    }
  });

  it('the guard signing input is byte-identical to the kernel signing input', (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — mirror UNPROVEN');
    const body = {
      v: TOOLSET_ATTEST_VERSION, kid: 'k', declarer: 'D', statement: TOOLSET_ATTEST_STATEMENT,
      set_digest: 'sha256:abc', declared_at: '2026-08-25T00:00:00Z',
      session_id: 'S', receipt_digest: 'sha256:rd', framework: 'FW', framework_version: 'FV',
      guard_version: 'GV', tool_count: 4, mutating_count: 3, scope_note: 'SN',
    };
    assert.equal(toolsetAttestSigningInput(body), kernel.signingInput(body));
    assert.equal(TOOLSET_ATTEST_SIGNING_PREFIX, kernel.SIGNING_PREFIX);
    assert.equal(TOOLSET_ATTEST_STATEMENT, kernel.STATEMENTS[0]);
  });
});

// ── end to end against the real kernel ─────────────────────────────────────

describe('the emitted token verifies against the REAL app kernel', () => {
  it('a generated declaration is TOOLSET_ATTEST_VALID and binds to its own set', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — cross-repo verification UNPROVEN');
    const k = hostKey();
    const tools = TOOLS();
    const tok = await tryIssueToolsetAttestation({ config: CFG(k), tools, guardVersion: '9.7.0' });
    const entries = declarationEntriesFromTools(tools);
    const r = kernel.verifyToolsetAttestation(tok, { registry: k.registry, entries });
    assert.equal(r.valid, true, `kernel rejected: ${r.status}/${r.reason}`);
    assert.equal(r.status, kernel.STATUSES.TOOLSET_ATTEST_VALID);
  });

  it('adding a tool after the declaration reads as UNBOUND against the kernel', async (t) => {
    if (!kernel) return t.skip('coderifts-app kernel not present — cross-repo verification UNPROVEN');
    const k = hostKey();
    const tok = await tryIssueToolsetAttestation({ config: CFG(k), tools: TOOLS() });
    const grown = declarationEntriesFromTools(TOOLS()).concat([{ name: 'exec_new', mutation_class: 'mutating' }]);
    const r = kernel.verifyToolsetAttestation(tok, { registry: k.registry, entries: grown });
    assert.equal(r.status, kernel.STATUSES.TOOLSET_ATTEST_UNBOUND);
  });
});
