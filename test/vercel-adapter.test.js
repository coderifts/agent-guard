'use strict';

/**
 * Roadmap 129 — Vercel AI SDK tool adapter over withCodeRifts.
 *
 * Same proofs as the OpenAI/Anthropic adapters; target shape is a dependency-free
 * generateText tools record matching v4 tool({ description, parameters, execute }).
 *
 * Proofs:
 *  1. withCodeRiftsVercel calls the core (guarded tools + assurance present)
 *  2. Vercel tool shape: { description?, parameters, execute } keyed by name
 *  3. ONLY protected tools in the Vercel table (never raw-only names)
 *  4. composition_assurance / registry_report / receipt_thread passed through unflattened
 *  5. ALLOW → real execute runs; REFUSE → execute blocked, Vercel result shape
 *  6. Example module loads and matches the same shape
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { pathToFileURL } = require('node:url');

const {
  withCodeRiftsVercel,
  vercelToolAdapter,
  toVercelTools,
  protectedToolToVercel,
  withCodeRifts,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
} = require('../dist/cjs/index.js');

const STUB_CLIENT = { preflight: async () => ({}) };

const rawTools = () => [
  {
    name: 'edit_file',
    description: 'Edit a file',
    mutationClass: 'mutating',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        old_string: { type: 'string' },
        new_string: { type: 'string' },
      },
      required: ['path', 'old_string', 'new_string'],
    },
    execute: async () => 'edited',
  },
  {
    name: 'read_file',
    description: 'Read a file',
    mutationClass: 'readonly',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
    },
    execute: async () => 'read',
  },
];

describe('withCodeRiftsVercel — thin Vercel AI SDK adapter (roadmap 129)', () => {
  it('1. returns a generateText tools record from raw tools + client + operation', () => {
    const r = withCodeRiftsVercel({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    assert.equal(typeof r.tools, 'object');
    assert.ok(r.tools !== null);
    assert.equal(Array.isArray(r.tools), false, 'Vercel tools is a Record, not an array');
    const names = Object.keys(r.tools).sort();
    assert.deepEqual(names, ['edit_file', 'read_file']);
    for (const name of names) {
      const t = r.tools[name];
      assert.equal(typeof t.parameters, 'object');
      assert.ok(t.parameters !== null);
      assert.equal(typeof t.execute, 'function');
      // Vercel tool() object: no OpenAI type/function wrapper, no Anthropic input_schema
      assert.equal('type' in t, false);
      assert.equal('function' in t, false);
      assert.equal('input_schema' in t, false);
      assert.equal('_coderifts' in t, false);
    }
    const edit = r.tools.edit_file;
    assert.equal(edit.description, 'Edit a file');
    assert.equal(edit.parameters.type, 'object');
    assert.ok(edit.parameters.properties.path);
  });

  it('2. PROOF only-protected-tools: Vercel names ⊆ protected_tools; no raw-only leakage', () => {
    const raw = rawTools();
    const r = withCodeRiftsVercel({ tools: raw, client: STUB_CLIENT, operation: 'merge' });
    const vercelNames = Object.keys(r.tools).sort();
    const protectedNames = r.protected_tools.map((t) => t.name).sort();
    assert.deepEqual(vercelNames, protectedNames, 'Vercel tools are exactly the protected set');
    for (const p of r.protected_tools) {
      assert.ok(p._coderifts, 'protected_tools carry _coderifts (guarded registry surface)');
      assert.equal(typeof p.execute, 'function');
    }
  });

  it('3. PROOF assurance passed through unflattened (composition may still be incomplete)', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const r = withCodeRiftsVercel({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });

    assert.deepEqual(r.composition_assurance, core.composition_assurance);
    assert.deepEqual(r.registry_report, core.registry_report);
    assert.equal(typeof r.receipt_thread, 'object');
    assert.equal(typeof r.receipt_thread.enabled, 'boolean');
    assert.equal(typeof r.coverage_observed.snapshot, 'function');
    assert.equal(typeof r.coverage_observed.reportToolDispatch, 'function');
    assert.equal(r.composition_assurance.observed_class, 'UNKNOWN_OUTSIDE_SCOPE');

    assert.equal(r.registry_report.coverage, 'COMPLETE');
    assert.equal(r.composition_assurance.coverage, 'PARTIAL');
    assert.equal(r.composition_assurance.inescapable_runtime, false);
    assert.ok(
      r.composition_assurance.residuals.includes('composition_call_policy_incomplete'),
      `expected composition_call_policy_incomplete residual, got ${JSON.stringify(r.composition_assurance.residuals)}`,
    );
  });

  it('4. vercelToolAdapter composition style matches withCodeRiftsVercel shape', () => {
    const core = withCodeRifts({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    const viaAdapter = vercelToolAdapter(core);
    const viaOneShot = withCodeRiftsVercel({ tools: rawTools(), client: STUB_CLIENT, operation: 'merge' });
    assert.deepEqual(Object.keys(viaAdapter.tools).sort(), Object.keys(viaOneShot.tools).sort());
    assert.deepEqual(
      viaAdapter.tools.edit_file.parameters,
      viaOneShot.tools.edit_file.parameters,
    );
    assert.deepEqual(viaAdapter.composition_assurance, viaOneShot.composition_assurance);
    assert.deepEqual(viaAdapter.registry_report, viaOneShot.registry_report);
    assert.equal(viaAdapter.coverage_observed, core.coverage_observed);
  });

  it('5. protectedToolToVercel / toVercelTools: empty schema when inputSchema missing', () => {
    const bare = {
      name: 'noop',
      execute: async () => 'ok',
      _coderifts: { guarded: false, mutationClass: 'readonly' },
    };
    const d = protectedToolToVercel(bare);
    assert.equal(d.parameters.type, 'object');
    assert.deepEqual(d.parameters.properties, {});
    assert.equal(typeof d.execute, 'function');
    assert.equal('description' in d, false);
    const rec = toVercelTools([bare]);
    assert.deepEqual(Object.keys(rec), ['noop']);
    assert.equal(typeof rec.noop.execute, 'function');
  });

  it('5b. readonly execute calls the guarded execute (passthrough raw result)', async () => {
    const r = withCodeRiftsVercel({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
    });
    const out = await r.tools.read_file.execute({ path: 'x' }, { toolCallId: 'tc_ro' });
    assert.equal(out, 'read');
  });

  it('6. missing operation still fails at construction (core rule, not reimplemented)', () => {
    assert.throws(
      () => withCodeRiftsVercel({ tools: rawTools(), client: STUB_CLIENT }),
      (err) => err instanceof Error && /operation/i.test(err.message),
    );
  });

  it('7. repository is carried through when supplied', () => {
    const r = withCodeRiftsVercel({
      tools: rawTools(),
      client: STUB_CLIENT,
      operation: 'merge',
      repository: 'acme/api',
    });
    assert.equal(r.repository, 'acme/api');
  });

  it('8. PROOF no hard ai/zod dependency in package or adapter source', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    for (const name of Object.keys(deps || {})) {
      assert.ok(
        name !== 'ai' && name !== 'zod' && !name.startsWith('@ai-sdk/'),
        `unexpected framework dep ${name} — adapter must stay dependency-free`,
      );
    }
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'adapters', 'vercel.ts'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    assert.doesNotMatch(src, /from\s+['"]ai['"]/);
    assert.doesNotMatch(src, /from\s+['"]zod['"]/);
    assert.doesNotMatch(src, /require\s*\(\s*['"]ai['"]/);
  });
});

function signedFor(env) {
  return { fp: env.fingerprint, bh: computeBodyHash(env) };
}

function envelope(execution_action, decision, opts = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_vercel_1',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: opts.expires_at || '2099-01-01T00:00:00Z',
    fingerprint: opts.fingerprint || ARTIFACTS_FP,
    input_fingerprint: opts.fingerprint || ARTIFACTS_FP,
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    operation: opts.operation || 'tool_call',
    required_action: null,
    receipt: opts.noReceipt
      ? undefined
      : { token: 'tok', format_version: 'v4', key_id: 'k', issued_at: 'x' },
  };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  return env;
}

function mockClient({ preflight, verify } = {}) {
  let lastEnv = null;
  return {
    async authorizeChangeSet(r) {
      return this.preflightChangeSet({ ...r, preflight_mode: 'authorize' });
    },
    async preflightChangeSet() {
      const resp = preflight
        ? preflight()
        : {
            decision: 'ALLOW',
            execution_action: 'CONTINUE',
            decision_result: envelope('CONTINUE', 'ALLOW'),
          };
      lastEnv = resp && resp.decision_result;
      return resp;
    },
    async verifyReceipt() {
      if (verify) return verify();
      return lastEnv
        ? { valid: true, status: 'VERIFIED_CURRENT', payload: signedFor(lastEnv) }
        : { valid: true, status: 'VERIFIED_CURRENT' };
    },
  };
}

const ARTIFACTS = [
  {
    id: 'a',
    type: 'openapi',
    before: 'openapi: 3.0.0\ninfo: {title: A}',
    after: 'openapi: 3.0.1\ninfo: {title: A}',
  },
];
const ARTIFACTS_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

describe('withCodeRiftsVercel — execute gate (ALLOW / REFUSE)', () => {
  it('gate ALLOWS → real execute runs; Vercel tool-result shape', async () => {
    let factoryRan = false;
    const r = withCodeRiftsVercel({
      tools: [{
        name: 'apply_openapi',
        mutationClass: 'mutating',
        execute: async () => {
          factoryRan = true;
          return { applied: true };
        },
      }],
      client: mockClient(),
      operation: 'tool_call',
    });
    const out = await r.tools.apply_openapi.execute(
      { artifacts: ARTIFACTS },
      { toolCallId: 'call_allow_v' },
    );
    assert.equal(factoryRan, true, 'factory must run on ALLOW');
    // generateText RESULT: proof-bound string (not a nested tool-result part).
    assert.equal(typeof out, 'string');
    assert.match(out, /applied/);
    assert.match(out, /CodeRifts execution proof/);
    assert.doesNotMatch(out, /"type":"tool-result"/);
  });

  it('gate REFUSES → execute is blocked; refusal in Vercel tool-result shape', async () => {
    let factoryRan = false;
    const env = envelope('STOP', 'BLOCK', { decision_id: 'dec_block_v' });
    const r = withCodeRiftsVercel({
      tools: [{
        name: 'apply_openapi',
        mutationClass: 'mutating',
        execute: async () => {
          factoryRan = true;
          return { applied: true };
        },
      }],
      client: mockClient({
        preflight: () => ({
          decision: 'BLOCK',
          execution_action: 'STOP',
          decision_result: env,
        }),
      }),
      operation: 'tool_call',
    });
    const out = await r.tools.apply_openapi.execute(
      { artifacts: ARTIFACTS },
      { toolCallId: 'call_block_v' },
    );
    assert.equal(factoryRan, false, 'factory must not run on BLOCK');
    // generateText RESULT: refusal body (Vercel puts this in ToolResultPart.result).
    assert.equal(typeof out, 'string');
    assert.match(out, /did not permit execution/i);
    assert.match(out, /verdict: BLOCK/);
    assert.doesNotMatch(out, /"applied":\s*true/);
    assert.match(out, /CodeRifts execution proof/);
  });
});

describe('examples/vercel-adapter — offline demo', () => {
  it('example module exports Vercel tools record + unflattened assurance', async () => {
    const url = pathToFileURL(path.join(__dirname, '..', 'examples', 'vercel-adapter.mjs')).href;
    const mod = await import(url);
    assert.equal(typeof mod.tools, 'object');
    assert.ok(mod.tools.edit_file);
    assert.equal(typeof mod.tools.edit_file.parameters, 'object');
    assert.equal(typeof mod.tools.edit_file.execute, 'function');
    assert.ok(mod.composition_assurance);
    assert.equal(mod.composition_assurance.inescapable_runtime, false);
    assert.ok(Array.isArray(mod.protected_tools));
    assert.equal(Object.keys(mod.tools).length, mod.protected_tools.length);
  });
});
