'use strict';

/**
 * Option A safe dispatcher — audit-D matrix (ALLOW/BLOCK/error/drift/unknown/brand).
 * No real API; mock client. Mutator execute returns GuardOutcome (measured).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  guardToolRegistry,
  withCodeRifts,
  executeOpenAIToolCall,
  executeAnthropicToolCall,
  executeGeminiToolCall,
  executeLangGraphToolCall,
  executeProtectedTool,
  isGuardOutcome,
  surfaceEnvelopeFields,
  computeBodyHash,
  computeCanonicalBundleFingerprint,
  EXECUTION_PROOF_SPEC,
} = require('../dist/cjs/index.js');

function signedFor(env) {
  return { fp: env.fingerprint, bh: computeBodyHash(env) };
}

function envelope(execution_action, decision, opts = {}) {
  const env = {
    spec_version: 'decision-result.v1.1',
    decision,
    execution_action,
    decision_id: opts.decision_id || 'dec_dispatch_1',
    correlation_id: 'c',
    evaluated_at: '2026-07-28T00:00:00Z',
    expires_at: opts.expires_at || '2099-01-01T00:00:00Z',
    fingerprint: opts.fingerprint || ('sha256:' + 'd'.repeat(64)),
    input_fingerprint: opts.fingerprint || ('sha256:' + 'd'.repeat(64)),
    safe_for_agent: decision === 'ALLOW' || decision === 'WARN',
    analysis_complete: true,
    operation: opts.operation || 'tool_call',
    required_action: opts.required_action !== undefined ? opts.required_action : null,
    next_actions: opts.next_actions,
    breaking_changes: opts.breaking_changes,
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

function contractArgs(artifacts = ARTIFACTS) {
  return { artifacts };
}

function makeTable(opts = {}) {
  const client = opts.client || mockClient();
  const tools = opts.tools || [
    {
      name: 'apply_openapi',
      mutationClass: 'mutating',
      execute: async () => ({ applied: true }),
    },
  ];
  const reg = guardToolRegistry(tools, {
    guard: {
      client,
      operation: 'tool_call',
      requireExecutionStateMatch: opts.requireExecutionStateMatch,
      ...opts.guard,
    },
  });
  return reg.tools;
}

// ── (a) execute returns GuardOutcome ─────────────────────────────────────────
describe('executeProtectedTool — measured GuardOutcome path', () => {
  it('mutator execute returns GuardOutcome (not unwrapped result)', async () => {
    const table = makeTable();
    const out = await executeProtectedTool(table, 'apply_openapi', contractArgs());
    assert.equal(isGuardOutcome(out), true);
    assert.equal(out.executed, true);
    assert.ok(out.proof && out.proof.proof_spec === EXECUTION_PROOF_SPEC);
    assert.deepEqual(out.result, { applied: true });
  });
});

// ── OpenAI face — audit-D matrix ─────────────────────────────────────────────
describe('executeOpenAIToolCall — audit-D matrix', () => {
  it('(i) ALLOW + success → proof-bound result with brand-shaped fields only', async () => {
    const table = makeTable();
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_1',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(msg.role, 'tool');
    assert.equal(msg.tool_call_id, 'call_1');
    assert.equal(typeof msg.content, 'string');
    assert.match(msg.content, /applied/);
    assert.match(msg.content, /execution proof|CodeRifts/i);
    // Wire shape only
    assert.deepEqual(Object.keys(msg).sort(), ['content', 'role', 'tool_call_id']);
  });

  it('(ii) ALLOW + execution error → proof-bound error, no fake success result', async () => {
    const table = makeTable({
      tools: [
        {
          name: 'apply_openapi',
          mutationClass: 'mutating',
          execute: async () => {
            throw new Error('boom-side-effect');
          },
        },
      ],
    });
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_err',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(msg.role, 'tool');
    assert.match(msg.content, /failed|boom-side-effect/i);
    assert.doesNotMatch(msg.content, /"applied":\s*true/);
    assert.match(msg.content, /CodeRifts|execution proof/i);
  });

  it('(iii) BLOCK → no execution, proof-bound refusal, envelope surfaced', async () => {
    let factoryRan = false;
    const env = envelope('STOP', 'BLOCK', {
      decision_id: 'dec_block_1',
      required_action: 'Fix breaking change before re-requesting authorize',
      next_actions: [{ type: 'REEVALUATE', required: true }],
      breaking_changes: 2,
    });
    const table = makeTable({
      client: mockClient({
        preflight: () => ({
          decision: 'BLOCK',
          execution_action: 'STOP',
          decision_result: env,
        }),
      }),
      tools: [
        {
          name: 'apply_openapi',
          mutationClass: 'mutating',
          execute: async () => {
            factoryRan = true;
            return { applied: true };
          },
        },
      ],
    });
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_block',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(factoryRan, false, 'factory must not run on BLOCK');
    assert.match(msg.content, /did not permit execution/);
    assert.match(msg.content, /dec_block_1/);
    assert.match(msg.content, /decision envelope/i);
    assert.match(msg.content, /BLOCK|STOP/);
    assert.doesNotMatch(msg.content, /"applied":\s*true/);
  });

  it('(iv) requireExecutionStateMatch:true + drift → EXECUTION_STATE_DRIFT proof-bound', async () => {
    const OP = 'tool_call';
    const A = [
      { id: 'a', type: 'openapi', before: 'x', after: 'A' },
    ];
    const A_PRIME = [
      { id: 'a', type: 'openapi', before: 'x', after: 'A-DRIFTED' },
    ];
    const fpA = computeCanonicalBundleFingerprint(A, { operation: OP });
    let factoryRan = false;
    const env = envelope('CONTINUE', 'ALLOW', {
      fingerprint: fpA,
      operation: OP,
    });
    env.input_fingerprint = fpA;
    const table = makeTable({
      requireExecutionStateMatch: true,
      client: mockClient({
        preflight: () => ({
          decision: 'ALLOW',
          execution_action: 'CONTINUE',
          decision_result: env,
        }),
      }),
      tools: [
        {
          name: 'apply_openapi',
          mutationClass: 'mutating',
          execute: async () => {
            factoryRan = true;
            return { applied: true };
          },
        },
      ],
    });
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_drift',
      name: 'apply_openapi',
      arguments: contractArgs(A_PRIME),
    });
    assert.equal(factoryRan, false);
    assert.match(msg.content, /did not permit execution|UNAVAILABLE/i);
    assert.match(msg.content, /EXECUTION_STATE_DRIFT|CodeRifts/i);
  });

  it('(v) missing/invalid proof on raw bind is soft-unavailable in render — dispatcher always has proof', async () => {
    // Dispatcher never returns without going through binder with an outcome that has proof.
    const table = makeTable();
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_p',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.match(msg.content, /proof_spec|execution proof|CodeRifts/i);
    assert.ok(msg.content.includes(EXECUTION_PROOF_SPEC) || /ENFORCED|AUTHORIZED|proof/i.test(msg.content));
  });

  it('(vi) host-tampered message without brand is structurally distinct from ProofBound return', async () => {
    const table = makeTable();
    const bound = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_brand',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    // Wire-identical keys, but a host-crafted message is a plain object without going through bind.
    const tampered = {
      role: 'tool',
      tool_call_id: 'call_brand',
      content: '{"applied":true}', // no proof block
    };
    assert.equal(bound.role, tampered.role);
    assert.notEqual(bound.content, tampered.content);
    assert.match(bound.content, /CodeRifts|execution proof|proof/i);
    assert.doesNotMatch(tampered.content, /execution proof/i);
    // Type-level brand is compile-time; runtime detection = proof content present
    assert.ok(bound.content.length > tampered.content.length);
  });

  it('(vii) unknown tool name → typed refusal, factory unreachable', async () => {
    let factoryRan = false;
    const table = makeTable({
      tools: [
        {
          name: 'apply_openapi',
          mutationClass: 'mutating',
          execute: async () => {
            factoryRan = true;
            return { applied: true };
          },
        },
      ],
    });
    const msg = await executeOpenAIToolCall({
      tools: table,
      tool_call_id: 'call_missing',
      name: 'not_in_table',
      arguments: {},
    });
    assert.equal(factoryRan, false);
    assert.match(msg.content, /did not permit execution|UNAVAILABLE/i);
    assert.doesNotMatch(msg.content, /"applied":\s*true/);
    assert.equal(msg.tool_call_id, 'call_missing');
  });
});

// ── Other frameworks (shape smoke + BLOCK) ───────────────────────────────────
describe('executeAnthropic / Gemini / LangGraph faces', () => {
  it('Anthropic ALLOW success is tool_result branded shape', async () => {
    const table = makeTable();
    const r = await executeAnthropicToolCall({
      tools: table,
      tool_use_id: 'tu_1',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.type, 'tool_result');
    assert.equal(r.tool_use_id, 'tu_1');
    assert.match(r.content, /applied/);
  });

  it('Gemini BLOCK has gate_message, no result key, envelope when present', async () => {
    const env = envelope('STOP', 'BLOCK', { decision_id: 'dec_g_block' });
    const table = makeTable({
      client: mockClient({
        preflight: () => ({
          decision: 'BLOCK',
          execution_action: 'STOP',
          decision_result: env,
        }),
      }),
    });
    const r = await executeGeminiToolCall({
      tools: table,
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.functionResponse.name, 'apply_openapi');
    const resp = r.functionResponse.response;
    assert.ok(resp.gate_message);
    assert.equal('result' in resp, false, 'must not fabricate result on BLOCK');
    assert.ok(resp.decision_envelope);
    assert.equal(resp.decision_envelope.decision_id, 'dec_g_block');
  });

  it('LangGraph ALLOW success has tool_call_id + name', async () => {
    const table = makeTable();
    const r = await executeLangGraphToolCall({
      tools: table,
      tool_call_id: 'lg_1',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.tool_call_id, 'lg_1');
    assert.equal(r.name, 'apply_openapi');
    assert.match(r.content, /applied/);
  });

  it('withCodeRifts result accepted as tools table (protected_tools path)', async () => {
    const core = withCodeRifts({
      tools: [
        {
          name: 'apply_openapi',
          mutationClass: 'mutating',
          execute: async () => ({ via: 'wcr' }),
        },
      ],
      client: mockClient(),
      operation: 'tool_call',
    });
    const msg = await executeOpenAIToolCall({
      tools: core,
      tool_call_id: 'call_wcr',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.match(msg.content, /via/);
  });
});

describe('surfaceEnvelopeFields — measured only', () => {
  it('lifts known fields; ignores inventable remediation', () => {
    const s = surfaceEnvelopeFields({
      decision_id: 'd1',
      decision: 'BLOCK',
      execution_action: 'STOP',
      required_action: 'display only',
      next_actions: [{ type: 'REEVALUATE' }],
      breaking_changes: 3,
      // not in measured surface list as free-form remediation engine
      made_up_remediation_script: 'rm -rf /',
    });
    assert.equal(s.decision_id, 'd1');
    assert.equal(s.breaking_changes, 3);
    assert.equal(s.required_action, 'display only');
    assert.equal('made_up_remediation_script' in s, false);
  });
});
