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
    fingerprint: opts.fingerprint || ARTIFACTS_FP,
    input_fingerprint: opts.fingerprint || ARTIFACTS_FP,
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
const ARTIFACTS_FP = computeCanonicalBundleFingerprint(ARTIFACTS, { operation: 'tool_call' });

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

// ── Shared scenario builders (same harness as OpenAI matrix; face asserts differ) ─
function tableAllowSuccess(execute = async () => ({ applied: true })) {
  return makeTable({
    tools: [{ name: 'apply_openapi', mutationClass: 'mutating', execute }],
  });
}

function tableAllowThrow() {
  return makeTable({
    tools: [{
      name: 'apply_openapi',
      mutationClass: 'mutating',
      execute: async () => {
        throw new Error('boom-side-effect');
      },
    }],
  });
}

function tableBlock(factoryFlag) {
  const env = envelope('STOP', 'BLOCK', {
    decision_id: 'dec_block_1',
    required_action: 'Fix breaking change before re-requesting authorize',
    next_actions: [{ type: 'REEVALUATE', required: true }],
    breaking_changes: 2,
  });
  return makeTable({
    client: mockClient({
      preflight: () => ({
        decision: 'BLOCK',
        execution_action: 'STOP',
        decision_result: env,
      }),
    }),
    tools: [{
      name: 'apply_openapi',
      mutationClass: 'mutating',
      execute: async () => {
        if (factoryFlag) factoryFlag.ran = true;
        return { applied: true };
      },
    }],
  });
}

function tableDrift(factoryFlag) {
  const OP = 'tool_call';
  const A = [{ id: 'a', type: 'openapi', before: 'x', after: 'A' }];
  const A_PRIME = [{ id: 'a', type: 'openapi', before: 'x', after: 'A-DRIFTED' }];
  const fpA = computeCanonicalBundleFingerprint(A, { operation: OP });
  const env = envelope('CONTINUE', 'ALLOW', { fingerprint: fpA, operation: OP });
  env.input_fingerprint = fpA;
  return {
    A_PRIME,
    table: makeTable({
      requireExecutionStateMatch: true,
      client: mockClient({
        preflight: () => ({
          decision: 'ALLOW',
          execution_action: 'CONTINUE',
          decision_result: env,
        }),
      }),
      tools: [{
        name: 'apply_openapi',
        mutationClass: 'mutating',
        execute: async () => {
          if (factoryFlag) factoryFlag.ran = true;
          return { applied: true };
        },
      }],
    }),
  };
}

function tableUnknown(factoryFlag) {
  return makeTable({
    tools: [{
      name: 'apply_openapi',
      mutationClass: 'mutating',
      execute: async () => {
        if (factoryFlag) factoryFlag.ran = true;
        return { applied: true };
      },
    }],
  });
}

// ── Anthropic face — full audit-D matrix (was smoke only) ────────────────────
describe('executeAnthropicToolCall — audit-D matrix', () => {
  it('(i) ALLOW + success → proof-bound tool_result shape', async () => {
    const r = await executeAnthropicToolCall({
      tools: tableAllowSuccess(),
      tool_use_id: 'tu_1',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.type, 'tool_result');
    assert.equal(r.tool_use_id, 'tu_1');
    assert.equal(typeof r.content, 'string');
    assert.match(r.content, /applied/);
    assert.match(r.content, /execution proof|CodeRifts/i);
    assert.deepEqual(Object.keys(r).sort(), ['content', 'tool_use_id', 'type']);
  });

  it('(ii) ALLOW + execution error → proof-bound error, no fake result', async () => {
    const r = await executeAnthropicToolCall({
      tools: tableAllowThrow(),
      tool_use_id: 'tu_err',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.type, 'tool_result');
    assert.match(r.content, /failed|boom-side-effect/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
    assert.match(r.content, /CodeRifts|execution proof/i);
  });

  it('(iii) BLOCK → no execution, proof-bound refusal, envelope surfaced', async () => {
    const flag = { ran: false };
    const r = await executeAnthropicToolCall({
      tools: tableBlock(flag),
      tool_use_id: 'tu_block',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution/);
    assert.match(r.content, /dec_block_1/);
    assert.match(r.content, /decision envelope/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
  });

  it('(iv) requireExecutionStateMatch:true + drift → EXECUTION_STATE_DRIFT proof-bound', async () => {
    const flag = { ran: false };
    const { table, A_PRIME } = tableDrift(flag);
    const r = await executeAnthropicToolCall({
      tools: table,
      tool_use_id: 'tu_drift',
      name: 'apply_openapi',
      arguments: contractArgs(A_PRIME),
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution|UNAVAILABLE/i);
    assert.match(r.content, /EXECUTION_STATE_DRIFT|CodeRifts/i);
  });

  it('(v) dispatcher always embeds proof (measured soft-unavailable is for raw bind only)', async () => {
    const r = await executeAnthropicToolCall({
      tools: tableAllowSuccess(),
      tool_use_id: 'tu_p',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.match(r.content, /proof_spec|execution proof|CodeRifts/i);
    assert.ok(r.content.includes(EXECUTION_PROOF_SPEC) || /ENFORCED|AUTHORIZED|proof/i.test(r.content));
  });

  it('(vi) host-tampered tool_result without proof is detectable vs ProofBound return', async () => {
    const bound = await executeAnthropicToolCall({
      tools: tableAllowSuccess(),
      tool_use_id: 'tu_brand',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    const tampered = {
      type: 'tool_result',
      tool_use_id: 'tu_brand',
      content: '{"applied":true}',
    };
    assert.equal(bound.type, tampered.type);
    assert.notEqual(bound.content, tampered.content);
    assert.match(bound.content, /CodeRifts|execution proof|proof/i);
    assert.doesNotMatch(tampered.content, /execution proof/i);
    assert.ok(bound.content.length > tampered.content.length);
  });

  it('(vii) unknown tool name → typed refusal, factory unreachable', async () => {
    const flag = { ran: false };
    const r = await executeAnthropicToolCall({
      tools: tableUnknown(flag),
      tool_use_id: 'tu_missing',
      name: 'not_in_table',
      arguments: {},
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution|UNAVAILABLE/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
    assert.equal(r.tool_use_id, 'tu_missing');
    assert.equal(r.type, 'tool_result');
  });
});

// ── Gemini face — full audit-D matrix (object response; was BLOCK smoke only) ─
describe('executeGeminiToolCall — audit-D matrix', () => {
  it('(i) ALLOW + success → functionResponse object with result + proof fields', async () => {
    const r = await executeGeminiToolCall({
      tools: tableAllowSuccess(),
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.functionResponse.name, 'apply_openapi');
    const resp = r.functionResponse.response;
    assert.ok(resp && typeof resp === 'object', 'Gemini response is an OBJECT (not stringified)');
    assert.ok('result' in resp);
    assert.deepEqual(resp.result, { applied: true });
    // attachProofToAgentResponse object path
    assert.ok(resp.final_answer_proof || resp.final_answer_proof_text);
    assert.deepEqual(Object.keys(r).sort(), ['functionResponse']);
    assert.deepEqual(Object.keys(r.functionResponse).sort(), ['name', 'response']);
  });

  it('(ii) ALLOW + execution error → gate_message, no fabricated result key', async () => {
    const r = await executeGeminiToolCall({
      tools: tableAllowThrow(),
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    const resp = r.functionResponse.response;
    assert.ok(resp.gate_message);
    assert.match(String(resp.gate_message), /failed|boom-side-effect/i);
    assert.equal('result' in resp, false, 'must not fabricate result on error');
    assert.ok(resp.final_answer_proof || resp.final_answer_proof_text);
  });

  it('(iii) BLOCK → no execution, gate_message, no result, envelope surfaced', async () => {
    const flag = { ran: false };
    const r = await executeGeminiToolCall({
      tools: tableBlock(flag),
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(flag.ran, false);
    const resp = r.functionResponse.response;
    assert.ok(resp.gate_message);
    assert.match(String(resp.gate_message), /did not permit execution/);
    assert.equal('result' in resp, false);
    assert.ok(resp.decision_envelope);
    assert.equal(resp.decision_envelope.decision_id, 'dec_block_1');
    assert.ok(resp.final_answer_proof || resp.final_answer_proof_text);
  });

  it('(iv) requireExecutionStateMatch:true + drift → EXECUTION_STATE_DRIFT proof-bound', async () => {
    const flag = { ran: false };
    const { table, A_PRIME } = tableDrift(flag);
    const r = await executeGeminiToolCall({
      tools: table,
      name: 'apply_openapi',
      arguments: contractArgs(A_PRIME),
    });
    assert.equal(flag.ran, false);
    const resp = r.functionResponse.response;
    assert.equal('result' in resp, false);
    assert.ok(resp.gate_message);
    assert.match(String(resp.gate_message), /did not permit execution|UNAVAILABLE/i);
    // proof text or gate mentions drift cause
    const blob = JSON.stringify(resp);
    assert.match(blob, /EXECUTION_STATE_DRIFT|CodeRifts|execution proof|UNAVAILABLE/i);
  });

  it('(v) dispatcher always embeds proof on Gemini object path', async () => {
    const r = await executeGeminiToolCall({
      tools: tableAllowSuccess(),
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    const resp = r.functionResponse.response;
    assert.ok(
      resp.final_answer_proof
      || (typeof resp.final_answer_proof_text === 'string' && resp.final_answer_proof_text.length > 0),
    );
    if (resp.final_answer_proof) {
      assert.equal(resp.final_answer_proof.proof_spec, EXECUTION_PROOF_SPEC);
    }
  });

  it('(vi) host-tampered functionResponse without proof is detectable', async () => {
    const bound = await executeGeminiToolCall({
      tools: tableAllowSuccess(),
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    const tampered = {
      functionResponse: {
        name: 'apply_openapi',
        response: { result: { applied: true } }, // no final_answer_proof*
      },
    };
    assert.equal(bound.functionResponse.name, tampered.functionResponse.name);
    assert.ok(bound.functionResponse.response.final_answer_proof
      || bound.functionResponse.response.final_answer_proof_text);
    assert.equal('final_answer_proof' in tampered.functionResponse.response, false);
    assert.equal('final_answer_proof_text' in tampered.functionResponse.response, false);
  });

  it('(vii) unknown tool name → typed refusal, no result key, factory unreachable', async () => {
    const flag = { ran: false };
    const r = await executeGeminiToolCall({
      tools: tableUnknown(flag),
      name: 'not_in_table',
      arguments: {},
    });
    assert.equal(flag.ran, false);
    assert.equal(r.functionResponse.name, 'not_in_table');
    const resp = r.functionResponse.response;
    assert.ok(resp.gate_message);
    assert.equal('result' in resp, false);
    assert.match(String(resp.gate_message), /did not permit execution|UNAVAILABLE/i);
  });
});

// ── LangGraph face — full audit-D matrix (was ALLOW smoke only) ──────────────
describe('executeLangGraphToolCall — audit-D matrix', () => {
  it('(i) ALLOW + success → proof-bound ToolMessage shape', async () => {
    const r = await executeLangGraphToolCall({
      tools: tableAllowSuccess(),
      tool_call_id: 'lg_1',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(r.tool_call_id, 'lg_1');
    assert.equal(r.name, 'apply_openapi');
    assert.equal(typeof r.content, 'string');
    assert.match(r.content, /applied/);
    assert.match(r.content, /execution proof|CodeRifts/i);
    assert.deepEqual(Object.keys(r).sort(), ['content', 'name', 'tool_call_id']);
  });

  it('(ii) ALLOW + execution error → proof-bound error, no fake result', async () => {
    const r = await executeLangGraphToolCall({
      tools: tableAllowThrow(),
      tool_call_id: 'lg_err',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.match(r.content, /failed|boom-side-effect/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
    assert.match(r.content, /CodeRifts|execution proof/i);
  });

  it('(iii) BLOCK → no execution, proof-bound refusal, envelope surfaced', async () => {
    const flag = { ran: false };
    const r = await executeLangGraphToolCall({
      tools: tableBlock(flag),
      tool_call_id: 'lg_block',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution/);
    assert.match(r.content, /dec_block_1/);
    assert.match(r.content, /decision envelope/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
  });

  it('(iv) requireExecutionStateMatch:true + drift → EXECUTION_STATE_DRIFT proof-bound', async () => {
    const flag = { ran: false };
    const { table, A_PRIME } = tableDrift(flag);
    const r = await executeLangGraphToolCall({
      tools: table,
      tool_call_id: 'lg_drift',
      name: 'apply_openapi',
      arguments: contractArgs(A_PRIME),
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution|UNAVAILABLE/i);
    assert.match(r.content, /EXECUTION_STATE_DRIFT|CodeRifts/i);
  });

  it('(v) dispatcher always embeds proof', async () => {
    const r = await executeLangGraphToolCall({
      tools: tableAllowSuccess(),
      tool_call_id: 'lg_p',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    assert.match(r.content, /proof_spec|execution proof|CodeRifts/i);
    assert.ok(r.content.includes(EXECUTION_PROOF_SPEC) || /ENFORCED|AUTHORIZED|proof/i.test(r.content));
  });

  it('(vi) host-tampered ToolMessage without proof is detectable', async () => {
    const bound = await executeLangGraphToolCall({
      tools: tableAllowSuccess(),
      tool_call_id: 'lg_brand',
      name: 'apply_openapi',
      arguments: contractArgs(),
    });
    const tampered = {
      content: '{"applied":true}',
      tool_call_id: 'lg_brand',
      name: 'apply_openapi',
    };
    assert.equal(bound.tool_call_id, tampered.tool_call_id);
    assert.notEqual(bound.content, tampered.content);
    assert.match(bound.content, /CodeRifts|execution proof|proof/i);
    assert.doesNotMatch(tampered.content, /execution proof/i);
    assert.ok(bound.content.length > tampered.content.length);
  });

  it('(vii) unknown tool name → typed refusal, factory unreachable', async () => {
    const flag = { ran: false };
    const r = await executeLangGraphToolCall({
      tools: tableUnknown(flag),
      tool_call_id: 'lg_missing',
      name: 'not_in_table',
      arguments: {},
    });
    assert.equal(flag.ran, false);
    assert.match(r.content, /did not permit execution|UNAVAILABLE/i);
    assert.doesNotMatch(r.content, /"applied":\s*true/);
    assert.equal(r.tool_call_id, 'lg_missing');
    assert.equal(r.name, 'not_in_table');
  });
});

describe('executeOpenAIToolCall — withCodeRifts table path (regression)', () => {
  it('withCodeRifts result accepted as tools table', async () => {
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
