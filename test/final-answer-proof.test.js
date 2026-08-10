'use strict';

/**
 * ID645 — human-readable final-answer proof block (render layer).
 * Does not re-test buildExecutionProof assembly; uses frozen-shaped fixtures.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  renderFinalAnswerProof,
  attachProofToAgentResponse,
  deriveProofBanner,
  EXECUTION_PROOF_SPEC,
  buildExecutionProof,
} = require('../dist/cjs/index.js');

const LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
});

function proofVerified() {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_ok_1',
    receipt: Object.freeze({
      verified: true,
      status: 'VERIFIED_CURRENT',
      expires_at: '2099-01-01T00:00:00.000Z',
    }),
    binds_to: Object.freeze({
      operation: 'tool_call',
      change_fp: 'sha256:' + 'c'.repeat(64),
    }),
    currently_authorized: true,
    execution: Object.freeze({ attempted: true, executed: true, enforced: true }),
    verdict_kind: 'ALLOW',
    execution_result_hash: Object.freeze({
      status: 'hashed',
      algorithm: 'sha256',
      value: 'a'.repeat(64),
    }),
    limits: LIMITS,
  });
}

function proofSkipped() {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: false,
    decision_id: null,
    receipt: Object.freeze({ verified: false, status: null, expires_at: null }),
    binds_to: null,
    currently_authorized: null,
    execution: Object.freeze({ attempted: true, executed: true, enforced: false }),
    verdict_kind: 'SKIPPED',
    execution_result_hash: Object.freeze({
      status: 'not_hashed',
      reason: 'not_executed',
    }),
    limits: LIMITS,
  });
}

function proofUnauthorized() {
  return Object.freeze({
    proof_spec: EXECUTION_PROOF_SPEC,
    preflighted: true,
    decision_id: 'dec_block_1',
    receipt: Object.freeze({ verified: false, status: null, expires_at: '2099-01-01T00:00:00.000Z' }),
    binds_to: Object.freeze({ operation: 'tool_call', change_fp: 'sha256:' + 'd'.repeat(64) }),
    currently_authorized: false,
    execution: Object.freeze({ attempted: false, executed: false, enforced: false }),
    verdict_kind: 'BLOCK',
    execution_result_hash: Object.freeze({ status: 'not_hashed', reason: 'not_executed' }),
    limits: LIMITS,
  });
}

describe('renderFinalAnswerProof — field mapping & honesty', () => {
  it('verified/enforced case: status ENFORCED, receipt verified, authz true, binds_to present', () => {
    const text = renderFinalAnswerProof(proofVerified());
    assert.match(text, /ENFORCED/);
    assert.match(text, /receipt\.verified: yes/);
    assert.match(text, /VERIFIED_CURRENT/);
    assert.match(text, /currently_authorized: true/);
    assert.match(text, /operation: tool_call/);
    assert.match(text, /change_fp: sha256:c+/);
    assert.match(text, /CHECKED at preflight/i);
    assert.match(text, /enforced: yes/);
    assert.match(text, /executed: yes/);
    assert.match(text, /verdict_kind: ALLOW/);
    assert.match(text, /dec_ok_1/);
  });

  it('SKIPPED (currently_authorized null) is visibly different — NOT a pass', () => {
    const text = renderFinalAnswerProof(proofSkipped());
    assert.match(text, /NOT EVALUATED \(SKIPPED\)/);
    assert.match(text, /currently_authorized: null/);
    assert.match(text, /not a pass/i);
    assert.doesNotMatch(text, /\bENFORCED\b/);
    assert.doesNotMatch(text, /Status:.*AUTHORIZED — receipt verified/);
    assert.match(text, /do NOT treat this as protected/i);
  });

  it('unauthorized (currently_authorized false) is NOT presented as protected', () => {
    const text = renderFinalAnswerProof(proofUnauthorized());
    assert.match(text, /NOT AUTHORIZED/);
    assert.match(text, /currently_authorized: false/);
    assert.doesNotMatch(text, /\bENFORCED\b/);
    assert.match(text, /do NOT present this call as receipt-protected/i);
  });

  it('verified vs skipped banners differ', () => {
    assert.equal(deriveProofBanner(proofVerified()), 'ENFORCED');
    assert.equal(deriveProofBanner(proofSkipped()), 'NOT_EVALUATED_SKIPPED');
    assert.equal(deriveProofBanner(proofUnauthorized()), 'PREFLIGHTED_NOT_AUTHORIZED');
    const a = renderFinalAnswerProof(proofVerified());
    const b = renderFinalAnswerProof(proofSkipped());
    assert.notEqual(a, b);
    assert.match(a, /ENFORCED/);
    assert.match(b, /SKIPPED/);
  });

  it('SURFACES limits — especially host_cannot_bypass and outside_guarded_path', () => {
    const text = renderFinalAnswerProof(proofVerified());
    assert.match(text, /Limits \(non-claims/);
    assert.match(text, /does NOT claim the host cannot bypass/i);
    assert.match(text, /outside the guarded path are invisible/i);
    assert.match(text, /does_not_claim_host_cannot_bypass=true/);
    assert.match(text, /calls_outside_guarded_path_invisible=true/);
    assert.match(text, /does NOT claim the change is safe/i);
    assert.match(text, /not what the factory executed/i);
    // Even the verified block must not read as "fully protected" without limits.
    assert.doesNotMatch(text, /fully protected/i);
    assert.doesNotMatch(text, /✓ fully/i);
  });

  it('limits still surface on SKIPPED (same non-claims)', () => {
    const text = renderFinalAnswerProof(proofSkipped());
    assert.match(text, /does_not_claim_host_cannot_bypass=true/);
    assert.match(text, /calls_outside_guarded_path_invisible=true/);
  });

  it('plain format omits markdown ## headings', () => {
    const text = renderFinalAnswerProof(proofVerified(), { format: 'plain' });
    assert.doesNotMatch(text, /^## /m);
    assert.match(text, /CodeRifts execution proof/);
    assert.match(text, /does_not_claim_host_cannot_bypass=true/);
  });

  // ── the limits block is not optional (ID645 / audit part 4) ────────────────────────────────────
  // There used to be an includeLimits option whose `false` suppressed the whole block. Nothing ever
  // passed it, and a proof that drops its non-claims while keeping the same title is precisely the
  // overclaim this render layer exists to prevent. The option is gone; these pin that it cannot
  // come back by accident — including via a stale JS caller still passing the removed key.
  it('the limits block is UNCONDITIONAL — every option combination still renders it', () => {
    const combos = [
      undefined,
      {},
      { format: 'plain' },
      { format: 'markdown' },
      { title: 'Custom title' },
      { format: 'plain', title: 'Custom title' },
    ];
    for (const opts of combos) {
      const text = opts === undefined
        ? renderFinalAnswerProof(proofVerified())
        : renderFinalAnswerProof(proofVerified(), opts);
      const label = JSON.stringify(opts);
      assert.match(text, /Limits \(non-claims/, `limits heading missing for opts=${label}`);
      assert.match(text, /does_not_claim_host_cannot_bypass=true/, `limit keys missing for opts=${label}`);
      assert.match(
        text, /honest because it states its limits/,
        `honesty sentence missing for opts=${label}`,
      );
    }
  });

  it('a stale caller passing the REMOVED includeLimits:false is ignored, not obeyed', () => {
    // TypeScript no longer offers the key, but a JS host on an old call site can still pass it.
    // It must be inert: suppressing the limits at runtime would silently resurrect the defect.
    const text = renderFinalAnswerProof(proofVerified(), { includeLimits: false });
    assert.match(text, /Limits \(non-claims/);
    assert.match(text, /honest because it states its limits/);
    const plain = renderFinalAnswerProof(proofVerified(), { format: 'plain', includeLimits: false });
    assert.match(plain, /Limits \(non-claims/);
  });

  it('plain format is the compaction path — it drops markup but KEEPS every limit line', () => {
    const md = renderFinalAnswerProof(proofVerified(), { format: 'markdown' });
    const plain = renderFinalAnswerProof(proofVerified(), { format: 'plain' });
    const limitsOf = (t) => t
      .split('\n')
      .filter((l) => /^[-*] /.test(l) && /(NOT |does_not_|limits\.|Absent fields|host-asserted)/.test(l))
      .map((l) => l.replace(/^[-*] /, '').trim());
    assert.ok(limitsOf(plain).length > 0, 'plain must render limit lines');
    assert.deepEqual(
      limitsOf(plain), limitsOf(md),
      'plain and markdown must state the SAME limits — plain compacts markup, not content',
    );
    assert.doesNotMatch(plain, /^## /m, 'plain still drops markdown headings');
  });

  it('invalid / missing proof → unavailable status (no overclaim)', () => {
    const text = renderFinalAnswerProof(null);
    assert.match(text, /UNAVAILABLE/i);
    assert.match(text, /no protection claim/i);
  });
});

describe('attachProofToAgentResponse — embedding convention', () => {
  it('append_text on string appends rendered block', () => {
    const out = attachProofToAgentResponse('Answer: done.', proofVerified());
    assert.equal(typeof out, 'string');
    assert.match(out, /^Answer: done\./);
    assert.match(out, /CodeRifts execution proof/);
    assert.match(out, /ENFORCED/);
    assert.match(out, /does_not_claim_host_cannot_bypass=true/);
  });

  it('object gets final_answer_proof + final_answer_proof_text; text field appended', () => {
    const out = attachProofToAgentResponse(
      { text: 'Hello user', meta: 1 },
      proofSkipped(),
    );
    assert.equal(out.meta, 1);
    assert.ok(out.final_answer_proof);
    assert.equal(out.final_answer_proof.currently_authorized, null);
    assert.match(out.final_answer_proof_text, /SKIPPED/);
    assert.match(out.text, /Hello user/);
    assert.match(out.text, /NOT EVALUATED \(SKIPPED\)/);
  });

  it('field_only does not append into text', () => {
    const out = attachProofToAgentResponse(
      { text: 'Keep me pure' },
      proofVerified(),
      { mode: 'field_only' },
    );
    assert.equal(out.text, 'Keep me pure');
    assert.match(out.final_answer_proof_text, /ENFORCED/);
  });

  it('field_only on string wraps object', () => {
    const out = attachProofToAgentResponse('bare', proofUnauthorized(), { mode: 'field_only' });
    assert.equal(out.text, 'bare');
    assert.match(out.final_answer_proof_text, /NOT AUTHORIZED/);
  });
});

describe('renderFinalAnswerProof — live buildExecutionProof fixtures', () => {
  it('renders a buildExecutionProof ALLOW/enforced block with limits', () => {
    // Minimal verdict shape the builder accepts (no full guard round-trip required).
    const p = buildExecutionProof({
      preflighted: true,
      executionAttempted: true,
      executed: true,
      enforced: true,
      verdict: {
        kind: 'ALLOW',
        envelope: {
          decision_id: 'dec_live_1',
          expires_at: '2099-01-01T00:00:00.000Z',
          operation: 'tool_call',
          fingerprint: 'sha256:' + 'e'.repeat(64),
        },
        receiptVerified: true,
      },
      result: 'stable-string',
    });
    const text = renderFinalAnswerProof(p);
    assert.match(text, /ENFORCED|AUTHORIZED/);
    assert.match(text, /currently_authorized: true/);
    assert.match(text, /does_not_claim_host_cannot_bypass=true/);
  });

  it('renders SKIPPED-style proof from buildExecutionProof (no envelope)', () => {
    const p = buildExecutionProof({
      preflighted: false,
      executionAttempted: true,
      executed: true,
      enforced: false,
      verdict: { kind: 'SKIPPED' },
      result: 'ok',
    });
    assert.equal(p.currently_authorized, null);
    const text = renderFinalAnswerProof(p);
    assert.match(text, /SKIPPED|null/);
    assert.match(text, /not a pass/i);
    assert.doesNotMatch(text, /\bENFORCED\b/);
  });
});
