'use strict';

/**
 * Pentad red-team regression suite (pentad-redteam-matrix v1.0, 18 fixtures). Locks the two P0 leak
 * fixes and proves the existing defenses hold. Matrix VENDORED into this test dir, loaded by a
 * RELATIVE path (the ENOENT lesson).
 *
 * Fixed THIS round (the two P0s + the normOp consequence):
 *   - RT-P-01 (RTM-001): merge-gate rejects an ABSENT operation → operation_mismatch (mirrors deploy T7).
 *   - RT-P-05 (RTM-005): RELABELED — with the shared normOp, 'Merge' normalizes to a valid merge and is
 *     ACCEPTED (casing is notation, not an attack); a real other op still fails. Expectation updated.
 *   - RT-P-13 (RTM-013): coverageReport merge/deploy ENFORCING requires the flag AND a consistent
 *     enforcement_state; an inconsistent inescapable_* claim → WEAK + inescapable_flag_inconsistent.
 *
 * DEFERRED to P1/P2 (out of this round's two-P0 scope — new fields/behaviors, tracked, not shipped):
 *   - RT-P-11 / RT-P-12 (RTM-011/012): ENFORCING should force require_bound_environment/artifact true.
 *   - RT-P-16 (RTM-016/016b): applicability_attested gate.
 *   - RT-P-20 (RTM-020): require_fingerprint on ENFORCING merge.
 *
 * CONFIRMED_SAFE rows assert the already-shipped defenses (T7, stale head, env staging≠prod, full
 * SHA/artifact equality, missing→UNKNOWN) still hold against the CURRENT (now-fixed) code.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { gateDecision, deployGate, coverageReport } = require('../dist/cjs/index.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'pentad-redteam-matrix.json'), 'utf8'));
const FIXTURES = MATRIX.fixtures;
const PRIMITIVES = { gateDecision, deployGate, coverageReport };

// findings deferred to P1/P2 — skipped with a visible reason (not fixed this round)
const DEFERRED = new Set(['RT-P-11', 'RT-P-12', 'RT-P-16', 'RT-P-20']);

function assertGate(out, e, id) {
  if (e.merge_allowed !== undefined) assert.equal(out.merge_allowed, e.merge_allowed, `${id} merge_allowed`);
  if (e.state !== undefined) assert.equal(out.state, e.state, `${id} state`);
  if (e.reason !== undefined) assert.equal(out.reason, e.reason, `${id} reason`);
  if (e.inescapable_merge !== undefined) assert.equal(out.inescapable_merge, e.inescapable_merge, `${id} inescapable_merge`);
  if (e.enforcement_state !== undefined) assert.equal(out.enforcement_state, e.enforcement_state, `${id} enforcement_state`);
}
function assertDeploy(out, e, id) {
  if (e.deploy_allowed !== undefined) assert.equal(out.deploy_allowed, e.deploy_allowed, `${id} deploy_allowed`);
  if (e.state !== undefined) assert.equal(out.state, e.state, `${id} state`);
  if (e.reason !== undefined) assert.equal(out.reason, e.reason, `${id} reason`);
  if (e.inescapable_deploy !== undefined) assert.equal(out.inescapable_deploy, e.inescapable_deploy, `${id} inescapable_deploy`);
}
function assertCoverage(out, e, id) {
  if (e.overall_coverage !== undefined) assert.equal(out.overall_coverage, e.overall_coverage, `${id} overall`);
  if (e.honest_claim_key !== undefined) assert.equal(out.honest_claim_key, e.honest_claim_key, `${id} claim key`);
  for (const inc of (e.residuals_include || [])) assert.ok(out.residuals.includes(inc), `${id} residuals include ${inc}`);
  if (e.residuals !== undefined) assert.deepEqual(out.residuals, e.residuals.slice().sort(), `${id} residuals exact`);
  if (e.flags) for (const [k, v] of Object.entries(e.flags)) assert.equal(out.flags[k], v, `${id} flag ${k}`);
  if (e.per_placement_strength) {
    const pm = Object.fromEntries(out.per_placement.map((p) => [p.placement, p.strength]));
    for (const [k, v] of Object.entries(e.per_placement_strength)) assert.equal(pm[k], v, `${id} strength ${k}`);
  }
}

describe('pentad red-team regression — 18 fixtures', () => {
  assert.equal(FIXTURES.length, 18, 'all 18 red-team fixtures present');

  for (const fx of FIXTURES) {
    const deferred = DEFERRED.has(fx.finding);
    const opts = deferred ? { skip: `${fx.finding} deferred to P1/P2 — outside this round's two-P0 scope` } : {};
    it(`${fx.id} [${fx.kind}/${fx.finding}]: ${fx.title.slice(0, 60)}`, opts, () => {
      const out = PRIMITIVES[fx.primitive](fx.input);
      const e = fx.expected || fx.expected_after_fix;
      if (fx.primitive === 'gateDecision') assertGate(out, e, fx.id);
      else if (fx.primitive === 'deployGate') assertDeploy(out, e, fx.id);
      else assertCoverage(out, e, fx.id);
    });
  }
});

// ── the two P0 fixes, called out explicitly ─────────────────────────────────────────────────────────
describe('pentad red-team — the two P0 fixes', () => {
  const fx = (id) => FIXTURES.find((f) => f.id === id);

  it('RT-P-01 (RTM-001): merge-gate rejects an ABSENT operation → operation_mismatch (was a leak)', () => {
    const out = gateDecision(fx('RTM-001').input);
    assert.equal(out.state, 'failure');
    assert.equal(out.reason, 'operation_mismatch');
    assert.equal(fx('RTM-001').input.receipt.operation, undefined, 'the receipt has no operation field');
  });

  it('RT-P-05 (RTM-005): normOp accepts case-variant "Merge" as a valid merge (casing ≠ attack)', () => {
    const out = gateDecision(fx('RTM-005').input);
    assert.equal(fx('RTM-005').input.receipt.operation, 'Merge');
    assert.equal(out.state, 'success');
    assert.equal(out.reason, 'allow_current_head');
    // but a genuinely different operation still fails
    const other = gateDecision({ ...fx('RTM-005').input, receipt: { ...fx('RTM-005').input.receipt, operation: 'deploy' } });
    assert.equal(other.reason, 'operation_mismatch', 'a real other op still fails closed');
  });

  it('RT-P-13 (RTM-013): inconsistent inescapable_merge:true + ADVISORY → WEAK + inescapable_flag_inconsistent, not FULLY', () => {
    const out = coverageReport(fx('RTM-013').input);
    assert.equal(out.overall_coverage, 'PARTIALLY_ENFORCED');
    assert.ok(out.residuals.includes('inescapable_flag_inconsistent'), 'names the inconsistency');
    assert.ok(out.residuals.includes('merge_gate_advisory'));
    assert.equal(out.flags.may_claim_full_tetrad, false);
    assert.equal(out.flags.may_claim_inescapable_merge, false, 'the flag no longer leaks true from an inconsistent claim');
    const merge = out.per_placement.find((p) => p.placement === 'merge');
    assert.equal(merge.strength, 'WEAK');
  });

  it('RT-P-13 does not fire on a CONSISTENT flag (inescapable + ENFORCING stays ENFORCING)', () => {
    const out = coverageReport({
      applicability: { runtime: false, merge: true, deploy: false, content: false },
      merge: { enforcement_state: 'ENFORCING', inescapable_merge: true },
    });
    const merge = out.per_placement.find((p) => p.placement === 'merge');
    assert.equal(merge.strength, 'ENFORCING');
    assert.ok(!out.residuals.includes('inescapable_flag_inconsistent'));
  });
});
