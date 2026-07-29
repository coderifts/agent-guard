'use strict';

/**
 * enforcement-coverage report (#9) acceptance — the PURE tetrad aggregator (enforcement-coverage-matrix
 * v1.0, 14 rows). Matrix VENDORED into this test dir, loaded by a RELATIVE path (the ENOENT lesson).
 * Ported per row: overall_coverage, residuals (exact / include / exclude), honest_claim_key, flags,
 * per_placement_strength.
 *
 * Plus: determinism, purity (no network I/O; input not mutated), and the honesty invariants
 * (C1/C2/C8/C10 — FULLY only when every applicable placement is ENFORCING; the language never
 * over-claims).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { coverageReport } = require('../dist/cjs/coverage-report.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'enforcement-coverage-matrix.json'), 'utf8'));
const ROWS = MATRIX.rows;
const row = (id) => ROWS.find((r) => r.id === id);
const strengths = (r) => Object.fromEntries(coverageReport(r.input).per_placement.map((p) => [p.placement, p.strength]));

// ── all 14 fixtures ────────────────────────────────────────────────────────────────────────────────
describe('coverageReport — 14-fixture matrix', () => {
  assert.equal(ROWS.length, 14, 'all 14 rows present');
  for (const r of ROWS) {
    it(`${r.id}: ${r.title.slice(0, 64)}`, () => {
      const got = coverageReport(r.input);
      const e = r.expected;
      assert.equal(got.overall_coverage, e.overall_coverage, `${r.id} overall`);
      if (e.honest_claim_key) assert.equal(got.honest_claim_key, e.honest_claim_key, `${r.id} claim key`);
      if (e.residuals) assert.deepEqual(got.residuals, e.residuals.slice().sort(), `${r.id} residuals exact`);
      for (const inc of (e.residuals_include || [])) assert.ok(got.residuals.includes(inc), `${r.id} residuals include ${inc}`);
      for (const exc of (e.residuals_must_not_include || [])) assert.ok(!got.residuals.includes(exc), `${r.id} residuals exclude ${exc}`);
      if (e.flags) for (const [k, v] of Object.entries(e.flags)) assert.equal(got.flags[k], v, `${r.id} flag ${k}`);
      if (e.per_placement_strength) {
        const pm = strengths(r);
        for (const [k, v] of Object.entries(e.per_placement_strength)) assert.equal(pm[k], v, `${r.id} strength ${k}`);
      }
      // C8: may_claim_full_tetrad ⇔ overall FULLY_ENFORCED
      assert.equal(got.flags.may_claim_full_tetrad, got.overall_coverage === 'FULLY_ENFORCED', `${r.id} C8`);
    });
  }
});

// ── named checklist (task PART 4) ─────────────────────────────────────────────────────────────────
describe('coverageReport — named checklist', () => {
  it('EC-001: all applicable ENFORCING → FULLY_ENFORCED (the clean row, and the only clean full tetrad)', () => {
    const r = coverageReport(row('EC-001').input);
    assert.equal(r.overall_coverage, 'FULLY_ENFORCED');
    assert.deepEqual(r.residuals, []);
    assert.equal(r.flags.may_claim_full_tetrad, true);
  });

  it('EC-002 vs EC-003: deploy ABSENT is a residual only when APPLICABLE (the applicability core)', () => {
    const applicable = coverageReport(row('EC-002').input); // deploy applicable + ABSENT
    assert.equal(applicable.overall_coverage, 'PARTIALLY_ENFORCED');
    assert.ok(applicable.residuals.includes('deploy_path_ungated'));
    assert.equal(strengths(row('EC-002')).deploy, 'WEAK');

    const excluded = coverageReport(row('EC-003').input); // deploy NOT applicable + ABSENT
    assert.equal(excluded.overall_coverage, 'FULLY_ENFORCED');
    assert.ok(!excluded.residuals.includes('deploy_path_ungated'), 'EXCLUDED placement never contributes a residual (C4/C5)');
    assert.equal(strengths(row('EC-003')).deploy, 'EXCLUDED');
  });

  it('EC-004: merge ENFORCING but inescapable_merge false (admin bypass) → not FULLY, residual named', () => {
    const r = coverageReport(row('EC-004').input);
    assert.equal(r.overall_coverage, 'PARTIALLY_ENFORCED');
    assert.ok(r.residuals.includes('admin_bypass_open'));
    assert.equal(r.flags.may_claim_inescapable_merge, false);
    assert.equal(r.flags.may_claim_full_tetrad, false);
    assert.equal(strengths(row('EC-004')).merge, 'WEAK');
  });

  it('EC-005 / EC-012: content UNRESOLVED → CONTENT_BLOCKED (distinguished from ordinary partial)', () => {
    const withOthers = coverageReport(row('EC-005').input);
    assert.equal(withOthers.overall_coverage, 'CONTENT_BLOCKED');
    assert.ok(withOthers.residuals.includes('content_unresolved') && withOthers.residuals.includes('missing_ref_target'));
    const contentOnly = coverageReport(row('EC-012').input);
    assert.equal(contentOnly.overall_coverage, 'CONTENT_BLOCKED');
    assert.ok(contentOnly.residuals.includes('content_unresolved') && contentOnly.residuals.includes('ambiguous_ssot'));
  });

  it('EC-008 / EC-014: a missing OR UNKNOWN applicable placement → UNKNOWN (fail-closed observation, C3)', () => {
    const missing = coverageReport(row('EC-008').input); // merge:null
    assert.equal(missing.overall_coverage, 'UNKNOWN');
    assert.ok(missing.residuals.includes('merge_state_missing'));
    assert.equal(strengths(row('EC-008')).merge, 'UNKNOWN');
    const unobserved = coverageReport(row('EC-014').input); // deploy enforcement UNKNOWN
    assert.equal(unobserved.overall_coverage, 'UNKNOWN');
    assert.equal(strengths(row('EC-014')).deploy, 'UNKNOWN');
    assert.equal(unobserved.flags.may_claim_full_tetrad, false);
  });

  it('EC-009: EMPTY content (no contracts) is vacuously ENFORCING → can still be FULLY_ENFORCED', () => {
    const r = coverageReport(row('EC-009').input);
    assert.equal(r.overall_coverage, 'FULLY_ENFORCED');
    assert.equal(strengths(row('EC-009')).content, 'ENFORCING');
    assert.deepEqual(r.residuals, []);
  });

  it('EC-011: app installed but merge ABSENT while applicable → PARTIAL (installed ≠ enforced)', () => {
    const r = coverageReport(row('EC-011').input);
    assert.equal(r.overall_coverage, 'PARTIALLY_ENFORCED');
    assert.ok(r.residuals.includes('merge_gate_not_configured'));
    assert.equal(r.flags.may_claim_inescapable_runtime, true);
    assert.equal(r.flags.may_claim_inescapable_merge, false);
  });

  it('EC-013: one WEAK applicable placement caps the overall (runtime BYPASSED among ENFORCING)', () => {
    const r = coverageReport(row('EC-013').input);
    assert.equal(r.overall_coverage, 'PARTIALLY_ENFORCED');
    assert.ok(r.residuals.includes('runtime_bypassed'));
    assert.equal(r.flags.may_claim_inescapable_merge, true);
    assert.equal(r.flags.may_claim_inescapable_deploy, true);
    assert.equal(r.flags.may_claim_inescapable_runtime, false);
    assert.equal(r.flags.may_claim_full_tetrad, false);
  });
});

// ── honesty invariants (C1/C2/C4/C10) ───────────────────────────────────────────────────────────────
describe('coverageReport — honesty invariants', () => {
  it('C1/C2: FULLY_ENFORCED ⇔ every applicable placement strength is ENFORCING', () => {
    for (const r of ROWS) {
      const rep = coverageReport(r.input);
      const applicableRows = rep.per_placement.filter((p) => p.applicable);
      const allEnf = applicableRows.length > 0 && applicableRows.every((p) => p.strength === 'ENFORCING');
      assert.equal(rep.overall_coverage === 'FULLY_ENFORCED', allEnf, `${r.id} C1/C2`);
    }
  });

  it('C4: a non-applicable (EXCLUDED) placement never contributes a residual', () => {
    for (const r of ROWS) {
      const rep = coverageReport(r.input);
      const excludedResiduals = rep.per_placement.filter((p) => !p.applicable).flatMap((p) => p.residuals);
      assert.deepEqual(excludedResiduals, [], `${r.id} EXCLUDED has no residuals`);
    }
  });

  it('C10: honest_claim_language never says "fully inescapable" unless the key is claim_fully_enforced; FULLY never claims "nothing can bypass"', () => {
    for (const r of ROWS) {
      const rep = coverageReport(r.input);
      if (rep.honest_claim_key !== 'claim_fully_enforced') {
        assert.doesNotMatch(rep.honest_claim_language, /fully inescapable/i, `${r.id} no over-claim`);
      } else {
        assert.doesNotMatch(rep.honest_claim_language, /nothing can (ever )?bypass/i, `${r.id} FULLY still admits residuals`);
        assert.match(rep.honest_claim_language, /may still exist/i, `${r.id} FULLY names the infra residual`);
      }
    }
  });
});

// ── determinism + purity ──────────────────────────────────────────────────────────────────────────
describe('coverageReport — determinism + purity', () => {
  it('same input → byte-identical output (deterministic, residuals sorted, C9)', () => {
    for (const r of ROWS) assert.deepEqual(coverageReport(r.input), coverageReport(r.input), `${r.id} deterministic`);
  });

  it('is synchronous and does not mutate its input', () => {
    for (const r of ROWS) {
      const snapshot = JSON.stringify(r.input);
      const out = coverageReport(r.input);
      assert.ok(!(out instanceof Promise), `${r.id} synchronous (pure)`);
      assert.equal(JSON.stringify(r.input), snapshot, `${r.id} input not mutated`);
    }
  });

  it('performs NO network I/O (a throwing fetch/http stub is never reached — does not re-run any primitive)', () => {
    const origFetch = global.fetch;
    const https = require('node:https');
    const http = require('node:http');
    const origHttps = https.request;
    const origHttp = http.request;
    const boom = () => { throw new Error('network I/O attempted — coverageReport must be pure'); };
    global.fetch = boom;
    https.request = boom;
    http.request = boom;
    try {
      for (const r of ROWS) coverageReport(r.input);
    } finally {
      global.fetch = origFetch;
      https.request = origHttps;
      http.request = origHttp;
    }
  });
});
