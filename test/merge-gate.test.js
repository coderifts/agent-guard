'use strict';

/**
 * repo-merge-gate (#7) acceptance — the PURE gate decision (repo-merge-gate-matrix v1.0, 16 rows).
 * The matrix is VENDORED into this test dir and loaded by a RELATIVE path (the ENOENT lesson — never
 * read from ~/grok-coderifts at test time). Ported assertions per row: merge_allowed, state, reason,
 * inescapable_merge, enforcement_state.
 *
 * Plus: determinism (same input → identical output), purity (no network I/O; input not mutated), and
 * the scope-honesty invariants (M6/M7 — inescapable_merge only in the fully-enforcing case).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { gateDecision } = require('../dist/cjs/merge-gate.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'repo-merge-gate-matrix.json'), 'utf8'));
const ROWS = MATRIX.rows;
const row = (id) => ROWS.find((r) => r.id === id);

// ── all 16 fixtures ────────────────────────────────────────────────────────────────────────────────
describe('gateDecision — 16-fixture matrix', () => {
  assert.equal(ROWS.length, 16, 'all 16 rows present');
  for (const r of ROWS) {
    it(`${r.id}: ${r.title.slice(0, 70)}`, () => {
      const got = gateDecision(r.input);
      const e = r.expected;
      assert.equal(got.merge_allowed, e.merge_allowed, `${r.id} merge_allowed`);
      assert.equal(got.state, e.state, `${r.id} state`);
      assert.equal(got.reason, e.reason, `${r.id} reason`);
      assert.equal(got.inescapable_merge, e.inescapable_merge, `${r.id} inescapable_merge`);
      if (e.enforcement_state !== undefined) {
        assert.equal(got.enforcement_state, e.enforcement_state, `${r.id} enforcement_state`);
      }
      // global validation rules from the matrix
      if (got.state === 'success') assert.notEqual(got.state, 'failure');
      assert.equal(typeof got.inescapable_merge, 'boolean');
    });
  }
});

// ── named checklist (task PART 4) ─────────────────────────────────────────────────────────────────
describe('gateDecision — named checklist', () => {
  it('MG-001: the ONLY inescapable_merge:true — ALLOW bound to current head + ENFORCING + no bypass', () => {
    const g = gateDecision(row('MG-001').input);
    assert.equal(g.state, 'success');
    assert.equal(g.reason, 'allow_current_head');
    assert.equal(g.inescapable_merge, true);
    // and it is the ONLY row that claims it
    const trueRows = ROWS.filter((r) => gateDecision(r.input).inescapable_merge).map((r) => r.id);
    assert.deepEqual(trueRows, ['MG-001'], 'exactly one inescapable_merge:true across the matrix');
  });

  it('MG-002: stale ALLOW for an OLD head → failure/stale_head — never greens a new head (M1)', () => {
    const g = gateDecision(row('MG-002').input);
    assert.equal(g.merge_allowed, false);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'stale_head');
    assert.notEqual(g.state, 'success');
  });

  it('MG-003: BLOCK receipt → decision_not_allow (never re-decides — reads the finished verdict)', () => {
    const g = gateDecision(row('MG-003').input);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'decision_not_allow');
  });

  it('MG-004/005: no receipt → fail-closed (failure), or pending when allowPending', () => {
    const noPend = gateDecision(row('MG-004').input);
    assert.equal(noPend.state, 'failure');
    assert.equal(noPend.reason, 'no_receipt');
    const pend = gateDecision(row('MG-005').input);
    assert.equal(pend.state, 'pending');
    assert.equal(pend.reason, 'no_receipt');
    assert.equal(pend.merge_allowed, false, 'pending is still not mergeable');
  });

  it('MG-006/007: expired / revoked → receipt_not_authorized (signature validity is NOT sufficient, M3)', () => {
    for (const id of ['MG-006', 'MG-007']) {
      const g = gateDecision(row(id).input);
      assert.equal(g.state, 'failure', `${id} failure`);
      assert.equal(g.reason, 'receipt_not_authorized', `${id} reason`);
      // both fixtures carry signature_valid:true — proving signature alone does not authorize
      assert.equal(row(id).input.receipt.signature_valid, true);
    }
  });

  it('MG-012..015: good receipt but non-ENFORCING / admin-bypass → success check yet inescapable_merge:false', () => {
    const cases = {
      'MG-012': { enforcement: 'ABSENT', residual: 'protection_not_configured' },
      'MG-013': { enforcement: 'ADVISORY', residual: 'protection_advisory_only' },
      'MG-014': { enforcement: 'ENFORCING', residual: 'admin_bypass_open' },
      'MG-015': { enforcement: 'UNKNOWN', residual: 'protection_not_configured' },
    };
    for (const [id, want] of Object.entries(cases)) {
      const g = gateDecision(row(id).input);
      assert.equal(g.state, 'success', `${id} check green for visibility`);
      assert.equal(g.merge_allowed, true, `${id} merge_allowed for the check`);
      assert.equal(g.inescapable_merge, false, `${id} claim honestly false`);
      assert.equal(g.enforcement_state, want.enforcement, `${id} enforcement_state`);
      assert.equal(g.residual, want.residual, `${id} residual named`);
    }
  });
});

// ── scope-honesty invariants (M6/M7) ────────────────────────────────────────────────────────────────
describe('gateDecision — scope honesty (M6/M7)', () => {
  it('M6: inescapable_merge:true ⇒ ENFORCING ∧ !admin_bypass ∧ state===success (every row)', () => {
    for (const r of ROWS) {
      const g = gateDecision(r.input);
      if (g.inescapable_merge === true) {
        assert.equal(g.enforcement_state, 'ENFORCING', `${r.id} M6 enforcement`);
        assert.equal(r.input.requiredContext.protection.admin_bypass_possible, false, `${r.id} M6 no bypass`);
        assert.equal(g.state, 'success', `${r.id} M6 success`);
        assert.equal(g.reason, 'allow_current_head', `${r.id} M7 reason`);
      }
    }
  });

  it('never claims inescapable_merge when protection is ADVISORY/ABSENT/UNKNOWN or admin-bypass is open', () => {
    const bad = ['ADVISORY', 'ABSENT', 'UNKNOWN'];
    for (const r of ROWS) {
      const p = r.input.requiredContext && r.input.requiredContext.protection;
      if (!p) continue;
      if (bad.includes(p.enforcement) || p.admin_bypass_possible === true) {
        assert.equal(gateDecision(r.input).inescapable_merge, false, `${r.id} must not claim inescapable_merge`);
      }
    }
  });
});

// ── determinism + purity (no I/O; input not mutated) ────────────────────────────────────────────────
describe('gateDecision — determinism + purity', () => {
  it('same input → byte-identical output (deterministic, M8)', () => {
    for (const r of ROWS) {
      assert.deepEqual(gateDecision(r.input), gateDecision(r.input), `${r.id} deterministic`);
    }
  });

  it('is synchronous and does not mutate its input', () => {
    for (const r of ROWS) {
      const snapshot = JSON.stringify(r.input);
      const out = gateDecision(r.input);
      assert.ok(!(out instanceof Promise), `${r.id} synchronous (pure, no async I/O)`);
      assert.equal(JSON.stringify(r.input), snapshot, `${r.id} input not mutated`);
    }
  });

  it('performs NO network I/O (a throwing fetch/http stub is never reached)', () => {
    const origFetch = global.fetch;
    const https = require('node:https');
    const http = require('node:http');
    const origHttps = https.request;
    const origHttp = http.request;
    const boom = () => { throw new Error('network I/O attempted — gateDecision must be pure'); };
    global.fetch = boom;
    https.request = boom;
    http.request = boom;
    try {
      for (const r of ROWS) gateDecision(r.input); // must not throw — no network touched
    } finally {
      global.fetch = origFetch;
      https.request = origHttps;
      http.request = origHttp;
    }
  });
});

// ── required_check_app_bound residual (honesty only — does not flip inescapable_merge) ───────────
// Measured on GitHub: required checks without app_id are name-spoofable; with app_id they are not.
// The gate cannot observe GitHub itself — the host supplies required_check_app_bound. Absence means
// unknown (not "not bound"). Residual names the gap; inescapable_merge stays true for existing callers.
describe('gateDecision — required_check_app_bound residual (claim not flipped)', () => {
  /** MG-001-shaped success input; protection overrides applied by the caller. */
  function enforcingNoBypassInput(protectionExtra) {
    const base = JSON.parse(JSON.stringify(row('MG-001').input));
    Object.assign(base.requiredContext.protection, protectionExtra || {});
    return base;
  }

  it('app-bound true + ENFORCING + no admin bypass → inescapable_merge true, NO app-binding residual', () => {
    const g = gateDecision(enforcingNoBypassInput({ required_check_app_bound: true }));
    assert.equal(g.state, 'success');
    assert.equal(g.inescapable_merge, true);
    assert.equal(g.residual, undefined, 'confirmed app-bound: no honesty residual');
  });

  it('field ABSENT + ENFORCING + no admin bypass → inescapable_merge still TRUE and residual required_check_app_binding_unknown (both halves — deliberate non-flip)', () => {
    // Do not pass required_check_app_bound — field absent (unknown ≠ not bound).
    const g = gateDecision(enforcingNoBypassInput({}));
    assert.equal(g.inescapable_merge, true, 'claim must NOT flip for callers who cannot supply the field');
    assert.equal(g.residual, 'required_check_app_binding_unknown', 'honesty residual: binding not observed');
  });

  it('field false + ENFORCING + no admin bypass → inescapable_merge still true, residual required_check_app_not_bound', () => {
    const g = gateDecision(enforcingNoBypassInput({ required_check_app_bound: false }));
    assert.equal(g.inescapable_merge, true, 'claim not flipped — residual only');
    assert.equal(g.residual, 'required_check_app_not_bound', 'host knows check is name-only / spoofable');
  });

  it('ADVISORY and admin-bypass-open keep existing residuals only (no app-binding residual conflict)', () => {
    const advisory = gateDecision(row('MG-013').input);
    assert.equal(advisory.inescapable_merge, false);
    assert.equal(advisory.residual, 'protection_advisory_only');
    assert.notEqual(advisory.residual, 'required_check_app_binding_unknown');
    assert.notEqual(advisory.residual, 'required_check_app_not_bound');

    const bypass = gateDecision(row('MG-014').input);
    assert.equal(bypass.inescapable_merge, false);
    assert.equal(bypass.residual, 'admin_bypass_open');
    assert.notEqual(bypass.residual, 'required_check_app_binding_unknown');
    assert.notEqual(bypass.residual, 'required_check_app_not_bound');

    // Even if the host also reports app-bound false under ADVISORY, the existing residual wins
    // (inescapable already false — do not replace with app-binding residual).
    const advPlus = JSON.parse(JSON.stringify(row('MG-013').input));
    advPlus.requiredContext.protection.required_check_app_bound = false;
    const g = gateDecision(advPlus);
    assert.equal(g.residual, 'protection_advisory_only', 'no duplicate/conflicting app residual under ADVISORY');
  });
});
