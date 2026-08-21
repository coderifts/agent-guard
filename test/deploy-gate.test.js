'use strict';

/**
 * deploy-gate (#8) acceptance — the PURE deploy authorization decision (deploy-gate-matrix v1.0, 16
 * rows). The matrix is VENDORED into this test dir and loaded by a RELATIVE path (the ENOENT lesson).
 * Ported per row: deploy_allowed, state, reason, inescapable_deploy, enforcement_state.
 *
 * Plus: determinism, purity (no network I/O; input not mutated), and the scope-honesty invariants
 * (D8/D10 — inescapable_deploy only in the fully-enforcing case; merge success ≠ deploy success).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { deployGate } = require('../dist/cjs/deploy-gate.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'deploy-gate-matrix.json'), 'utf8'));
const ROWS = MATRIX.rows;
const row = (id) => ROWS.find((r) => r.id === id);

// ── all 16 fixtures ────────────────────────────────────────────────────────────────────────────────
describe('deployGate — 16-fixture matrix', () => {
  assert.equal(ROWS.length, 16, 'all 16 rows present');
  for (const r of ROWS) {
    it(`${r.id}: ${r.title.slice(0, 68)}`, () => {
      const got = deployGate(r.input);
      const e = r.expected;
      assert.equal(got.deploy_allowed, e.deploy_allowed, `${r.id} deploy_allowed`);
      assert.equal(got.state, e.state, `${r.id} state`);
      assert.equal(got.reason, e.reason, `${r.id} reason`);
      assert.equal(got.inescapable_deploy, e.inescapable_deploy, `${r.id} inescapable_deploy`);
      if (e.enforcement_state !== undefined) {
        assert.equal(got.enforcement_state, e.enforcement_state, `${r.id} enforcement_state`);
      }
      assert.equal(typeof got.inescapable_deploy, 'boolean');
    });
  }
});

// ── named checklist (task PART 4) ─────────────────────────────────────────────────────────────────
describe('deployGate — named checklist', () => {
  it('DG-001: the ONLY inescapable_deploy:true — ENFORCING ∧ ¬bypass ∧ fingerprint rebound', () => {
    assert.equal(deployGate(row('DG-001').input).inescapable_deploy, true);
    const trueRows = ROWS.filter((r) => deployGate(r.input).inescapable_deploy).map((r) => r.id);
    assert.deepEqual(trueRows, ['DG-001'], 'exactly one inescapable_deploy:true across the matrix');
    // DG-016 still succeeds via case-normalized env, but cannot claim inescapable without re-bind
    assert.equal(row('DG-016').input.deployTarget.environment, 'Production');
    assert.equal(row('DG-016').input.receipt.bound_environment, 'production');
    assert.equal(deployGate(row('DG-016').input).deploy_allowed, true);
    assert.equal(deployGate(row('DG-016').input).inescapable_deploy, false);
  });

  it('DG-002: a MERGE receipt cannot deploy → operation_mismatch (T7 core, never re-decides)', () => {
    const g = deployGate(row('DG-002').input);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'operation_mismatch');
    assert.equal(row('DG-002').input.receipt.operation, 'merge');
  });

  it('DG-003: a STAGING ALLOW never authorizes PRODUCTION → env_mismatch', () => {
    const g = deployGate(row('DG-003').input);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'env_mismatch');
  });

  it('DG-004: an OLD artifact ALLOW never deploys a newer one → stale_artifact', () => {
    const g = deployGate(row('DG-004').input);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'stale_artifact');
  });

  it('DG-005/015: BLOCK / REQUIRE_APPROVAL → decision_not_allow', () => {
    assert.equal(deployGate(row('DG-005').input).reason, 'decision_not_allow');
    assert.equal(deployGate(row('DG-015').input).reason, 'decision_not_allow');
  });

  it('DG-006/007: no receipt → fail-closed (failure), or pending when allowPending', () => {
    const f = deployGate(row('DG-006').input);
    assert.equal(f.state, 'failure');
    assert.equal(f.reason, 'no_receipt');
    const p = deployGate(row('DG-007').input);
    assert.equal(p.state, 'pending');
    assert.equal(p.reason, 'no_receipt');
    assert.equal(p.deploy_allowed, false, 'pending is still not deployable');
  });

  it('DG-010: a MISSING operation also fails closed → operation_mismatch (stricter than merge)', () => {
    const g = deployGate(row('DG-010').input);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'operation_mismatch');
    assert.equal(row('DG-010').input.receipt.operation, undefined, 'fixture has no operation field');
  });

  it('DG-012..014: good receipt but non-ENFORCING / bypass → success check yet inescapable_deploy:false', () => {
    const cases = {
      'DG-012': { enforcement: 'ABSENT', residual: 'enforcement_not_configured' },
      'DG-013': { enforcement: 'ADVISORY', residual: 'enforcement_not_configured' },
      'DG-014': { enforcement: 'ENFORCING', residual: 'bypass_open' },
    };
    for (const [id, want] of Object.entries(cases)) {
      const g = deployGate(row(id).input);
      assert.equal(g.state, 'success', `${id} check green for visibility`);
      assert.equal(g.deploy_allowed, true, `${id} deploy_allowed for the check`);
      assert.equal(g.inescapable_deploy, false, `${id} claim honestly false`);
      assert.equal(g.enforcement_state, want.enforcement, `${id} enforcement_state`);
      assert.equal(g.residual, want.residual, `${id} residual named`);
    }
  });
});

// ── scope-honesty invariants (D8/D10) ────────────────────────────────────────────────────────────
describe('deployGate — scope honesty (D8/D10)', () => {
  it('D8: inescapable_deploy:true ⇒ ENFORCING ∧ !bypass ∧ fingerprint rebound ∧ success (every row)', () => {
    for (const r of ROWS) {
      const g = deployGate(r.input);
      if (g.inescapable_deploy === true) {
        assert.equal(g.enforcement_state, 'ENFORCING', `${r.id} D8 enforcement`);
        assert.equal(r.input.requiredContext.enforcement.bypass_possible, false, `${r.id} D8 no bypass`);
        const fp = r.input.requiredContext && r.input.requiredContext.expected_fingerprint;
        assert.ok(fp != null && String(fp).length > 0, `${r.id} D8 fingerprint rebound`);
        assert.equal(g.state, 'success', `${r.id} D8 success`);
        assert.equal(g.reason, 'allow_current_deploy', `${r.id} D8 reason`);
      }
    }
  });

  it('D10: merge success does not imply deploy success — a merge receipt is operation_mismatch', () => {
    // a receipt that would green the merge gate (operation=merge) must NOT deploy
    const g = deployGate(row('DG-002').input);
    assert.notEqual(g.state, 'success');
    assert.equal(g.reason, 'operation_mismatch');
  });

  it('never claims inescapable_deploy when enforcement is ADVISORY/ABSENT/UNKNOWN or bypass open', () => {
    const weak = ['ADVISORY', 'ABSENT', 'UNKNOWN'];
    for (const r of ROWS) {
      const enf = r.input.requiredContext && r.input.requiredContext.enforcement;
      if (!enf) continue;
      if (weak.includes(enf.enforcement) || enf.bypass_possible === true) {
        assert.equal(deployGate(r.input).inescapable_deploy, false, `${r.id} must not claim inescapable_deploy`);
      }
    }
  });
});

// ── determinism + purity ──────────────────────────────────────────────────────────────────────────
describe('deployGate — determinism + purity', () => {
  it('same input → byte-identical output (deterministic, D9)', () => {
    for (const r of ROWS) {
      assert.deepEqual(deployGate(r.input), deployGate(r.input), `${r.id} deterministic`);
    }
  });

  it('is synchronous and does not mutate its input', () => {
    for (const r of ROWS) {
      const snapshot = JSON.stringify(r.input);
      const out = deployGate(r.input);
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
    const boom = () => { throw new Error('network I/O attempted — deployGate must be pure'); };
    global.fetch = boom;
    https.request = boom;
    http.request = boom;
    try {
      for (const r of ROWS) deployGate(r.input); // must not throw — no network touched
    } finally {
      global.fetch = origFetch;
      https.request = origHttps;
      http.request = origHttp;
    }
  });
});

// ── change_set_not_rebound residual (fail-closed inescapable_deploy) ───────────────────────────
// Optional expected_fingerprint: mismatch still hard-fails; absence greens deploy_allowed
// with residual change_set_not_rebound and inescapable_deploy false.
describe('deployGate — change_set_not_rebound residual (inescapable fail-closed)', () => {
  function cleanEnforcingInput() {
    return JSON.parse(JSON.stringify(row('DG-001').input));
  }

  it('expected_fingerprint supplied and matching → success, no change_set residual, claim unchanged', () => {
    const input = cleanEnforcingInput();
    assert.equal(
      input.requiredContext.expected_fingerprint,
      input.receipt.verdict_fingerprint,
      'fixture preconditions: matching expected_fingerprint',
    );
    const g = deployGate(input);
    assert.equal(g.state, 'success');
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.reason, 'allow_current_deploy');
    assert.equal(g.inescapable_deploy, true);
    assert.notEqual(g.residual, 'change_set_not_rebound');
    assert.notEqual(g.reason, 'fingerprint_mismatch');
    assert.equal(g.residual, undefined, 're-bind present and matched: no change-set residual');
  });

  it('expected_fingerprint supplied and mismatched → fingerprint_mismatch failure (existing path)', () => {
    const input = cleanEnforcingInput();
    input.requiredContext.expected_fingerprint = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const g = deployGate(input);
    assert.equal(g.deploy_allowed, false);
    assert.equal(g.state, 'failure');
    assert.equal(g.reason, 'fingerprint_mismatch');
    assert.equal(g.inescapable_deploy, false);
    assert.equal(g.residual, undefined, 'hard failure path — not a residual');
  });

  it('expected_fingerprint absent → residual change_set_not_rebound; deploy_allowed true, inescapable_deploy false', () => {
    const input = cleanEnforcingInput();
    delete input.requiredContext.expected_fingerprint;
    const g = deployGate(input);
    assert.equal(g.state, 'success', 'visibility: still green');
    assert.equal(g.deploy_allowed, true, 'deploy_allowed unchanged');
    assert.equal(g.reason, 'allow_current_deploy');
    assert.equal(g.inescapable_deploy, false, 'fail-closed: cannot claim inescapable_deploy without re-bind');
    assert.equal(g.residual, 'change_set_not_rebound', 'honesty: receipt not re-bound to current change set');
    assert.deepEqual(g.residuals, ['change_set_not_rebound']);
    assert.notEqual(g.reason, 'fingerprint_mismatch', 'must not confusable with hard mismatch failure');
  });
});

// ── residuals[] array (additive; singular residual priority preserved) ───────────────────────────
describe('deployGate — residuals[] reports all co-occurring honesty residuals', () => {
  it('clean ENFORCING + fingerprint re-bind → residuals=[] and residual undefined', () => {
    const input = JSON.parse(JSON.stringify(row('DG-001').input));
    const g = deployGate(input);
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.inescapable_deploy, true);
    assert.equal(g.residual, undefined);
    assert.deepEqual(g.residuals, []);
  });

  it('single residual (bypass_open) → residuals=[same], singular byte-identical', () => {
    const input = JSON.parse(JSON.stringify(row('DG-014').input));
    // DG-014 has no verdict_fingerprint — supply a matching re-bind pair so only the
    // enforcement residual applies (change_set_not_rebound requires expected_fingerprint absent).
    const fp =
      input.receipt.verdict_fingerprint ??
      'sha256:1111111111111111111111111111111111111111111111111111111111111111';
    input.receipt.verdict_fingerprint = fp;
    input.requiredContext.expected_fingerprint = fp;
    const g = deployGate(input);
    assert.equal(g.residual, 'bypass_open');
    assert.deepEqual(g.residuals, ['bypass_open']);
  });

  it('co-occurrence: bypass_open + no expected_fingerprint → both; singular = bypass first', () => {
    const input = JSON.parse(JSON.stringify(row('DG-014').input));
    delete input.requiredContext.expected_fingerprint;
    const g = deployGate(input);
    assert.equal(g.deploy_allowed, true);
    assert.equal(g.residual, 'bypass_open', 'singular keeps measured priority (enforcement before change_set)');
    assert.deepEqual(
      g.residuals,
      ['bypass_open', 'change_set_not_rebound'],
      'both co-occurring residuals reported (previously change_set was dropped)',
    );
  });

  it('co-occurrence: enforcement_not_configured + no fingerprint → both residuals', () => {
    const input = JSON.parse(JSON.stringify(row('DG-013').input)); // ADVISORY
    delete input.requiredContext.expected_fingerprint;
    const g = deployGate(input);
    assert.equal(g.residual, 'enforcement_not_configured');
    assert.deepEqual(g.residuals, ['enforcement_not_configured', 'change_set_not_rebound']);
  });
});
