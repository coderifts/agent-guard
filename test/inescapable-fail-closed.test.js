'use strict';

/**
 * P0 fail-closed inescapable_* (RT-P-20 / app-binding / deploy residual).
 *
 * The check may still be success (visibility) but inescapable_* MUST NOT be true when
 * proof is incomplete: missing fingerprint, required check not App-bound, or deploy
 * change-set not rebound. Residual names the gap; the claim is fail-closed false.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { gateDecision } = require('../dist/cjs/merge-gate.js');
const { deployGate } = require('../dist/cjs/deploy-gate.js');

const MG = JSON.parse(fs.readFileSync(path.join(__dirname, 'repo-merge-gate-matrix.json'), 'utf8'));
const DG = JSON.parse(fs.readFileSync(path.join(__dirname, 'deploy-gate-matrix.json'), 'utf8'));
const clone = (id, matrix) => JSON.parse(JSON.stringify(matrix.rows.find((r) => r.id === id).input));

describe('P0 fail-closed inescapable_* (missing proof → false, not residual-true)', () => {
  it('P0 RT-P-20: missing expected_fingerprint → inescapable_merge false (merge_allowed may stay true)', () => {
    const input = clone('MG-001', MG);
    input.requiredContext.protection.required_check_app_bound = true;
    delete input.requiredContext.expected_fingerprint;
    const g = gateDecision(input);
    assert.equal(g.merge_allowed, true, 'visibility: still allow_current_head');
    assert.equal(g.state, 'success');
    assert.equal(g.inescapable_merge, false, 'cannot claim inescapable without fingerprint re-bind');
    assert.ok(g.residuals.includes('change_set_not_rebound'));
  });

  it('P0 app-binding: required_check_app_bound false → inescapable_merge false', () => {
    const input = clone('MG-001', MG);
    input.requiredContext.protection.required_check_app_bound = false;
    const g = gateDecision(input);
    assert.equal(g.merge_allowed, true);
    assert.equal(g.state, 'success');
    assert.equal(g.inescapable_merge, false, 'name-only required check is spoofable — not inescapable');
    assert.ok(g.residuals.includes('required_check_app_not_bound'));
    assert.notEqual(g.residual, 'admin_bypass_open', 'must not mis-name the gap as admin bypass');
  });

  it('P0 app-binding unknown (field absent) → inescapable_merge false', () => {
    const input = clone('MG-001', MG);
    delete input.requiredContext.protection.required_check_app_bound;
    const g = gateDecision(input);
    assert.equal(g.inescapable_merge, false, 'unknown app-binding cannot assert inescapable');
    assert.ok(g.residuals.includes('required_check_app_binding_unknown'));
  });

  it('P0 deploy residual: missing expected_fingerprint → inescapable_deploy false', () => {
    const input = clone('DG-001', DG);
    delete input.requiredContext.expected_fingerprint;
    const g = deployGate(input);
    assert.equal(g.deploy_allowed, true, 'visibility: still allow_current_deploy');
    assert.equal(g.state, 'success');
    assert.equal(g.inescapable_deploy, false, 'cannot claim inescapable_deploy with unbound change set');
    assert.ok(g.residuals.includes('change_set_not_rebound'));
    assert.notEqual(g.residual, 'bypass_open', 'must not mis-name fingerprint gap as bypass');
  });
});
