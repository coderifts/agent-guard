'use strict';

/**
 * bindDeploy — pure deploy-time composition over deployGate.
 * No I/O. Environment is always host_asserted. pipeline_action is always not_observed.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { bindDeploy, deployGate, asVerifiedDeployReceiptView } = require('../dist/cjs/index.js');

const ART_A = 'sha256:' + 'a'.repeat(64);
const ART_B = 'sha256:' + 'b'.repeat(64);

function baseReceipt(over = {}) {
  return asVerifiedDeployReceiptView({
    currently_authorized: true,
    decision: 'ALLOW',
    execution_action: 'CONTINUE',
    operation: 'deploy',
    bound_environment: 'production',
    bound_artifact_id: ART_A,
    verdict_fingerprint: 'sha256:' + '1'.repeat(64),
    body_hash: 'sha256:' + '2'.repeat(64),
    target_id: 'svc:payments-api',
    signature_valid: true,
    ...over,
  });
}

function enforcing() {
  return { enforcement: 'ENFORCING', bypass_possible: false, required_step_name: 'CodeRifts / deploy-gate' };
}

describe('bindDeploy — three deploy binds at call time', () => {
  it('merge receipt refused for deploy (operation_mismatch)', () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt: baseReceipt({ operation: 'merge' }),
      pipeline_enforcement: enforcing(),
    });
    assert.equal(r.decision_allows_deploy, false);
    assert.equal(r.reason, 'operation_mismatch');
    assert.equal(r.gate.reason, 'operation_mismatch');
    assert.equal(r.deploy_check_status, 'failure');
    assert.equal(r.inescapable_deploy, false);
    assert.equal(r.must_re_preflight, true);
  });

  it('staging receipt refused for production (env_mismatch)', () => {
    const r = bindDeploy({
      environment: { name: 'production', provenance: 'host_asserted' },
      artifact_id: ART_A,
      receipt: baseReceipt({ bound_environment: 'staging' }),
      pipeline_enforcement: enforcing(),
    });
    assert.equal(r.decision_allows_deploy, false);
    assert.equal(r.reason, 'env_mismatch');
    assert.equal(r.gate.detail.environment, 'production');
    assert.equal(r.gate.detail.bound_environment, 'staging');
  });

  it("older artifact's receipt refused for a newer one (stale_artifact)", () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_B, // deploying newer
      receipt: baseReceipt({ bound_artifact_id: ART_A }), // receipt for older
      pipeline_enforcement: enforcing(),
    });
    assert.equal(r.decision_allows_deploy, false);
    assert.equal(r.reason, 'stale_artifact');
  });
});

describe('bindDeploy — environment claim is asserted, never verified', () => {
  it('string environment is wrapped as host_asserted', () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt: baseReceipt(),
      pipeline_enforcement: enforcing(),
    });
    assert.deepEqual(r.environment, { name: 'production', provenance: 'host_asserted' });
    assert.notEqual(r.environment.provenance, 'verified');
  });

  it('host cannot force provenance verified — output stays host_asserted', () => {
    const r = bindDeploy({
      environment: { name: 'production', provenance: 'verified' }, // hostile / mistaken
      artifact_id: ART_A,
      receipt: baseReceipt(),
      pipeline_enforcement: enforcing(),
    });
    assert.equal(r.environment.provenance, 'host_asserted');
    assert.equal(r.environment.name, 'production');
  });

  it('successful decision still labels environment host_asserted (not verified)', () => {
    const r = bindDeploy({
      environment: { name: 'production', provenance: 'host_asserted' },
      artifact_id: ART_A,
      receipt: baseReceipt(),
      pipeline_enforcement: enforcing(),
      expected_fingerprint: baseReceipt().verdict_fingerprint,
      expected_body_hash: baseReceipt().body_hash,
      service: 'payments-api',
    });
    assert.equal(r.decision_allows_deploy, true);
    assert.equal(r.gate.reason, 'allow_current_deploy');
    assert.equal(r.environment.provenance, 'host_asserted');
  });
});

describe('bindDeploy — decision vs pipeline action', () => {
  it('deny: decision_allows_deploy false but pipeline_action is not_observed (we did not block)', () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt: baseReceipt({ operation: 'merge' }),
      pipeline_enforcement: enforcing(),
    });
    assert.equal(r.decision_allows_deploy, false);
    assert.equal(r.pipeline_action, 'not_observed');
    // Distinguishable: gate says no; we did not claim the pipeline acted.
    assert.notEqual(r.pipeline_action, 'blocked');
    assert.notEqual(r.pipeline_action, 'allowed');
  });

  it('allow: decision_allows_deploy true still pipeline_action not_observed (we did not deploy)', () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt: baseReceipt(),
      pipeline_enforcement: enforcing(),
      expected_fingerprint: baseReceipt().verdict_fingerprint,
      expected_body_hash: baseReceipt().body_hash,
      service: 'payments-api',
    });
    assert.equal(r.decision_allows_deploy, true);
    assert.equal(r.pipeline_action, 'not_observed');
    assert.equal(r.inescapable_deploy, true); // from gate only under ENFORCING∧¬bypass
  });

  it('advisory enforcement: green decision does not claim inescapable_deploy', () => {
    const r = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt: baseReceipt(),
      pipeline_enforcement: { enforcement: 'ADVISORY', bypass_possible: true },
      expected_fingerprint: baseReceipt().verdict_fingerprint,
      expected_body_hash: baseReceipt().body_hash,
      service: 'payments-api',
    });
    assert.equal(r.decision_allows_deploy, true);
    assert.equal(r.inescapable_deploy, false);
    assert.equal(r.pipeline_action, 'not_observed');
  });
});

describe('bindDeploy — composes deployGate without redefining binds', () => {
  it('same inputs as deployGate yield the same gate decision fields', () => {
    const receipt = baseReceipt({ operation: 'merge' });
    const direct = deployGate({
      deployTarget: { environment: 'production', artifact_id: ART_A },
      receipt,
      requiredContext: { operation: 'deploy', enforcement: enforcing() },
    });
    const bound = bindDeploy({
      environment: 'production',
      artifact_id: ART_A,
      receipt,
      pipeline_enforcement: enforcing(),
    });
    assert.equal(bound.gate.reason, direct.reason);
    assert.equal(bound.gate.deploy_allowed, direct.deploy_allowed);
    assert.equal(bound.gate.inescapable_deploy, direct.inescapable_deploy);
  });
});
