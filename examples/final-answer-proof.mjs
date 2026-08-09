/**
 * Final-answer proof block example (ID645).
 *
 * NOT shipped in the npm tarball. Offline demo of renderFinalAnswerProof +
 * attachProofToAgentResponse for:
 *   (1) a verified / enforced call
 *   (2) a skipped / currently_authorized:null call
 * so the visible difference is obvious — and limits always appear.
 *
 *   npm run build && node examples/final-answer-proof.mjs
 *   node --test test/final-answer-proof.test.js
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

const {
  renderFinalAnswerProof,
  attachProofToAgentResponse,
  EXECUTION_PROOF_SPEC,
} = require(path.join(distCjs, 'index.js'));

if (typeof renderFinalAnswerProof !== 'function') {
  throw new Error('examples/final-answer-proof: build dist first (npm run build)');
}

const LIMITS = Object.freeze({
  does_not_claim_change_safe: true,
  does_not_claim_host_cannot_bypass: true,
  does_not_claim_absent_field_is_compliance: true,
  change_fp_is_what_was_checked_not_what_executed: true,
  calls_outside_guarded_path_invisible: true,
  execution_result_hash_is_not_artifact_match_proof: true,
});

/** Fixture: receipt verified, call enforced on the guarded path. */
const verifiedProof = Object.freeze({
  proof_spec: EXECUTION_PROOF_SPEC,
  preflighted: true,
  decision_id: 'dec_demo_verified',
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
    value: 'ab'.repeat(32),
  }),
  limits: LIMITS,
});

/** Fixture: no receipt path — currently_authorized null (SKIPPED), not a soft pass. */
const skippedProof = Object.freeze({
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
    reason: 'result_not_byte_stable',
  }),
  limits: LIMITS,
});

const verifiedText = renderFinalAnswerProof(verifiedProof);
const skippedText = renderFinalAnswerProof(skippedProof);

const agentAnswerVerified = attachProofToAgentResponse(
  'I applied the OpenAPI edit as authorized.',
  verifiedProof,
);
const agentAnswerSkipped = attachProofToAgentResponse(
  'I read the file (readonly path; no receipt).',
  skippedProof,
);

function main() {
  console.log('========== VERIFIED / ENFORCED (currently_authorized: true) ==========');
  console.log(verifiedText);
  console.log('========== SKIPPED (currently_authorized: null — NOT a pass) ==========');
  console.log(skippedText);
  console.log('========== attachProofToAgentResponse — verified ==========');
  console.log(agentAnswerVerified);
  console.log('========== attachProofToAgentResponse — skipped ==========');
  console.log(agentAnswerSkipped);
  console.log('\nOK — verified and skipped blocks are visibly different; limits always present.');
}

export {
  verifiedProof,
  skippedProof,
  verifiedText,
  skippedText,
  agentAnswerVerified,
  agentAnswerSkipped,
  main,
};

if (import.meta.url === pathToFileURLIfMain()) {
  main();
}

function pathToFileURLIfMain() {
  const { pathToFileURL } = require('node:url');
  return process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
}
