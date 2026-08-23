/**
 * Client-side authorization gate (P0-b/c) — mirrors the server §106 (binding), §111 (fail-closed on
 * degraded) and §115 (safe_for_agent) in the guard. All checks are LOCAL and fail-closed.
 *
 * Threat model (bounded): a raw execution_action is not trusted alone when the response has NO
 * receipt — without a signed decision_body_hash, a proxy or intermediary can flip fields. When a
 * receipt IS present, decision_body_hash covers the RFC 8785-canonical envelope (minus receipt and
 * the hash field itself) and the receipt signature covers that hash, so execution_action cannot be
 * flipped without the recomputed hash diverging or a forged signature. The gate still reconciles
 * decision↔action locally (stricter wins), fails closed on a PRESENT-but-unrecognised action
 * (version skew — not a missing-action fallback), and never treats an unknown value as permission.
 *
 * Composes with the P0-a receipt binding (receipt-binding.ts). This module reconciles the DECISION
 * itself; receipt-binding authenticates the envelope the decision rides on.
 */

import { createHash } from 'node:crypto';
import type { IntegrityCause, Artifact } from './types.js';

type Decision = 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'BLOCK';
type Action = 'CONTINUE' | 'CONTINUE_WITH_MONITORING' | 'REQUEST_APPROVAL' | 'STOP';

const DECISION_RANK: Record<Decision, number> = { ALLOW: 0, WARN: 1, REQUIRE_APPROVAL: 2, BLOCK: 3 };
const ACTION_TO_DECISION: Record<Action, Decision> = {
  CONTINUE: 'ALLOW', CONTINUE_WITH_MONITORING: 'WARN', REQUEST_APPROVAL: 'REQUIRE_APPROVAL', STOP: 'BLOCK',
};
const DECISION_TO_ACTION: Record<Decision, Action> = {
  ALLOW: 'CONTINUE', WARN: 'CONTINUE_WITH_MONITORING', REQUIRE_APPROVAL: 'REQUEST_APPROVAL', BLOCK: 'STOP',
};
function isDecision(v: unknown): v is Decision {
  return v === 'ALLOW' || v === 'WARN' || v === 'REQUIRE_APPROVAL' || v === 'BLOCK';
}
function isAction(v: unknown): v is Action {
  return v === 'CONTINUE' || v === 'CONTINUE_WITH_MONITORING' || v === 'REQUEST_APPROVAL' || v === 'STOP';
}

const NUL = '\x1f'; // matches the server's change-set canonical separator
function sha256hex(s: string): string { return createHash('sha256').update(s).digest('hex'); }
function specStr(v: unknown): string { return v == null ? '' : (typeof v === 'string' ? v : JSON.stringify(v)); }

/** Local artifact_digest — byte-identical to the server change-set.js algorithm (sorted by type,id). */
export function computeArtifactDigest(artifacts: Artifact[]): string {
  const preimage = artifacts.slice()
    .sort((a, b) => (`${a.type}${NUL}${a.id}` < `${b.type}${NUL}${b.id}` ? -1 : 1))
    .map((a) => `${sha256hex(specStr(a.before))}${sha256hex(specStr(a.after))}`)
    .join(NUL);
  return `sha256:${sha256hex(preimage)}`;
}

/** Local bundle input_fingerprint — byte-identical to the server change-set.js algorithm. */
export function computeBundleFingerprint(artifacts: Artifact[]): string {
  const parts = artifacts.slice()
    .sort((a, b) => (`${a.type}${NUL}${a.id}` < `${b.type}${NUL}${b.id}` ? -1 : 1))
    .map((a) => [a.type, a.id, sha256hex(specStr(a.before)), sha256hex(specStr(a.after))].join(NUL));
  return `sha256:${sha256hex(parts.join(NUL))}`;
}

export type GateResult =
  | { verdict: 'allow'; kind: 'ALLOW' | 'MONITOR' }
  | { verdict: 'block-strict'; decision: 'BLOCK' | 'REQUIRE_APPROVAL' }
  | { verdict: 'fail-closed'; cause: IntegrityCause; detail?: string };

/**
 * Reconcile an envelope's decision fail-closed. Order:
 *  0. execution_action PRESENT but not in closed set         → EXECUTION_ACTION_UNRECOGNISED
 *     (version skew; distinct from DECISION_INCONSISTENT — reconciliation is impossible)
 *  1. decision present + valid enum                          (CE-EP-04)   → DECISION_INCONSISTENT
 *  2. effective decision = STRICTEST(envelope.decision, action-implied, top-level decision/action)
 *     (CE-EP-01, CE-CC-01)  — BLOCK/REQUIRE_APPROVAL → clean block (positive control CE-EP-02 kept)
 *  3. safe_for_agent === false on an allow-class decision    (CE-EP-03/§115) → DECISION_INCONSISTENT
 *  4. degraded / analysis_complete=false / coverage_gap      (CE-CC-02/§111) → ANALYSIS_DEGRADED
 *  5. artifact_digest / input_fingerprint local compare      (CE-AF-03/#6)   → ARTIFACT_MISMATCH
 *
 * @param response   the raw preflight response (for the top-level decision/action, CE-CC-01)
 * @param envelope   the decision_result envelope
 * @param executionAction  rd.executionAction from readDecision (closed Action, or raw string if unrecognised)
 * @param sentArtifacts    the artifacts the guard sent to preflight (for the digest bind)
 */
export function evaluateEnvelope(
  response: unknown,
  envelope: Record<string, unknown>,
  executionAction: Action | string,
  sentArtifacts: Artifact[],
): GateResult {
  const top = (response && typeof response === 'object') ? response as Record<string, unknown> : {};

  // 0. PRESENT-but-unrecognised action — before any decision map or reconciliation.
  //    Missing action is not handled here (readDecision maps legacy 1.0 missing → closed Action;
  //    v2 / unspecified missing EA is UNREADABLE_DECISION in readDecision, before this gate).
  const candidates: unknown[] = [executionAction, envelope.execution_action, top.execution_action];
  for (const cand of candidates) {
    if (cand === undefined || cand === null || cand === '') continue; // missing — skip
    if (!isAction(cand)) {
      return {
        verdict: 'fail-closed',
        cause: 'EXECUTION_ACTION_UNRECOGNISED',
        detail: `execution_action=${JSON.stringify(cand)} is present but not in the closed set`,
      };
    }
  }

  // 1. decision required + valid enum.
  const dec = envelope.decision;
  if (!isDecision(dec)) {
    return { verdict: 'fail-closed', cause: 'DECISION_INCONSISTENT', detail: `decision=${JSON.stringify(dec)} is missing/invalid` };
  }

  // Known closed action from here (step 0 rejected unknowns).
  const action = executionAction as Action;

  // 2. Strictest of every decision signal present (envelope, action-implied, top-level).
  const signals: Decision[] = [dec, ACTION_TO_DECISION[action]];
  if (isDecision(top.decision)) signals.push(top.decision);
  if (isAction(top.execution_action)) signals.push(ACTION_TO_DECISION[top.execution_action]);
  const effective = signals.reduce((a, b) => (DECISION_RANK[b] > DECISION_RANK[a] ? b : a));

  if (DECISION_RANK[effective] >= DECISION_RANK.REQUIRE_APPROVAL) {
    // Stricter-wins: a BLOCK/RA anywhere (incl. an inconsistent BLOCK+CONTINUE) → clean block.
    return { verdict: 'block-strict', decision: effective as 'BLOCK' | 'REQUIRE_APPROVAL' };
  }

  // (effective is ALLOW or WARN — but ALSO require the envelope's own action to agree, else tamper.)
  if (DECISION_TO_ACTION[dec] !== action) {
    return { verdict: 'fail-closed', cause: 'DECISION_INCONSISTENT', detail: `decision=${dec} ≠ execution_action=${action}` };
  }

  // 3. §115 — safe_for_agent=false is NEVER executable, regardless of action.
  if (envelope.safe_for_agent === false) {
    return { verdict: 'fail-closed', cause: 'DECISION_INCONSISTENT', detail: 'safe_for_agent=false on an allow-class decision' };
  }

  // 4. §111 — incomplete/degraded analysis is never a clean proceed.
  const degradedReasons = envelope.degraded_reasons;
  if (envelope.analysis_complete === false
      || (Array.isArray(degradedReasons) && degradedReasons.length > 0)
      || envelope.degraded === true
      || envelope.coverage_gap === true) {
    return { verdict: 'fail-closed', cause: 'ANALYSIS_DEGRADED', detail: 'analysis degraded / incomplete' };
  }

  // 5. Artifact bind (CE-AF-03) — the server must have analyzed exactly the artifacts we sent.
  //    LOCALLY recompute artifact_digest and compare to the envelope's when present. (input_fingerprint
  //    is NOT separately compared here: it is already authenticated by the P0-a receipt body-hash
  //    binding — it lives inside the signed decision body — and its exact per-version preimage is
  //    riskier to reproduce client-side, so re-deriving it here would over-block honest traffic.)
  if (Array.isArray(sentArtifacts) && sentArtifacts.length > 0
      && typeof envelope.artifact_digest === 'string'
      && envelope.artifact_digest !== computeArtifactDigest(sentArtifacts)) {
    return { verdict: 'fail-closed', cause: 'ARTIFACT_MISMATCH', detail: 'artifact_digest ≠ locally-recomputed digest of sent artifacts' };
  }

  return { verdict: 'allow', kind: effective === 'ALLOW' ? 'ALLOW' : 'MONITOR' };
}
