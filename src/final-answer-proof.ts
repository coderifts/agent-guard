/**
 * Human-readable final-answer proof block (ID645) — render layer over GuardExecutionProof.
 *
 * Does NOT assemble or re-decide protection. It FAITHFULLY formats a machine
 * GuardExecutionProof (from buildExecutionProof) so an agent can embed it in a final
 * answer without overclaiming.
 *
 * Honesty rules:
 *  - currently_authorized:null → "NOT EVALUATED (SKIPPED)" — never a soft pass
 *  - currently_authorized:false → "NOT AUTHORIZED" — never "protected/verified"
 *  - currently_authorized:true → "AUTHORIZED" only when receipt.verified; still surfaces limits
 *  - limits block always appears (operative non-claims) — there is no opt-out; format:'plain'
 *    compacts the markup and still renders every limit
 *
 * Does not modify execution-proof.ts or the proof shape.
 */

import type { GuardExecutionProof, ExecutionResultHash } from './execution-proof.js';
import { EXECUTION_PROOF_SPEC } from './execution-proof.js';
import { formatMonitoringDeliveryLine } from './monitoring-delivery.js';

export type FinalAnswerProofFormat = 'markdown' | 'plain';

export type RenderFinalAnswerProofOptions = {
  /**
   * Output format. Default 'markdown'.
   * plain = no #/* markup (still line-oriented, limits as bullet-like lines with "- ").
   */
  format?: FinalAnswerProofFormat;
  /**
   * Optional heading override. Default: "CodeRifts execution proof".
   */
  title?: string;
};

export type AttachProofToAgentResponseOptions = RenderFinalAnswerProofOptions & {
  /**
   * How to embed the rendered block.
   *  - 'append_text' (default): append a string section to a string response, or set
   *    `final_answer_proof` + `final_answer_proof_text` on object responses
   *  - 'field_only': never mutate text; only attach structured fields on objects
   *    (string responses become `{ text, final_answer_proof, final_answer_proof_text }`)
   */
  mode?: 'append_text' | 'field_only';
  /**
   * Separator before the appended block when mode is append_text and response is a string.
   * Default: "\n\n---\n\n"
   */
  separator?: string;
};

/** Coarse human status derived only from proof fields (never invents protection). */
export type FinalAnswerProofBanner =
  | 'ENFORCED'
  | 'AUTHORIZED'
  | 'NOT_AUTHORIZED'
  | 'NOT_EVALUATED_SKIPPED'
  | 'PREFLIGHTED_NOT_AUTHORIZED'
  | 'NO_PREFLIGHT';

/**
 * Map proof fields → a single banner label that is visibly different for
 * authorized / not-authorized / skipped / no-preflight.
 */
export function deriveProofBanner(proof: GuardExecutionProof): FinalAnswerProofBanner {
  if (!proof || typeof proof !== 'object') return 'NO_PREFLIGHT';
  // null is SKIPPED / not evaluated — never a pass (whether or not preflight ran).
  if (proof.currently_authorized === null) {
    return 'NOT_EVALUATED_SKIPPED';
  }
  if (proof.currently_authorized === false) {
    return proof.preflighted ? 'PREFLIGHTED_NOT_AUTHORIZED' : 'NOT_AUTHORIZED';
  }
  // currently_authorized === true
  if (proof.execution && proof.execution.enforced === true) return 'ENFORCED';
  return 'AUTHORIZED';
}

function bannerHeadline(banner: FinalAnswerProofBanner): string {
  switch (banner) {
    case 'ENFORCED':
      return 'ENFORCED — receipt verified; call ran on the guarded path';
    case 'AUTHORIZED':
      return 'AUTHORIZED — receipt verified for this scope (not a claim of full host protection)';
    case 'NOT_AUTHORIZED':
      return 'NOT AUTHORIZED — receipt path present but did not authorize';
    case 'PREFLIGHTED_NOT_AUTHORIZED':
      return 'PREFLIGHTED, NOT AUTHORIZED — preflight ran; receipt did not verify / not authorized';
    case 'NOT_EVALUATED_SKIPPED':
      return 'NOT EVALUATED (SKIPPED) — no receipt path; currently_authorized is null (not a pass)';
    case 'NO_PREFLIGHT':
      return 'NO PREFLIGHT — protection not evaluated on this call';
    default:
      return 'UNKNOWN PROOF STATUS';
  }
}

function yn(v: boolean): string {
  return v ? 'yes' : 'no';
}

function formatAuthz(v: boolean | null): string {
  if (v === true) return 'true (authorized at verify time)';
  if (v === false) return 'false (not authorized)';
  return 'null — not evaluated / no receipt path (SKIPPED; not a pass)';
}

function formatResultHash(h: ExecutionResultHash): string {
  if (!h || typeof h !== 'object') return 'unavailable';
  if (h.status === 'hashed') return `${h.algorithm}:${h.value.slice(0, 16)}… (factory return; not artifact-match proof)`;
  return `not hashed (${h.reason})`;
}

function limitLines(proof: GuardExecutionProof): string[] {
  const L = proof.limits;
  // Operative non-claims — always from the proof object (never invented).
  return [
    'This block does NOT claim the change is safe.',
    'This block does NOT claim the host cannot bypass the package.',
    'Absent fields are NOT compliance.',
    'change_fp is what was CHECKED at preflight — not what the factory applied.',
    'Calls outside the guarded path are invisible to this proof.',
    'execution_result_hash is NOT proof that applied artifacts match change_fp.',
    'conditional_write:true is host-asserted (the host says it conditioned on a version token); it is NOT independently CAS-verified by the guard.',
    ...(L.commit_observation_is_observed_at_t3_not_atomic === true
      ? ['commit_observation is observed at T3, not atomic: another writer may act between write and observation; token-only adapters compare version token not content; host attestation is a host claim layered on the measurement']
      : []),
    // Machine keys for greppability (still honest if someone only reads keys).
    `limits.does_not_claim_host_cannot_bypass=${L.does_not_claim_host_cannot_bypass === true}`,
    `limits.calls_outside_guarded_path_invisible=${L.calls_outside_guarded_path_invisible === true}`,
    `limits.does_not_claim_change_safe=${L.does_not_claim_change_safe === true}`,
    `limits.change_fp_is_what_was_checked_not_what_executed=${L.change_fp_is_what_was_checked_not_what_executed === true}`,
  ];
}

/**
 * Render a GuardExecutionProof as a compact human-readable block.
 * Faithful to fields; never upgrades null/false authorization into "protected".
 */
export function renderFinalAnswerProof(
  proof: GuardExecutionProof,
  opts: RenderFinalAnswerProofOptions = {},
): string {
  if (!proof || typeof proof !== 'object' || proof.proof_spec !== EXECUTION_PROOF_SPEC) {
    return [
      'CodeRifts execution proof',
      'Status: UNAVAILABLE — no valid guard-execution-proof.v1 object was supplied.',
      'Limits: without a proof block, no protection claim can be made.',
    ].join('\n');
  }

  const format: FinalAnswerProofFormat = opts.format === 'plain' ? 'plain' : 'markdown';
  const title = opts.title != null && String(opts.title).trim()
    ? String(opts.title).trim()
    : 'CodeRifts execution proof';

  const banner = deriveProofBanner(proof);
  const headline = bannerHeadline(banner);
  const md = format === 'markdown';

  const h1 = md ? `## ${title}` : title;
  const h2 = (s: string) => (md ? `### ${s}` : s);
  const bold = (s: string) => (md ? `**${s}**` : s);
  const bullet = (s: string) => (md ? `- ${s}` : `- ${s}`);

  const lines: string[] = [];
  lines.push(h1);
  lines.push('');
  lines.push(`${bold('Status:')} ${headline}`);
  lines.push(`${bold('Banner:')} ${banner}`);
  lines.push(`${bold('Proof spec:')} ${proof.proof_spec}`);
  lines.push('');

  lines.push(h2('Preflight & receipt'));
  lines.push(bullet(`preflighted: ${yn(proof.preflighted === true)}`));
  lines.push(bullet(`decision_id: ${proof.decision_id != null ? proof.decision_id : '(none)'}`));
  lines.push(bullet(`receipt.verified: ${yn(proof.receipt.verified === true)}`));
  lines.push(bullet(
    `receipt.status: ${proof.receipt.status != null ? proof.receipt.status : 'null (not verified / no receipt path)'}`,
  ));
  lines.push(bullet(
    `receipt.expires_at: ${proof.receipt.expires_at != null ? proof.receipt.expires_at : '(none)'}`,
  ));
  const trail = proof.recheck_trail;
  if (Array.isArray(trail) && trail.length > 1) {
    const n = trail.length - 1;
    const id = proof.decision_id != null ? proof.decision_id : '(none)';
    lines.push(bullet(`re-preflighted ${n}× after remediation; final decision ${id}`));
  }
  lines.push('');

  lines.push(h2('Authorization'));
  lines.push(bullet(`currently_authorized: ${formatAuthz(proof.currently_authorized)}`));
  if (proof.currently_authorized === null) {
    lines.push(bullet(
      'Interpretation: SKIPPED / no receipt path — do NOT treat this as protected or verified.',
    ));
  } else if (proof.currently_authorized === false) {
    lines.push(bullet(
      'Interpretation: NOT authorized — do NOT present this call as receipt-protected.',
    ));
  } else {
    lines.push(bullet(
      'Interpretation: authorized at verify time for the bound scope only — see Limits.',
    ));
  }
  lines.push('');

  lines.push(h2('Scope bound (what was checked)'));
  if (proof.binds_to == null) {
    lines.push(bullet('binds_to: null (no envelope — nothing bound)'));
  } else {
    lines.push(bullet(`operation: ${proof.binds_to.operation != null ? proof.binds_to.operation : '(null)'}`));
    lines.push(bullet(
      `change_fp: ${proof.binds_to.change_fp != null ? proof.binds_to.change_fp : '(null)'}`,
    ));
    lines.push(bullet(
      'Note: change_fp is what was CHECKED at preflight — not what the factory executed.',
    ));
  }
  lines.push('');

  lines.push(h2('Execution'));
  lines.push(bullet(`verdict_kind: ${proof.verdict_kind}`));
  lines.push(bullet(`attempted: ${yn(proof.execution.attempted === true)}`));
  lines.push(bullet(`executed: ${yn(proof.execution.executed === true)}`));
  lines.push(bullet(`enforced: ${yn(proof.execution.enforced === true)}`));
  lines.push(bullet(`execution_result_hash: ${formatResultHash(proof.execution_result_hash)}`));
  lines.push('');

  const co = proof.commit_observation;
  if (co && typeof co === 'object') {
    lines.push(h2('Commit observation (T3)'));
    lines.push(bullet(`status: ${co.status}`));
    lines.push(bullet(`observed_at: ${co.observed_at || '(none)'}`));
    if (co.host_attestation) lines.push(bullet(`host_attestation: ${co.host_attestation}`));
    if (co.observed_fp) lines.push(bullet(`observed_fp: ${co.observed_fp}`));
    if (co.expected_fp) lines.push(bullet(`expected_fp: ${co.expected_fp}`));
    if (co.token) lines.push(bullet(`token: ${co.token}`));
    lines.push(bullet(
      'Observed at T3, not atomic: another writer may act between write and observation; token-only adapters compare version token not content; host attestation is a host claim layered on the measurement.',
    ));
    lines.push('');
  }

  const mdv = proof.monitoring_delivery;
  if (mdv && typeof mdv === 'object' && typeof mdv.status === 'string') {
    lines.push(h2('Monitoring delivery'));
    lines.push(bullet(formatMonitoringDeliveryLine(mdv)));
    lines.push(bullet(
      'delivered_acked means the sink returned an ack — it does NOT mean a human saw the event.',
    ));
    lines.push('');
  }

  // Unconditional: the limits are part of the proof, not a presentation option. A block that
  // dropped them would still call itself the same proof while no longer stating what it does not
  // claim — the exact overclaim this render layer exists to prevent. Hosts that need a shorter
  // block use format:'plain', which compacts the markup and KEEPS the limits.
  lines.push(h2('Limits (non-claims — always true on this proof)'));
  for (const L of limitLines(proof)) {
    lines.push(bullet(L));
  }
  lines.push('');
  lines.push(
    md
      ? '_This block is honest because it states its limits. It is not a stronger guarantee than the machine proof._'
      : 'This block is honest because it states its limits. It is not a stronger guarantee than the machine proof.',
  );

  return lines.join('\n').replace(/\n+$/, '') + '\n';
}

/**
 * Attach a rendered proof to a host response (framework-agnostic).
 *
 * Convention:
 *  - String response + append_text → `response + separator + rendered`
 *  - Object response → shallow copy with:
 *      final_answer_proof: GuardExecutionProof (reference; not deep-cloned)
 *      final_answer_proof_text: string (rendered block)
 *    and, when mode is append_text and a stringish field exists (`text` | `content` |
 *    `message` | `final_answer`), that field is appended with the block.
 *  - field_only never mutates string fields; wraps bare strings in an object.
 *
 * Hosts that only want the string can call renderFinalAnswerProof directly.
 */
export function attachProofToAgentResponse<T = unknown>(
  response: T,
  proof: GuardExecutionProof,
  opts: AttachProofToAgentResponseOptions = {},
): T | (Record<string, unknown> & { final_answer_proof: GuardExecutionProof; final_answer_proof_text: string }) {
  const mode = opts.mode === 'field_only' ? 'field_only' : 'append_text';
  const separator = opts.separator != null ? opts.separator : '\n\n---\n\n';
  const text = renderFinalAnswerProof(proof, opts);

  if (typeof response === 'string') {
    if (mode === 'field_only') {
      return {
        text: response,
        final_answer_proof: proof,
        final_answer_proof_text: text,
      };
    }
    return (response + separator + text) as unknown as T;
  }

  if (response != null && typeof response === 'object' && !Array.isArray(response)) {
    const base = { ...(response as Record<string, unknown>) };
    base.final_answer_proof = proof;
    base.final_answer_proof_text = text;

    if (mode === 'append_text') {
      const keys = ['final_answer', 'text', 'content', 'message'] as const;
      for (const k of keys) {
        if (typeof base[k] === 'string') {
          base[k] = String(base[k]) + separator + text;
          break;
        }
      }
    }
    return base as T & {
      final_answer_proof: GuardExecutionProof;
      final_answer_proof_text: string;
    };
  }

  // Non-string, non-object (null, number, …): wrap so the proof is not lost.
  return {
    value: response,
    final_answer_proof: proof,
    final_answer_proof_text: text,
  };
}
