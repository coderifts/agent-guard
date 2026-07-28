/**
 * Client-side receipt→envelope BINDING (P0 fix: receipt-substitution).
 *
 * A valid receipt authenticates a decision the SERVER signed — it does NOT authenticate whatever
 * envelope an attacker wraps around it. Before executing with enforced:true, the guard must bind the
 * receipt to THIS envelope by LOCALLY RECOMPUTING the canonical decision body hash and comparing it
 * to the receipt's SIGNED `bh` (never trusting the envelope's own claimed `decision_body_hash`, which
 * an attacker rewrites). This mirrors the server's §106 isCurrentlyAuthorized binding, applied in the
 * client — the guard is the component that authorizes execution, so the binding must live here too.
 *
 * The canonicalization is ported VERBATIM from the server's canonical-json.js + decision-result.js
 * computeBodyHash so the recomputed hash is byte-identical to the server's decision_body_hash.
 */

import { createHash } from 'node:crypto';

/**
 * RFC 8785 (JCS) canonical JSON for the envelope domain (ASCII keys, JSON-representable scalars).
 * Ported verbatim from the server canonicalizer so client + server hash identically.
 */
export function canonicalJson(value: unknown): string {
  return encode(value);
}

function encode(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value as number)) throw new TypeError('canonicalJson: non-finite number is not representable');
    return JSON.stringify(value);
  }
  if (t === 'undefined') throw new TypeError('canonicalJson: undefined is not representable (omit the key instead)');
  if (Array.isArray(value)) return `[${value.map(encode).join(',')}]`;
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${encode(obj[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported type ${t}`);
}

function sha256hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/**
 * decision_body_hash = 'sha256:' + sha256(canonicalJson(envelope MINUS receipt MINUS
 * decision_body_hash)). Recomputed LOCALLY from the presented envelope so a rewritten field can
 * never pass — identical algorithm to the server's decision-result.js computeBodyHash.
 */
export function computeBodyHash(envelope: Record<string, unknown>): string {
  const rest = { ...envelope };
  delete rest.receipt;
  delete rest.decision_body_hash;
  return `sha256:${sha256hex(canonicalJson(rest))}`;
}

/** Minimal shape of the SDK verifyReceipt result the binding consumes. */
export interface VerifyReceiptResultLike {
  valid?: boolean;
  status?: string;
  reason?: string | null;
  payload?: Record<string, unknown>;
}

/** Host context the receipt scope must match (from GuardConfig). */
export interface BindContext {
  operation?: string;
  environment?: string;
  audience?: string;
}

export type BindCause = 'RECEIPT_UNVERIFIED' | 'RECEIPT_ENVELOPE_MISMATCH';

export interface BindResult {
  ok: boolean;
  cause?: BindCause;
  detail?: string;
}

/**
 * Bind a verified receipt to THIS envelope. Fail-closed on ANY mismatch. Ordered checks:
 *  1. valid === true                              (bad signature → RECEIPT_UNVERIFIED)
 *  2. status === 'VERIFIED_CURRENT'               (expired / superseded / wrong-audience / wrong-env
 *                                                  / scope-mismatch → RECEIPT_ENVELOPE_MISMATCH)
 *  3. signed bh === LOCALLY-recomputed body hash  (the anti-substitution anchor — binds the ENTIRE
 *                                                  decision body incl. decision/execution_action/fp)
 *  4. signed fp === envelope.fingerprint          (explicit fingerprint binding)
 *  5. operation / environment / audience scope    (when the AUTHENTICATED envelope carries them —
 *                                                  bh already binds their presence/value)
 *
 * @param envelope  the presented decision envelope (attacker-influenced; NOT trusted for bh/fp)
 * @param vr        the SDK verifyReceipt result ({ valid, status, payload:{ fp, bh, … } })
 * @param ctx       host operation/environment/audience the receipt must match
 */
export function bindReceiptToEnvelope(
  envelope: Record<string, unknown> | null | undefined,
  vr: VerifyReceiptResultLike | null | undefined,
  ctx: BindContext = {},
): BindResult {
  if (!envelope) return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: 'no envelope' };
  if (!vr || vr.valid !== true) return { ok: false, cause: 'RECEIPT_UNVERIFIED', detail: `valid=${vr ? vr.valid : 'none'}` };
  if (vr.status !== 'VERIFIED_CURRENT') {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: `status ${vr.status ?? 'unknown'} != VERIFIED_CURRENT` };
  }

  const payload = (vr.payload || {}) as Record<string, unknown>;

  // 3. LOCAL body-hash recomputation — the load-bearing anti-substitution check.
  const localBh = computeBodyHash(envelope);
  if (typeof payload.bh !== 'string' || payload.bh !== localBh) {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: 'decision_body_hash mismatch (receipt was signed over a different envelope)' };
  }

  // 4. Signed fingerprint must bind the envelope's fingerprint.
  if (typeof payload.fp !== 'string' || payload.fp !== envelope.fingerprint) {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: 'verdict_fingerprint mismatch' };
  }

  // 5. Scope: operation / environment / audience (bh already authenticates these values; this asserts
  //    the receipt was issued for the CURRENTLY-REQUESTED context — the merge≠deploy / §106 rule).
  const requestedOp = ctx.operation ?? 'tool_call';
  if (envelope.operation != null && requestedOp != null && envelope.operation !== requestedOp) {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: `operation ${String(envelope.operation)} != ${String(requestedOp)}` };
  }
  if (ctx.environment != null && envelope.environment != null && envelope.environment !== ctx.environment) {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: `environment ${String(envelope.environment)} != ${String(ctx.environment)}` };
  }
  if (ctx.audience != null && envelope.audience != null && envelope.audience !== ctx.audience) {
    return { ok: false, cause: 'RECEIPT_ENVELOPE_MISMATCH', detail: `audience ${String(envelope.audience)} != ${String(ctx.audience)}` };
  }

  return { ok: true };
}
