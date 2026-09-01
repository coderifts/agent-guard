/**
 * TOKEN-mode chain-receipt verification for deployGate.
 *
 * SDK 3.4.0 `CodeRifts.verifyReceipt` is HTTP POST /api/v1/verify-receipt (async, I/O) —
 * unusable inside the pure deployGate. Local public-material verify of crchain.v1 is
 * NOT exported by that SDK. This module:
 *   - uses node:crypto Ed25519 the same way `@coderifts/sdk` `verifyExecutionAttestation` does
 *     (`createPublicKey` + `verify`) — no new algorithm
 *   - reuses SDK `ExecutorKeyRegistry` shape and `isReceiptExpired` (ID104 leeway)
 *   - reuses this package's `computeBodyHash` for envelope bind
 *   - reconstructs the published crchain.v1 signing input (RECEIPT_FORMAT / app kernel)
 *
 * No fetch. Same inputs → same output.
 */

import { readNextAgentStep, type NextAgentStep } from './next-agent-step.js';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { isReceiptExpired } from '@coderifts/sdk';
import type { ExecutorKeyRegistry } from '@coderifts/sdk';
import { computeBodyHash } from './receipt-binding.js';

/** Structural receipt view produced after TOKEN verify (assignable to DeployReceiptView). */
export type TokenDerivedReceiptView = {
  currently_authorized: boolean;
  decision: string;
  execution_action?: string;
  operation?: string;
  bound_environment?: string | null;
  bound_artifact_id?: string | null;
  verdict_fingerprint?: string;
  body_hash?: string;
  target_id?: string;
  /**
   * I-1288f — the decision's own remediation suggestion, lifted from the envelope.
   * Only ever populated by viewFromEnvelope, which runs after the body hash bound.
   * `fail()` returns `view: null`, so no unverified token can produce one.
   */
  next_agent_step?: NextAgentStep | null;
};

export const CHAIN_SIGNING_PREFIX = 'crchain.v1';

export type DeployTokenReceipt = {
  /** Signed chain_receipt token (`base64url(body).base64url(sig)`). */
  token: string;
  /** Body-hash-bound decision envelope (verifier family). Required for currently_authorized. */
  decision_result?: Record<string, unknown>;
  /** Well-known-shaped registry `{ keys: [{ kid, public_key_pem, status, valid_from, retired_at }] }`. */
  registry?: ExecutorKeyRegistry;
  /** Air-gap single PEM (kid-agnostic). */
  pinnedKeyPem?: string;
};

export type DeployTokenVerifyStatus =
  | 'VERIFIED_CURRENT'
  | 'VERIFIED_EXPIRED'
  | 'RETIRED_KEY_VALID_AT_ISSUE'
  | 'INVALID_SIGNATURE'
  | 'MALFORMED'
  | 'UNKNOWN_KEY'
  | 'UNSUPPORTED_VERSION'
  // Key-withdrawal statuses, matching the published verifier taxonomy
  // (RECEIPT_FORMAT.md §7.1). Every one of these is valid:false.
  | 'KEY_REVOKED'
  | 'REVOKED_KEY'
  | 'REVOKED_KEY_UNDECIDABLE'
  | 'KEY_RETIRED_AFTER_SIGNING'
  | 'UNKNOWN_KEY_STATUS';

export type DeployTokenVerifyResult = {
  valid: boolean;
  status: DeployTokenVerifyStatus;
  currently_authorized: boolean;
  authz_reason: string | null;
  /** When set, deployGate denies with this reason before bind checks. */
  denyReason: string | null;
  payload?: Record<string, unknown>;
  view: TokenDerivedReceiptView | null;
  key_status: 'active' | 'retired' | 'revoked' | 'unknown' | null;
};

function scalar(v: unknown): string {
  return v == null ? '' : String(v);
}

function reconstructInput(payload: Record<string, unknown>): string {
  const v1 = `${CHAIN_SIGNING_PREFIX}|${scalar(payload.kid)}|${scalar(payload.fp)}|${scalar(payload.prev)}|${scalar(payload.caller)}|${scalar(payload.ts)}`;
  if (payload.v === 4) {
    return `${v1}|${scalar(payload.reg)}|${scalar(payload.ir)}|${scalar(payload.expires_at)}|${scalar(payload.bh)}`;
  }
  if (payload.v === 3) {
    return `${v1}|${scalar(payload.reg)}|${scalar(payload.ir)}`;
  }
  if (payload.v === 2) {
    return `${v1}|${scalar(payload.reg)}`;
  }
  return v1;
}

/**
 * The key-withdrawal half of the published verifier's status taxonomy
 * (`receipt-verifier/verify.js` deriveStatus, RECEIPT_FORMAT.md §7.1),
 * transliterated. Returns the refusal status, or null to continue.
 *
 * Order matters and matches the reference: an unknown status fails closed before
 * anything else is read; `revoked_at` kills the whole key history because the
 * attacker chooses `ts`; `retired_at` only rejects receipts signed at or after
 * it. A revoked key is never valid — UNDECIDABLE is not a softer accept, it
 * reports that a legitimate pre-compromise receipt cannot be told apart from a
 * backdated forgery.
 *
 * Kept as a small local function rather than a shared import: this package ships
 * pure and dependency-light, and the reference core is CommonJS with a CLI and
 * `fs` at module scope. `test/vendor-core.test.js` pins agreement with a
 * byte-identical copy of that core, so the two cannot drift silently.
 */
function deriveKeyWithdrawalStatus(
  ts: string | undefined,
  keyMeta: Pick<ResolvedKeyMeta, 'status' | 'retired_at' | 'revoked_at' | 'compromised_at'>,
): DeployTokenVerifyStatus | null {
  const KNOWN_STATUSES: ReadonlyArray<string | null> = ['active', 'retired', 'revoked', null];
  if (!KNOWN_STATUSES.includes(keyMeta.status)) return 'UNKNOWN_KEY_STATUS';

  if (typeof keyMeta.revoked_at === 'string' && keyMeta.revoked_at.length > 0) return 'KEY_REVOKED';

  if (typeof keyMeta.retired_at === 'string' && keyMeta.retired_at.length > 0 && ts) {
    const issued = Date.parse(ts);
    const retired = Date.parse(keyMeta.retired_at);
    if (Number.isFinite(issued) && Number.isFinite(retired) && issued >= retired) {
      return 'KEY_RETIRED_AFTER_SIGNING';
    }
  }

  if (keyMeta.status === 'revoked') {
    const at = keyMeta.compromised_at;
    if (typeof at !== 'string' || at.length === 0) return 'REVOKED_KEY_UNDECIDABLE';
    const boundary = Date.parse(at);
    const issued = typeof ts === 'string' ? Date.parse(ts) : NaN;
    if (!Number.isFinite(boundary) || !Number.isFinite(issued)) return 'REVOKED_KEY_UNDECIDABLE';
    return issued >= boundary ? 'REVOKED_KEY' : 'REVOKED_KEY_UNDECIDABLE';
  }
  return null;
}

function isIssueTimeWithinKeyWindow(
  ts: string | undefined,
  keyMeta: { status: string | null; valid_from: string | null; retired_at: string | null },
): boolean {
  if (!keyMeta || keyMeta.status === 'active') return true;
  if (keyMeta.status !== 'retired') return false;
  if (typeof keyMeta.retired_at !== 'string' || keyMeta.retired_at.length === 0) return false;
  if (typeof ts !== 'string' || ts.length === 0) return false;
  const issueMs = Date.parse(ts);
  if (!Number.isFinite(issueMs)) return false;
  if (keyMeta.valid_from) {
    const fromMs = Date.parse(keyMeta.valid_from);
    if (Number.isFinite(fromMs) && issueMs < fromMs) return false;
  }
  const retiredMs = Date.parse(keyMeta.retired_at);
  if (!Number.isFinite(retiredMs)) return false;
  if (issueMs >= retiredMs) return false;
  return true;
}

/**
 * The registry entry as it was published, not as we hope it reads.
 *
 * MEASURED 2026-09-01: this used to collapse the entry to `'retired' | 'active'`
 * — `entry.status === 'retired' ? 'retired' : 'active'`. A key the registry had
 * marked `revoked` therefore arrived here as ACTIVE, and deployGate allowed a
 * production deploy authorized by it, indistinguishably from a healthy key.
 * The status is now carried through verbatim and judged below.
 *
 * `revoked_at` / `compromised_at` are published on the well-known registry but
 * are not in the SDK's ExecutorKeyEntry type, so they are read structurally.
 */
type ResolvedKeyMeta = {
  publicKey: ReturnType<typeof createPublicKey>;
  status: string | null;
  valid_from: string | null;
  retired_at: string | null;
  revoked_at: string | null;
  compromised_at: string | null;
};

function optionalString(source: unknown, field: string): string | null {
  if (!source || typeof source !== 'object') return null;
  const v = (source as Record<string, unknown>)[field];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function resolveKey(
  kid: string,
  registry: ExecutorKeyRegistry | undefined,
  pinnedKeyPem: string | undefined,
): ResolvedKeyMeta | null {
  if (typeof pinnedKeyPem === 'string' && pinnedKeyPem.trim().length > 0) {
    try {
      return {
        publicKey: createPublicKey(pinnedKeyPem),
        status: 'active',
        valid_from: null,
        retired_at: null,
        revoked_at: null,
        compromised_at: null,
      };
    } catch {
      return null;
    }
  }
  if (!registry || !Array.isArray(registry.keys) || !kid) return null;
  const matches = registry.keys.filter((k) => k && k.kid === kid && typeof k.public_key_pem === 'string');
  if (matches.length === 0) return null;
  const entry = matches.find((k) => k.status === 'active') || matches[0];
  try {
    return {
      publicKey: createPublicKey(entry.public_key_pem),
      status: typeof entry.status === 'string' ? entry.status : null,
      valid_from: entry.valid_from || null,
      retired_at: entry.retired_at || null,
      revoked_at: optionalString(entry, 'revoked_at'),
      compromised_at: optionalString(entry, 'compromised_at'),
    };
  } catch {
    return null;
  }
}

function fail(
  status: DeployTokenVerifyStatus,
  denyReason: string,
  extra: Partial<DeployTokenVerifyResult> = {},
): DeployTokenVerifyResult {
  return {
    valid: false,
    status,
    currently_authorized: false,
    authz_reason: extra.authz_reason ?? denyReason,
    denyReason,
    view: null,
    key_status: extra.key_status ?? null,
    payload: extra.payload,
  };
}

function viewFromEnvelope(
  envelope: Record<string, unknown>,
  payload: Record<string, unknown>,
  currently_authorized: boolean,
): TokenDerivedReceiptView {
  const artifact = envelope.target_id ?? envelope.artifact_digest ?? envelope.bound_artifact_id;
  return {
    currently_authorized,
    decision: typeof envelope.decision === 'string' ? envelope.decision : '',
    execution_action: typeof envelope.execution_action === 'string' ? envelope.execution_action : undefined,
    operation: typeof envelope.operation === 'string' ? envelope.operation : undefined,
    bound_environment: typeof envelope.environment === 'string' ? envelope.environment : null,
    bound_artifact_id: artifact == null ? null : String(artifact),
    verdict_fingerprint: typeof envelope.fingerprint === 'string'
      ? envelope.fingerprint
      : (typeof payload.fp === 'string' ? payload.fp : undefined),
    body_hash: typeof payload.bh === 'string' ? payload.bh : undefined,
    target_id: envelope.target_id == null ? undefined : String(envelope.target_id),
    // Read from the envelope the caller supplied. On the currently_authorized path the
    // body hash has already bound it; on the expired / retired-key paths the signature
    // was authentic too. Every path that did NOT authenticate returns through fail(),
    // which sets view: null — so this field cannot carry an unsigned step.
    next_agent_step: readNextAgentStep(envelope),
  };
}

/**
 * Verify a chain-receipt token against a registry or pinned PEM. Pure (no I/O).
 */
export function verifyDeployReceiptToken(
  input: DeployTokenReceipt,
  _intended: { operation?: string; environment?: string; artifact_id?: string } = {},
  nowMs?: number,
): DeployTokenVerifyResult {
  const token = input && input.token;
  if (typeof token !== 'string' || token.length === 0) {
    return fail('MALFORMED', 'unverified_receipt_view');
  }
  const hasKeys = (input.pinnedKeyPem && String(input.pinnedKeyPem).trim().length > 0)
    || (input.registry && Array.isArray(input.registry.keys) && input.registry.keys.length > 0);
  if (!hasKeys) {
    return fail('MALFORMED', 'inputs_incomplete', { authz_reason: 'keys_missing' });
  }

  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) {
    return fail('MALFORMED', 'unverified_receipt_view');
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch {
    return fail('MALFORMED', 'unverified_receipt_view');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return fail('MALFORMED', 'unverified_receipt_view');
  }
  if (typeof payload.v === 'number' && payload.v > 4) {
    return fail('UNSUPPORTED_VERSION', 'unverified_receipt_view', { payload });
  }

  const kid = typeof payload.kid === 'string' ? payload.kid : '';
  const resolved = resolveKey(kid, input.registry, input.pinnedKeyPem);
  if (!resolved) return fail('UNKNOWN_KEY', 'unknown_key', { payload });

  let sigOk = false;
  try {
    sigOk = cryptoVerify(
      null,
      Buffer.from(reconstructInput(payload), 'utf8'),
      resolved.publicKey,
      Buffer.from(segments[1], 'base64url'),
    );
  } catch {
    return fail('INVALID_SIGNATURE', 'invalid_signature', { payload });
  }
  if (!sigOk) return fail('INVALID_SIGNATURE', 'invalid_signature', { payload });

  for (const k of ['kid', 'fp', 'prev', 'caller', 'ts', 'reg', 'ir', 'expires_at', 'bh']) {
    if (typeof payload[k] === 'string' && (payload[k] as string).includes('|')) {
      return fail('INVALID_SIGNATURE', 'invalid_signature', { payload, authz_reason: 'delimiter_in_field' });
    }
  }

  // A key the registry has withdrawn is judged BEFORE any authorization path.
  // The signature verified — that is precisely the problem a withdrawal exists
  // to answer, and no timestamp on a receipt the attacker minted may rehabilitate it.
  const withdrawn = deriveKeyWithdrawalStatus(
    typeof payload.ts === 'string' ? payload.ts : undefined,
    resolved,
  );
  if (withdrawn) {
    return fail(withdrawn, withdrawn === 'UNKNOWN_KEY_STATUS' ? 'unknown_key_status' : 'revoked_key', {
      payload,
      authz_reason: withdrawn.toLowerCase(),
      key_status: withdrawn === 'UNKNOWN_KEY_STATUS' ? 'unknown' : 'revoked',
    });
  }

  if (resolved.status === 'retired') {
    if (!isIssueTimeWithinKeyWindow(typeof payload.ts === 'string' ? payload.ts : undefined, resolved)) {
      return fail('INVALID_SIGNATURE', 'invalid_signature', { payload, authz_reason: 'retired_key_outside_window' });
    }
    const envelope = input.decision_result && typeof input.decision_result === 'object'
      ? input.decision_result
      : undefined;
    const view = envelope ? viewFromEnvelope(envelope, payload, false) : null;
    return {
      valid: true,
      status: 'RETIRED_KEY_VALID_AT_ISSUE',
      currently_authorized: false,
      authz_reason: 'retired_key',
      denyReason: 'retired_key',
      payload,
      view,
      key_status: 'retired',
    };
  }

  if (payload.v === 4 && typeof payload.expires_at === 'string') {
    const exp = Date.parse(payload.expires_at);
    const now = Number.isFinite(nowMs) ? (nowMs as number) : Date.now();
    if (isReceiptExpired(exp, now, { environment: _intended.environment, operation: _intended.operation })) {
      const envelope = input.decision_result && typeof input.decision_result === 'object'
        ? input.decision_result
        : undefined;
      return {
        valid: true,
        status: 'VERIFIED_EXPIRED',
        currently_authorized: false,
        authz_reason: 'expired',
        denyReason: 'expired',
        payload,
        view: envelope ? viewFromEnvelope(envelope, payload, false) : null,
        key_status: 'active',
      };
    }
  }

  const envelope = input.decision_result && typeof input.decision_result === 'object'
    ? input.decision_result
    : undefined;
  if (!envelope) {
    return {
      valid: true,
      status: 'VERIFIED_CURRENT',
      currently_authorized: false,
      authz_reason: 'receipt_context_required',
      denyReason: 'receipt_not_authorized',
      payload,
      view: null,
      key_status: 'active',
    };
  }

  let localBh: string | null = null;
  try { localBh = computeBodyHash(envelope); } catch { localBh = null; }
  if (typeof payload.bh !== 'string' || payload.bh !== localBh) {
    return fail('INVALID_SIGNATURE', 'body_hash_mismatch', { payload, authz_reason: 'body_hash_mismatch' });
  }

  return {
    valid: true,
    status: 'VERIFIED_CURRENT',
    currently_authorized: true,
    authz_reason: 'ok',
    denyReason: null,
    payload,
    view: viewFromEnvelope(envelope, payload, true),
    key_status: 'active',
  };
}
