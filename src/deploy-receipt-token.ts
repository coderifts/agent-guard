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
  | 'UNSUPPORTED_VERSION';

export type DeployTokenVerifyResult = {
  valid: boolean;
  status: DeployTokenVerifyStatus;
  currently_authorized: boolean;
  authz_reason: string | null;
  /** When set, deployGate denies with this reason before bind checks. */
  denyReason: string | null;
  payload?: Record<string, unknown>;
  view: TokenDerivedReceiptView | null;
  key_status: 'active' | 'retired' | null;
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

function isIssueTimeWithinKeyWindow(
  ts: string | undefined,
  keyMeta: { status: string; valid_from: string | null; retired_at: string | null },
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

function resolveKey(
  kid: string,
  registry: ExecutorKeyRegistry | undefined,
  pinnedKeyPem: string | undefined,
): { publicKey: ReturnType<typeof createPublicKey>; status: 'active' | 'retired'; valid_from: string | null; retired_at: string | null } | null {
  if (typeof pinnedKeyPem === 'string' && pinnedKeyPem.trim().length > 0) {
    try {
      return {
        publicKey: createPublicKey(pinnedKeyPem),
        status: 'active',
        valid_from: null,
        retired_at: null,
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
      status: entry.status === 'retired' ? 'retired' : 'active',
      valid_from: entry.valid_from || null,
      retired_at: entry.retired_at || null,
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
