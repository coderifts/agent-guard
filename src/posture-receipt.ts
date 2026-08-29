/**
 * cr.posture.receipt.v1 verifier (roadmap 1167).
 *
 * Verifies the signed posture receipt produced by the data plane
 * (capability-demo demo/src/posture.js): a catalog read-back asserting the
 * credential boundary is still wired, signed out-of-DB by the executor key.
 *
 * WHY THIS EXISTS. ENFORCING_ATOMIC_V1's credential_boundary invariant accepts
 * `credentialBoundary: true` — a bare assertion, verified by nothing
 * (atomic-profile.ts:108-109). An external audit called that a P0, correctly.
 * _V2 replaces the assertion with this verification. _V1 is frozen and still
 * accepts the bare form; the break is opt-in.
 *
 * No new crypto: `createPublicKey` + `verify` from node:crypto, the same two
 * primitives deploy-receipt-token.ts uses, and the same registry/pinned-PEM
 * key resolution shape.
 *
 * VERIFY OVER RAW BYTES, PARSE ONLY TO READ. The producer signs
 * `canonicalJson(body)` (posture.js:436-437), and that canonicalJson is a local
 * implementation (posture.js:179-183), NOT RFC 8785 JCS. Re-serialising the
 * parsed object to re-derive the signed bytes would be a bit-exactness trap
 * that fails on the first key-order or escaping difference. So: the signature is
 * checked against the DECODED PREIMAGE BYTES exactly as they arrived, and
 * JSON.parse is used only to read fields out of an already-verified message.
 *
 * FRESHNESS, NOT EXPIRY — and the distinction is load-bearing. The receipt
 * carries `measured_at` (posture.js:431) and NO `expires_at`; measured against
 * the producer, the field simply does not exist. So this verifier cannot check
 * an expiry the receipt never made. It checks AGE against a caller-supplied
 * `maxAgeMs`, and it deliberately has NO default: a default here would present
 * the guard's policy as though the receipt had stated it.
 *
 * No fetch. Same inputs → same output.
 */

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { ExecutorKeyRegistry } from '@coderifts/sdk';

export const POSTURE_RECEIPT_V = 'cr.posture.receipt.v1' as const;

export type PostureVerifyStatus =
  | 'POSTURE_PASS'
  | 'POSTURE_FAIL'
  | 'POSTURE_MALFORMED'
  | 'POSTURE_UNKNOWN_KEY'
  | 'POSTURE_INVALID_SIGNATURE'
  | 'POSTURE_UNBOUND'
  | 'POSTURE_STALE';

export type PostureReceiptPayload = {
  v?: string;
  executor_kid?: string;
  deployment_id?: string;
  measured_at?: string;
  verdict?: string;
  facts?: unknown;
  drift?: unknown;
};

export type PostureVerifyInput = {
  /** Well-known-shaped registry `{ keys: [{ kid, public_key_pem, status, … }] }`. */
  registry?: ExecutorKeyRegistry;
  /** Air-gap single PEM (kid-agnostic). */
  pinnedKeyPem?: string;
  /** The receipt must be bound to THIS deployment. */
  expectedDeploymentId?: string;
  /** Caller-supplied freshness window in ms. NO DEFAULT — see the header. */
  maxAgeMs?: number;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
};

export type PostureVerifyResult = {
  valid: boolean;
  status: PostureVerifyStatus;
  reason: string | null;
  payload?: PostureReceiptPayload;
  /** Age in ms at verification time, when it could be computed. */
  age_ms?: number;
};

/**
 * Same shape and precedence as deploy-receipt-token.ts:106-134 — pinned PEM wins
 * (air-gap), then the registry entry for this kid, preferring an active key.
 */
function resolvePostureKey(
  kid: string,
  registry: ExecutorKeyRegistry | undefined,
  pinnedKeyPem: string | undefined,
): ReturnType<typeof createPublicKey> | null {
  if (typeof pinnedKeyPem === 'string' && pinnedKeyPem.trim().length > 0) {
    try {
      return createPublicKey(pinnedKeyPem);
    } catch {
      return null;
    }
  }
  if (!registry || !Array.isArray(registry.keys) || !kid) return null;
  const matches = registry.keys.filter(
    (k) => k && k.kid === kid && typeof k.public_key_pem === 'string',
  );
  if (matches.length === 0) return null;
  const entry = matches.find((k) => k.status === 'active') || matches[0];
  try {
    return createPublicKey(entry.public_key_pem as string);
  } catch {
    return null;
  }
}

const fail = (
  status: PostureVerifyStatus,
  reason: string,
  extra: Partial<PostureVerifyResult> = {},
): PostureVerifyResult => ({ valid: false, status, reason, ...extra });

/**
 * Verify a posture receipt token.
 *
 * @param token `cr.posture.receipt.v1|<executor_kid>|<b64url(preimage)>|<signature>`
 *              (envelope shape measured at posture.js:370-377)
 */
export function verifyPostureReceipt(
  token: unknown,
  input: PostureVerifyInput = {},
): PostureVerifyResult {
  if (typeof token !== 'string' || token.length === 0) {
    return fail('POSTURE_MALFORMED', 'malformed_structure');
  }
  const seg = token.split('|');
  if (seg.length !== 4 || seg[0] !== POSTURE_RECEIPT_V || seg.some((x) => !x)) {
    return fail('POSTURE_MALFORMED', 'malformed_structure');
  }

  // The bytes the producer signed, exactly as they arrived. Never re-derived.
  let preimageBytes: Buffer;
  try {
    preimageBytes = Buffer.from(seg[2], 'base64url');
    if (preimageBytes.length === 0) throw new Error('empty');
  } catch {
    return fail('POSTURE_MALFORMED', 'bad_preimage');
  }

  const key = resolvePostureKey(seg[1], input.registry, input.pinnedKeyPem);
  if (!key) return fail('POSTURE_UNKNOWN_KEY', 'unknown_kid');

  let sigOk = false;
  try {
    sigOk = cryptoVerify(null, preimageBytes, key, Buffer.from(seg[3], 'base64url'));
  } catch {
    return fail('POSTURE_INVALID_SIGNATURE', 'signature_error');
  }
  if (!sigOk) return fail('POSTURE_INVALID_SIGNATURE', 'signature_mismatch');

  // Parsed AFTER the signature holds: reading fields out of a verified message.
  let payload: PostureReceiptPayload;
  try {
    payload = JSON.parse(preimageBytes.toString('utf8')) as PostureReceiptPayload;
  } catch {
    return fail('POSTURE_MALFORMED', 'bad_json');
  }
  if (!payload || typeof payload !== 'object') {
    return fail('POSTURE_MALFORMED', 'bad_json');
  }

  // A validly signed FAIL is a signed drift artifact, not a broken receipt. The
  // signature held; the posture did not. Reporting this as INVALID_SIGNATURE
  // would hide a real boundary regression behind a crypto-shaped error.
  if (payload.verdict !== 'PASS') {
    return fail('POSTURE_FAIL', 'posture_verdict_not_pass', { payload });
  }

  if (typeof input.expectedDeploymentId === 'string' && input.expectedDeploymentId.length > 0) {
    if (payload.deployment_id !== input.expectedDeploymentId) {
      return fail('POSTURE_UNBOUND', 'deployment_id_mismatch', { payload });
    }
  }

  // FRESHNESS. maxAgeMs is the CALLER's window; there is no receipt-carried
  // expiry to fall back on, so an absent maxAgeMs means the caller did not ask
  // for an age check — not that the receipt is timeless.
  let ageMs: number | undefined;
  if (typeof input.maxAgeMs === 'number' && Number.isFinite(input.maxAgeMs)) {
    const measured = Date.parse(String(payload.measured_at));
    if (Number.isNaN(measured)) {
      return fail('POSTURE_STALE', 'measured_at_unparseable', { payload });
    }
    const now = (input.now || (() => Date.now()))();
    ageMs = now - measured;
    if (ageMs > input.maxAgeMs) {
      return fail('POSTURE_STALE', 'outside_freshness_window', { payload, age_ms: ageMs });
    }
  }

  return {
    valid: true,
    status: 'POSTURE_PASS',
    reason: null,
    payload,
    ...(ageMs === undefined ? {} : { age_ms: ageMs }),
  };
}
