/**
 * Pure receipt-chain LINKAGE verifier.
 *
 * Checks only that each token's signed body `prev` field matches the predecessor commitment
 * (literal 'null' for a root, or 'sha256:'+hex(sha256(previous_token)) for a link). Does NOT
 * verify Ed25519 signatures, expiry, keys, or authorization — those live on the verify-receipt
 * path. Linkage ≠ authenticity.
 *
 * The composition / guard MUST NOT call this over a package-held chain and report the result as
 * product truth; a consumer re-runs this (and signature verify) on an export they hold.
 */

import { createHash } from 'node:crypto';

/** Literal stored in the receipt body when the issuer was given no previous receipt. */
export const RECEIPT_PREV_NULL = 'null';

export type ReceiptChainLinkageReason =
  | 'malformed_token'
  | 'broken_link'
  | 'unexpected_predecessor';

export type ReceiptChainLinkageResult =
  | {
      ok: true;
      /** Number of tokens examined (0 for an empty list — vacuously linked). */
      length: number;
    }
  | {
      ok: false;
      length: number;
      /** 0-based index of the token that failed the check. */
      failedAt: number;
      reason: ReceiptChainLinkageReason;
      /** What the verifier expected in body.prev (when known). */
      expected?: string;
      /** What body.prev actually contained (when parsed). */
      actual?: string;
    };

/**
 * sha256 hex digest of a prior receipt token, in the issuer's prev-slot form:
 * `sha256:` + hex (matches server chain-attestation issueReceipt).
 */
export function previousReceiptCommitment(previousToken: string): string {
  return 'sha256:' + createHash('sha256').update(previousToken, 'utf8').digest('hex');
}

/**
 * Decode the JSON body of a chain receipt token (`base64url(body).base64url(sig)`).
 * Returns null if the token is not two segments or the body is not JSON with a string `prev`.
 */
export function decodeReceiptBodyPrev(token: string): { prev: string } | null {
  if (typeof token !== 'string' || token.length === 0) return null;
  // Chain receipt layout: base64url(body).base64url(sig) — exactly two segments.
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  try {
    const json = Buffer.from(parts[0], 'base64url').toString('utf8');
    const body = JSON.parse(json) as { prev?: unknown };
    if (typeof body.prev !== 'string') return null;
    return { prev: body.prev };
  } catch {
    return null;
  }
}

/**
 * Verify predecessor-hash LINKAGE over an ordered list of receipt tokens.
 *
 * - Empty list → ok (vacuous).
 * - tokens[0] must have prev === 'null' (root of this presented sequence).
 * - tokens[i] must have prev === previousReceiptCommitment(tokens[i-1]).
 *
 * Does not contact the network or consult a clock.
 */
export function verifyReceiptChainLinkage(
  tokens: readonly string[],
): ReceiptChainLinkageResult {
  const length = tokens.length;
  if (length === 0) {
    return { ok: true, length: 0 };
  }

  for (let i = 0; i < length; i++) {
    const decoded = decodeReceiptBodyPrev(tokens[i]!);
    if (!decoded) {
      return {
        ok: false,
        length,
        failedAt: i,
        reason: 'malformed_token',
      };
    }
    if (i === 0) {
      // First token of the presented list must be a root of that list (prev = 'null').
      // A non-null prev means the list claims a predecessor that was not included —
      // distinct from a broken link between two included tokens.
      if (decoded.prev !== RECEIPT_PREV_NULL) {
        return {
          ok: false,
          length,
          failedAt: 0,
          reason: 'unexpected_predecessor',
          expected: RECEIPT_PREV_NULL,
          actual: decoded.prev,
        };
      }
      continue;
    }
    const expected = previousReceiptCommitment(tokens[i - 1]!);
    if (decoded.prev !== expected) {
      return {
        ok: false,
        length,
        failedAt: i,
        reason: 'broken_link',
        expected,
        actual: decoded.prev,
      };
    }
  }

  return { ok: true, length };
}
