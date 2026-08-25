/**
 * cr.coverage.attest.v1 issuance (guard side).
 *
 * Wire/signing input MIRRORS app src/verdict-core/coverage-attestation.js. The guard SIGNS via a
 * host-provided sign(bytes) callback — never a raw key in config. CodeRifts never holds the
 * coverage private key. Custody model copied from tryIssueMonitoringAttestation, deliberately:
 * one custody story for every host-signed artifact, not a second one per envelope.
 *
 * Observation-side only. Signer throw/empty → omit the token; never unsigned.
 *
 * ── THE PAYLOAD DECISION, and it is the point of this module ────────────────────────────────
 * A signed statement must not assert more than the guard measured.
 *
 * The guard's own class vocabulary is WIDER than the envelope's, deliberately:
 *   guard    UNKNOWN_OUTSIDE_SCOPE | INCOMPLETE_OBSERVED | COMPLETE_OBSERVED
 *   envelope UNKNOWN_OUTSIDE_SCOPE | INCOMPLETE_OBSERVED          (no COMPLETE, by design)
 *
 * Half B absent (host never reported total dispatches): the guard knows governed_calls and
 * nothing else. The token carries UNKNOWN_OUTSIDE_SCOPE and OMITS total_calls entirely. It does
 * not default the total to governed_calls, and it does not send zero — absence is not zero, and a
 * signed zero would be a lie with a signature on it.
 *
 * Guard COMPLETE_OBSERVED maps to envelope INCOMPLETE_OBSERVED. Not a downgrade for its own sake:
 * the envelope's two classes encode "totals known" vs "totals unknown", and the app kernel rejects
 * a COMPLETE payload as malformed rather than coercing it, because from inside the process the
 * ABSENCE of an ungoverned call is unprovable. The numbers carry the finding — an empty
 * ungoverned_tools tells the reader everything the host reported was governed, without a signed
 * claim of completeness that we cannot back.
 */
'use strict';

import type { CoverageObserved } from './coverage-observed.js';

export const COVERAGE_ATTEST_VERSION = 'cr.coverage.attest.v1';
export const COVERAGE_ATTEST_SIGNING_PREFIX = 'crcovattest.v1';
export const COVERAGE_ATTEST_ENVELOPE_TAG = 'cr.coverage.attest.v1';

/** Envelope classes. Intentionally two — there is no COMPLETE to emit. */
const ENVELOPE_CLASSES = ['INCOMPLETE_OBSERVED', 'UNKNOWN_OUTSIDE_SCOPE'] as const;

/** NUL joins the tool-name list inside one pipe field, so a name can never forge a field. */
const NUL = '\x1f';

export type CoverageAttestationSigner = (
  bytes: Uint8Array,
) => Uint8Array | Promise<Uint8Array>;

export type CoverageAttestationConfig = {
  /** Customer-held coverage key id. Named on the token; resolved later against a registry. */
  kid: string;
  /** Host signs the UTF-8 signing-input bytes. Returns raw Ed25519 signature. Never a raw key. */
  signer: CoverageAttestationSigner;
  /** Scope label for the statement (e.g. a session id). Required — a statement needs a subject. */
  sessionId: string;
};

function scalar(v: unknown): string {
  return v == null ? '' : String(v);
}

function canonicalUngoverned(list: unknown): string {
  return Array.isArray(list) ? list.map((s) => String(s)).join(NUL) : '';
}

export function coverageAttestSigningInput(body: Record<string, unknown>): string {
  const parts = [
    COVERAGE_ATTEST_SIGNING_PREFIX,
    scalar(body.kid),
    scalar(body.session_id),
    scalar(body.observed_class),
    body.governed_calls != null ? String(body.governed_calls) : '',
    body.total_calls != null ? String(body.total_calls) : '',
    canonicalUngoverned(body.ungoverned_tools),
    scalar(body.decision_id),
    scalar(body.receipt_digest),
    scalar(body.observed_at),
  ];
  return parts.join('|');
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

/** True when the host reported Half B (total dispatches), so a total may be asserted. */
function hasHalfB(cov: CoverageObserved): boolean {
  return cov.class !== 'UNKNOWN_OUTSIDE_SCOPE'
    && typeof (cov as { total_calls?: unknown }).total_calls === 'number';
}

/**
 * Issue a cr.coverage.attest.v1 token from a coverage snapshot. Returns undefined when config is
 * absent, the snapshot is unusable, or the host signer throws — never an unsigned token.
 */
export async function tryIssueCoverageAttestation(args: {
  config?: CoverageAttestationConfig | null;
  coverage: CoverageObserved | null | undefined;
  decisionId?: string | null;
  receiptDigest?: string | null;
  now?: string;
}): Promise<string | undefined> {
  const cfg = args.config;
  if (!cfg || typeof cfg.kid !== 'string' || !cfg.kid || typeof cfg.signer !== 'function') {
    return undefined;
  }
  if (typeof cfg.sessionId !== 'string' || cfg.sessionId.length === 0) return undefined;

  const cov = args.coverage;
  if (!cov || typeof cov !== 'object') return undefined;
  if (typeof cov.governed_calls !== 'number' || !Number.isInteger(cov.governed_calls) || cov.governed_calls < 0) {
    return undefined;
  }

  const halfB = hasHalfB(cov);
  const observed_class = halfB ? 'INCOMPLETE_OBSERVED' : 'UNKNOWN_OUTSIDE_SCOPE';
  if (!(ENVELOPE_CLASSES as readonly string[]).includes(observed_class)) return undefined;

  const body: Record<string, unknown> = {
    v: COVERAGE_ATTEST_VERSION,
    kid: cfg.kid,
    session_id: cfg.sessionId,
    observed_class,
    governed_calls: cov.governed_calls,
    observed_at: args.now || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };

  if (halfB) {
    const withTotals = cov as { total_calls: number; ungoverned_tools?: readonly string[] };
    // A statement claiming more governed than dispatched is not a coverage statement — the app
    // kernel rejects it as malformed, so refuse to mint it rather than emit a token that fails.
    if (!Number.isInteger(withTotals.total_calls) || withTotals.total_calls < cov.governed_calls) {
      return undefined;
    }
    body.total_calls = withTotals.total_calls;
    body.ungoverned_tools = Array.isArray(withTotals.ungoverned_tools)
      ? withTotals.ungoverned_tools.map((s) => String(s))
      : [];
  }
  // else: total_calls and ungoverned_tools are OMITTED. Not zero. Not defaulted.

  if (typeof args.decisionId === 'string' && args.decisionId) body.decision_id = args.decisionId;
  if (typeof args.receiptDigest === 'string' && args.receiptDigest) body.receipt_digest = args.receiptDigest;

  const input = Buffer.from(coverageAttestSigningInput(body), 'utf8');
  let sig: Uint8Array;
  try {
    sig = await cfg.signer(input);
  } catch {
    return undefined;
  }
  if (sig == null) return undefined;
  const sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  if (sigBuf.length === 0) return undefined;

  return [
    COVERAGE_ATTEST_ENVELOPE_TAG,
    cfg.kid,
    b64url(Buffer.from(JSON.stringify(body), 'utf8')),
    b64url(sigBuf),
  ].join('|');
}

export function kidFromCoverageAttestation(token: string | undefined | null): string | null {
  if (typeof token !== 'string' || token.length === 0) return null;
  const parts = token.split('|');
  if (parts.length !== 4 || parts[0] !== COVERAGE_ATTEST_ENVELOPE_TAG) return null;
  return parts[1] || null;
}
