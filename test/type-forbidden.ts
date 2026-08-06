/**
 * tsc-verified forbidden states. Each @ts-expect-error asserts the frozen invariant is
 * UNREPRESENTABLE at compile time. If a forbidden state ever becomes representable, its
 * @ts-expect-error goes "unused" and `npm run typecheck:forbidden` fails. The valid states at the
 * bottom prove the unions are not merely rejecting everything.
 *
 * Not part of the build (test/ is excluded from dist); compiled only by tsconfig.typetest.json.
 */
import type { GuardOutcome, ApprovedVerdict, UnavailableVerdict, ReceiptVerifiedEnvelope, DecisionResultEnvelope, GuardExecutionProof } from '../src/types';

declare const env: DecisionResultEnvelope;
declare const branded: ReceiptVerifiedEnvelope;
// proof is always present on GuardOutcome; fixtures supply a declared value (not caller-injected at runtime).
declare const proof: GuardExecutionProof;

// enforced:true with a BLOCK verdict — enforced-bypass, unrepresentable.
// @ts-expect-error enforced:true requires an ApprovedVerdict (ALLOW/MONITOR), never BLOCK
const f1: GuardOutcome<string> = { executionAttempted: true, executed: true, enforced: true, result: 'x', verdict: { kind: 'BLOCK', action: 'STOP', envelope: env, receiptVerified: true }, preflighted: true, proof };

// ApprovedVerdict with receiptVerified:false — enforced without verification, unrepresentable.
// @ts-expect-error ApprovedVerdict.receiptVerified must be literally true
const f2: ApprovedVerdict = { kind: 'ALLOW', action: 'CONTINUE', envelope: env, receiptVerified: false };

// closed policy that executes — integrity-fail-open, unrepresentable.
// @ts-expect-error OPEN_PASSTHROUGH requires failPolicy:'open', not 'closed'
const f3: UnavailableVerdict = { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: 1, cause: 'TIMEOUT', failPolicy: 'closed', resolution: 'OPEN_PASSTHROUGH', action: 'CONTINUE' };

// an integrity cause resolving permissively — unrepresentable.
// @ts-expect-error an IntegrityCause can only resolve CLOSED, never OPEN_PASSTHROUGH
const f4: UnavailableVerdict = { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: 1, cause: 'INVALID_RESPONSE', failPolicy: 'open', resolution: 'OPEN_PASSTHROUGH', action: 'CONTINUE' };

// LKG executing on an UNVERIFIED envelope — unrepresentable.
// @ts-expect-error lkgEnvelope must be a branded ReceiptVerifiedEnvelope, not a plain envelope
const f5: UnavailableVerdict = { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: 1, cause: 'TIMEOUT', failPolicy: 'lkg', resolution: 'LKG_SUBSTITUTION', action: 'CONTINUE', lkgEnvelope: env };

// ── valid states (MUST compile) ──────────────────────────────────────────────────
const ok1: ApprovedVerdict = { kind: 'ALLOW', action: 'CONTINUE', envelope: env, receiptVerified: true };
const ok2: UnavailableVerdict = { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: 1, cause: 'TIMEOUT', failPolicy: 'lkg', resolution: 'LKG_SUBSTITUTION', action: 'CONTINUE', lkgEnvelope: branded };
const ok3: GuardOutcome<string> = { executionAttempted: true, executed: true, enforced: true, result: 'x', verdict: ok1, preflighted: true, proof };

void f1; void f2; void f3; void f4; void f5; void ok1; void ok2; void ok3;
