/**
 * 1356 — the host is the FIRST gate in the inescapability order (host → model → registry → CI),
 * and until now it was the only one of the four that let a mutating call through by default.
 *
 * ── WHAT WAS ALREADY FAIL-CLOSED, MEASURED 2026-09-04 ───────────────────────────────────────
 *
 * Three of the four cases in the brief were ALREADY blocked by default, and the flip must not be
 * described as if it closed them:
 *
 *   contract call + NO receipt        UNAVAILABLE / RECEIPT_MISSING       guard.ts:981,1067
 *   contract call + unknown key       UNAVAILABLE / RECEIPT_UNVERIFIED    guard.ts:813
 *   contract call + STOP              BLOCK                               guard.ts:854
 *
 * `enforceable = receiptVerified && …` (guard.ts:981) is the invariant that does it: the guard
 * never runs the factory as enforced without a bound receipt. `requireReceipt: 'fail-closed'`
 * (1307) fires earlier on the same fact; it is not what stood between a stranger and execution.
 *
 * ── THE GAP THAT WAS REAL ───────────────────────────────────────────────────────────────────
 *
 * All three depend on the DETECTOR having triggered. The detector fires on contract artifacts —
 * OpenAPI, GraphQL, protobuf, MCP manifests. A call it does not recognise takes the SKIPPED path
 * (guard.ts:600) and executes with `preflighted:false, enforced:false`. Measured, by default:
 *
 *   Read   README.md                                  SKIPPED → executed   (correct)
 *   Edit   src/app.py       old_string/new_string     SKIPPED → executed   ← mutation, unguarded
 *   Write  deploy.sh        content: 'rm -rf /'       SKIPPED → executed   ← mutation, unguarded
 *
 * "Not a contract change" is a true statement about the ARTIFACT and it was being used as a
 * decision about the ACTION. The host wrapped the tool, the guard saw the call, and the write
 * happened anyway with nothing signed.
 *
 * ── THE FLIP ────────────────────────────────────────────────────────────────────────────────
 *
 * A mutating call that reaches the end of the guard with no verified receipt is BLOCKED by
 * default. Advisory remains available and is now a NAMED choice — `CODERIFTS_ADVISORY=1`, or
 * `requireGuardedMutation: 'advisory'` — and it WARNS every time. `verify_ssl=false` is the
 * comparison: a real option, spelled out loud, never the silent default.
 *
 * ── WHAT THIS DELIBERATELY DOES NOT DO ──────────────────────────────────────────────────────
 *
 * It does not widen `isMutatingCall` (freshness.ts:433). That predicate is shared with the
 * conditional-write policy (guard.ts:495), so widening it here would silently change a second,
 * unrelated gate. The consequence is a MEASURED RESIDUAL, and it should be read as a limit of
 * this change rather than a property of it: `Bash { command: 'kubectl apply -f prod.yaml' }` is
 * NOT classified mutating — the predicate reads contents/content/new_string/old_string/patch/
 * edits, and `command` is not among them. A shell command that mutates production still takes the
 * SKIPPED path. Closing that needs the predicate widened WITH the conditional-write blast radius
 * measured, which is a separate change.
 *
 * An explicit `requireGuardedMutation: 'fail-closed'` is NOT overridable by the environment. An
 * escape hatch that can undo a decision the host wrote down is not an escape hatch, it is a
 * bypass, and anyone who can set an environment variable would hold it.
 */

/**
 * 'fail-closed'  default — a mutating call with no verified receipt does not execute.
 * 'advisory'     execute anyway, and warn every time. Deliberate, named, and loud.
 */
export type GuardedMutationPolicy = 'fail-closed' | 'advisory';

/** The named opt-out. Compared against exactly these, so `CODERIFTS_ADVISORY=0` is not advisory. */
const ADVISORY_TRUE = new Set(['1', 'true', 'yes', 'on']);

export const ADVISORY_ENV_VAR = 'CODERIFTS_ADVISORY';

export interface UnguardedMutationDecision {
  /** Refuse to execute. */
  readonly stop: boolean;
  /** Executing anyway under advisory — the caller MUST surface this; silence is the failure mode. */
  readonly warn?: string;
  /** Why, in terms of what is at risk. */
  readonly detail?: string;
  /** Which input produced the advisory outcome, so a report can say who chose it. */
  readonly source?: 'config' | 'environment';
}

const RISK =
  'A mutating tool call reached the guard with no verified receipt: the detector did not '
  + 'recognise a contract artifact, so nothing was preflighted and nothing was signed. "Not a '
  + 'contract change" describes the artifact, not the action — the write still happens.';

/**
 * @param mutating   isMutatingCall() over the REDACTED descriptor — never the raw one.
 * @param policy     host configuration; undefined means the new default.
 * @param env        process.env, injected so this stays a pure function and is testable.
 */
export function decideUnguardedMutation(
  mutating: boolean,
  policy: GuardedMutationPolicy | undefined,
  env: Record<string, string | undefined>,
): UnguardedMutationDecision {
  // Read tools are the whole reason this is gated on mutation rather than on "was it preflighted".
  if (!mutating) return { stop: false };

  if (policy === 'advisory') {
    return {
      stop: false,
      source: 'config',
      detail: RISK,
      warn:
        'CodeRifts: ADVISORY — executing an unguarded mutating tool call. '
        + 'requireGuardedMutation is set to \'advisory\', so the guard is reporting rather than '
        + 'enforcing. ' + RISK,
    };
  }

  // An explicit fail-closed outranks the environment. Checked BEFORE reading env on purpose.
  if (policy !== 'fail-closed' && ADVISORY_TRUE.has(String(env[ADVISORY_ENV_VAR] ?? '').toLowerCase())) {
    return {
      stop: false,
      source: 'environment',
      detail: RISK,
      warn:
        `CodeRifts: ADVISORY — executing an unguarded mutating tool call because `
        + `${ADVISORY_ENV_VAR} is set. This is the documented opt-out and it is not the default. `
        + RISK,
    };
  }

  return {
    stop: true,
    detail:
      RISK + ' Blocked by default. To proceed without a receipt, choose it explicitly: set '
      + `${ADVISORY_ENV_VAR}=1 or requireGuardedMutation: 'advisory'. To proceed WITH one, send `
      + 'the change through preflight so there is something to verify.',
  };
}
