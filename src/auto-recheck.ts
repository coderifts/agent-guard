/**
 * S6 auto-recheck loop — host-side orchestration AFTER a BLOCK with a remediation_transaction.
 *
 * Default OFF. The frozen guardToolCall is unchanged; this wraps it. The guard never writes
 * artifacts: the host's applyFix applies the fix (honesty line). After applyFix true, artifacts
 * are re-resolved FRESH (resolve() from artifact-resolver when resolveInput is supplied, else
 * the host-updated call / rebind).
 *
 * recheck_scope is an OUTPUT on the BLOCK envelope (app remediation-transaction.js). The
 * preflight request does not accept a scope hint (measured SDK / authorizeChangeSet) — so
 * each attempt is a FULL re-preflight. Noted, not faked.
 *
 * Nothing here enters a fingerprint preimage (host orchestration only).
 */

import { guardToolCall } from './guard.js';
import type {
  GuardConfig,
  GuardOutcome,
  GuardVerdict,
  ToolCallDescriptor,
  ExecuteFactory,
  GuardEvent,
  GuardToolCallContext,
  DecisionResultEnvelope,
  Artifact,
} from './types.js';
import { readRemediationTransaction } from './remediation-loop-attestation.js';
import type { RemediationTransactionView } from './remediation-loop-attestation.js';
import { resolve as resolveArtifacts } from './artifact-resolver.js';
import type { ResolveInput, ResolveConfig } from './artifact-resolver.js';

/** Hard cap on RE-preflights per original call. */
export const AUTO_RECHECK_MAX_CAP = 3;

export type RecheckTrailEntry = {
  attempt: number;
  decision_id: string | null;
  fingerprint: string | null;
  execution_action: string | null;
};

export type RecheckStopReason =
  | 'no_progress'
  | 'apply_fix_declined'
  | 'apply_fix_threw'
  | 'exhausted';

export type RecheckObservation = {
  recheck_trail?: ReadonlyArray<RecheckTrailEntry>;
  /** 849 metric feed. Present only when the loop ran. value true iff a recheck landed allow-class. */
  fixed_after_block?: { value: true | null; attempt_count: number | null };
  recheck_stop_reason?: RecheckStopReason;
};

export type AutoRecheckApplyFixContext = {
  call: ToolCallDescriptor;
  attempt: number;
  outcome: GuardOutcome<unknown>;
};

export type AutoRecheckConfig = {
  /**
   * Bound on RE-preflights per original call. Allowed 1–3; values above 3 clamp to 3.
   * Values below 1 disable the loop.
   */
  maxAttempts: number;
  /**
   * HOST applies the fix. The guard never writes artifacts.
   * false / throw → loop ends, original BLOCK stands.
   */
  applyFix: (
    remediation: RemediationTransactionView,
    context: AutoRecheckApplyFixContext,
  ) => boolean | Promise<boolean>;
  /**
   * Optional. After applyFix true, produce a fresh git snapshot for resolve() (CAP-202).
   * When absent, the loop re-runs `rebind` / uses artifacts the host attached on context.call.
   */
  resolveInput?: () => ResolveInput | Promise<ResolveInput>;
  resolveConfig?: ResolveConfig;
};

function iso(): string {
  return new Date().toISOString();
}

function emit(config: GuardConfig, e: GuardEvent): void {
  if (config.onEvent) {
    try { config.onEvent(e); } catch { /* onEvent never throws out */ }
  }
}

export function clampMaxAttempts(n: unknown): number {
  const v = typeof n === 'number' ? n : Number(n);
  if (!Number.isFinite(v)) return 0;
  const i = Math.floor(v);
  if (i < 1) return 0;
  return i > AUTO_RECHECK_MAX_CAP ? AUTO_RECHECK_MAX_CAP : i;
}

export function normalizeAutoRecheck(raw: unknown): AutoRecheckConfig | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Partial<AutoRecheckConfig>;
  if (typeof o.applyFix !== 'function') return null;
  const maxAttempts = clampMaxAttempts(o.maxAttempts);
  if (maxAttempts < 1) return null;
  const cfg: AutoRecheckConfig = { maxAttempts, applyFix: o.applyFix };
  if (typeof o.resolveInput === 'function') cfg.resolveInput = o.resolveInput;
  if (o.resolveConfig && typeof o.resolveConfig === 'object') cfg.resolveConfig = o.resolveConfig;
  return cfg;
}

function envelopeOf(outcome: GuardOutcome<unknown>): DecisionResultEnvelope | null {
  const v = outcome.verdict as GuardVerdict;
  if (v && 'envelope' in v && v.envelope && typeof v.envelope === 'object') {
    return v.envelope;
  }
  return null;
}

function fingerprintOf(outcome: GuardOutcome<unknown>): string | null {
  const env = envelopeOf(outcome);
  if (env && typeof env.fingerprint === 'string' && env.fingerprint) return env.fingerprint;
  const fp = outcome.proof && outcome.proof.binds_to && outcome.proof.binds_to.change_fp;
  return typeof fp === 'string' && fp ? fp : null;
}

function decisionIdOf(outcome: GuardOutcome<unknown>): string | null {
  const env = envelopeOf(outcome);
  if (env && typeof env.decision_id === 'string' && env.decision_id) return env.decision_id;
  const id = outcome.proof && outcome.proof.decision_id;
  return typeof id === 'string' && id ? id : null;
}

function executionActionOf(outcome: GuardOutcome<unknown>): string | null {
  const v = outcome.verdict as GuardVerdict;
  if (v && 'action' in v && typeof v.action === 'string') return v.action;
  return null;
}

function isAllowClass(outcome: GuardOutcome<unknown>): boolean {
  const v = outcome.verdict as GuardVerdict;
  if (!v || typeof v !== 'object') return false;
  // Kind only — UnavailableVerdict can carry action CONTINUE / CONTINUE_WITH_MONITORING
  // on OPEN_PASSTHROUGH / LKG_SUBSTITUTION; that is not allow-class.
  return v.kind === 'ALLOW' || v.kind === 'MONITOR';
}

function isBlockWithRemediation(outcome: GuardOutcome<unknown>): RemediationTransactionView | null {
  const v = outcome.verdict as GuardVerdict;
  if (!v || v.kind !== 'BLOCK') return null;
  return readRemediationTransaction(envelopeOf(outcome));
}

function trailEntry(outcome: GuardOutcome<unknown>, attempt: number): RecheckTrailEntry {
  return Object.freeze({
    attempt,
    decision_id: decisionIdOf(outcome),
    fingerprint: fingerprintOf(outcome),
    execution_action: executionActionOf(outcome),
  });
}

function attachObservation<T>(
  outcome: GuardOutcome<T>,
  trail: RecheckTrailEntry[],
  extras: { stop?: RecheckStopReason; fixed?: boolean },
): GuardOutcome<T> {
  const frozenTrail = Object.freeze(trail.map((e) => Object.freeze({ ...e })));
  const proof = Object.freeze({
    ...outcome.proof,
    recheck_trail: frozenTrail,
  });
  const obs: RecheckObservation = { recheck_trail: frozenTrail };
  if (extras.stop) obs.recheck_stop_reason = extras.stop;
  const recheckCount = Math.max(0, trail.length - 1);
  if (extras.fixed === true) {
    obs.fixed_after_block = { value: true, attempt_count: recheckCount };
  } else if (trail.length > 0) {
    obs.fixed_after_block = { value: null, attempt_count: recheckCount > 0 ? recheckCount : null };
  }
  return { ...outcome, proof, ...obs };
}

/**
 * Keep T2's hashed artifacts and the factory's arguments.artifacts the same array.
 * wrapWithGuard executes `redacted.arguments`; a descriptor that preflights ART_FIXED
 * while arguments still hold the BLOCK-era payload would authorize one change set and
 * apply another.
 */
function withFreshArtifacts(call: ToolCallDescriptor, artifacts: Artifact[]): ToolCallDescriptor {
  const next: ToolCallDescriptor = { ...call, artifacts };
  const args = next.arguments;
  if (args && typeof args === 'object' && !Array.isArray(args)) {
    next.arguments = { ...(args as Record<string, unknown>), artifacts };
  }
  return next;
}

async function freshCall(
  cfg: AutoRecheckConfig,
  current: ToolCallDescriptor,
  rebind: () => ToolCallDescriptor | Promise<ToolCallDescriptor>,
  artifactsBeforeFix: Artifact[] | undefined,
): Promise<ToolCallDescriptor> {
  // Host-updated call first so applyFix mutations of arguments / filesTouched / diff survive.
  let next: ToolCallDescriptor = { ...current };

  if (typeof cfg.resolveInput === 'function') {
    const input = await cfg.resolveInput();
    const resolved = resolveArtifacts(input, cfg.resolveConfig);
    if (resolved.artifacts && resolved.artifacts.length > 0) {
      return withFreshArtifacts(next, resolved.artifacts as Artifact[]);
    }
  }

  const hostReplacedArtifacts = Array.isArray(current.artifacts)
    && current.artifacts !== artifactsBeforeFix;
  if (hostReplacedArtifacts) {
    return withFreshArtifacts(next, current.artifacts as Artifact[]);
  }

  const rebound = await Promise.resolve(rebind());
  if (Array.isArray(rebound.artifacts) && rebound.artifacts.length > 0) {
    return withFreshArtifacts(next, rebound.artifacts);
  }
  return next;
}

export type AutoRecheckLoopArgs<T> = {
  call: ToolCallDescriptor;
  factory: ExecuteFactory<T>;
  config: GuardConfig;
  callContext?: GuardToolCallContext;
  rebind: () => ToolCallDescriptor | Promise<ToolCallDescriptor>;
  /** Re-collect freshness VALUES from the FRESH call (full re-preflight). */
  refreshContext?: (call: ToolCallDescriptor) => Promise<GuardToolCallContext | undefined>;
};

/**
 * First call is always a normal guardToolCall. The loop runs only when autoRecheck is
 * normalized (applyFix present, maxAttempts in 1–3) AND the outcome is BLOCK with a
 * remediation_transaction.
 */
export async function runAutoRecheckLoop<T>(args: AutoRecheckLoopArgs<T>): Promise<GuardOutcome<T>> {
  const cfg = normalizeAutoRecheck(args.config.autoRecheck);
  const first = await guardToolCall(args.call, args.factory, args.config, args.callContext);
  if (!cfg) return first;

  const remediation0 = isBlockWithRemediation(first);
  if (!remediation0) return first;

  const trail: RecheckTrailEntry[] = [trailEntry(first, 0)];
  let currentCall = args.call;
  let previous = first;
  let previousFp = fingerprintOf(first);
  let remediation = remediation0;

  for (let i = 1; i <= cfg.maxAttempts; i++) {
    const artifactsBeforeFix = currentCall.artifacts;
    const ctx: AutoRecheckApplyFixContext = {
      call: currentCall,
      attempt: i,
      outcome: previous as GuardOutcome<unknown>,
    };
    let applied = false;
    try {
      applied = (await cfg.applyFix(remediation, ctx)) === true;
    } catch {
      emit(args.config, {
        type: 'recheck_attempt',
        at: iso(),
        attempt: i,
        decisionId: decisionIdOf(previous) ?? undefined,
        from_fp: previousFp,
        to_fp: previousFp,
        cause: 'apply_fix_threw',
      });
      return attachObservation(first, trail, { stop: 'apply_fix_threw' });
    }
    if (!applied) {
      return attachObservation(first, trail, { stop: 'apply_fix_declined' });
    }

    currentCall = await freshCall(cfg, ctx.call, args.rebind, artifactsBeforeFix);
    const nextCtx = args.refreshContext
      ? await args.refreshContext(currentCall)
      : args.callContext;
    const next = await guardToolCall(currentCall, args.factory, args.config, nextCtx);
    const toFp = fingerprintOf(next);
    trail.push(trailEntry(next, i));
    emit(args.config, {
      type: 'recheck_attempt',
      at: iso(),
      attempt: i,
      decisionId: decisionIdOf(next) ?? undefined,
      from_fp: previousFp,
      to_fp: toFp,
    });

    // Same fingerprint as the previous attempt → no progress. Stop; last decision stands.
    if (previousFp != null && toFp != null && previousFp === toFp) {
      return attachObservation(next, trail, { stop: 'no_progress' });
    }

    if (isAllowClass(next)) {
      return attachObservation(next, trail, { fixed: true });
    }

    const remNext = isBlockWithRemediation(next);
    if (!remNext) {
      return attachObservation(next, trail, {});
    }

    previous = next;
    previousFp = toFp;
    remediation = remNext;
  }

  return attachObservation(previous, trail, { stop: 'exhausted' });
}
