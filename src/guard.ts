/**
 * @coderifts/agent-guard — guardToolCall (the security-core control flow).
 *
 * Order (frozen spec): redactor(call) -> input_fingerprint on the redacted call -> detect ->
 * preflight (unless SKIPPED) -> decide -> executeFactory(envelope, redactedCall) IFF SKIPPED or
 * CONTINUE / CONTINUE_WITH_MONITORING (or observeOnly). Fail-closed on every unknown; INTEGRITY
 * causes always resolve CLOSED + trip the breaker; enforced:true only on a LIVE receipt-verified
 * ALLOW/MONITOR; LKG is dormant in v1 (binding fields absent => UNUSABLE => closed). onEvent never throws.
 */

import { createHash } from 'node:crypto';
import { readDecision } from '@coderifts/sdk';
import type {
  GuardConfig, GuardOutcome, GuardVerdict, ApprovedVerdict, UnavailableCause, AvailabilityCause,
  IntegrityCause, ToolCallDescriptor, ExecuteFactory, GuardEvent, ReceiptVerifiedEnvelope,
  DecisionResultEnvelope, UnavailableVerdict,
} from './types.js';
import { builtinDetector } from './detector.js';

// Per-config breaker state (time-window; not consecutive).
const breakers = new WeakMap<GuardConfig, { fails: number[] }>();

const nowMs = () => Date.now();
const iso = () => new Date().toISOString();

function emit(config: GuardConfig, e: GuardEvent): void {
  if (config.onEvent) { try { config.onEvent(e); } catch { /* onEvent never throws out */ } }
}

function fingerprint(call: ToolCallDescriptor): string {
  const canon = JSON.stringify({ toolName: call.toolName, arguments: call.arguments, artifacts: call.artifacts, filesTouched: call.filesTouched, diff: call.diff });
  return 'sha256:' + createHash('sha256').update(canon).digest('hex');
}

function breakerRecord(config: GuardConfig): void {
  let s = breakers.get(config); if (!s) { s = { fails: [] }; breakers.set(config, s); }
  s.fails.push(nowMs());
}
function breakerTripped(config: GuardConfig): boolean {
  const s = breakers.get(config); if (!s) return false;
  const win = config.breakerWindowMs ?? 60000;
  const t = nowMs();
  s.fails = s.fails.filter((x) => t - x < win);
  return s.fails.length >= (config.maxUnavailablePerWindow ?? 3);
}

function classifyError(err: unknown, config: GuardConfig): { cause: UnavailableCause; integrity: boolean } {
  const e = err as { name?: string; status?: number; code?: string; message?: string; body?: { status?: number } } | undefined;
  const name = e?.name;
  const status = e?.status ?? e?.body?.status;
  if (name === 'TimeoutError' || name === 'AbortError' || e?.code === 'ABORT_ERR') return { cause: 'TIMEOUT', integrity: false };
  if (status === 429 || name === 'RateLimitError') return { cause: 'RATE_LIMITED', integrity: false };
  if (status === 413) return { cause: 'PAYLOAD_TOO_LARGE', integrity: true };
  if (status === 422) return { cause: 'REQUEST_REJECTED', integrity: true };
  if (status === 400 || status === 401 || status === 409) return { cause: 'REQUEST_REJECTED', integrity: true };
  if (typeof status === 'number' && status >= 500) return { cause: 'SERVER_ERROR', integrity: false };
  if (name === 'TypeError' || /fetch failed|network|ENOTFOUND|ECONNREFUSED|EAI_AGAIN/i.test(String(e?.message))) return { cause: 'NETWORK', integrity: false };
  if (name === 'ApiError') return { cause: 'SERVER_ERROR', integrity: false };
  return { cause: 'INVALID_RESPONSE', integrity: true }; // unrecognized => integrity => closed
}

function withTimeout<R>(p: Promise<R>, ms: number): Promise<R> {
  return new Promise<R>((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error(`preflight timed out after ${ms}ms`), { name: 'TimeoutError' })), Math.max(1, ms));
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

async function preflightWithRetry(config: GuardConfig, request: unknown): Promise<{ ok: true; response: unknown } | { ok: false; cause: UnavailableCause; integrity: boolean }> {
  const retries = config.retries ?? 1;
  const timeoutMs = config.timeoutMs ?? 2000;
  const budget = config.totalBudgetMs ?? 4500;
  const start = nowMs();
  let last: { cause: UnavailableCause; integrity: boolean } = { cause: 'TIMEOUT', integrity: false };
  for (let attempt = 0; attempt <= retries; attempt++) {
    const remaining = budget - (nowMs() - start);
    if (remaining <= 0) return { ok: false, cause: 'TIMEOUT', integrity: false };
    try {
      const response = await withTimeout((config.client as { preflightChangeSet(r: unknown): Promise<unknown> }).preflightChangeSet(request), Math.min(timeoutMs, remaining));
      return { ok: true, response };
    } catch (err) {
      last = classifyError(err, config);
      if (last.integrity) return { ok: false, ...last }; // integrity: never retry
    }
  }
  return { ok: false, ...last };
}

/** Verify the envelope's receipt via the SDK. Returns the BRANDED envelope only when verified. */
async function verifyEnvelope(config: GuardConfig, envelope: DecisionResultEnvelope | null): Promise<ReceiptVerifiedEnvelope | null> {
  if (!envelope) return null;
  if (config.verifyReceipts === false) return null; // opt-out => cannot brand => unenforceable + LKG unusable
  const token = envelope.receipt?.token;
  if (!token) return null;
  try {
    const r = await (config.client as { verifyReceipt(t: string): Promise<{ valid?: boolean }> }).verifyReceipt(token);
    if (r && r.valid === true) return envelope as ReceiptVerifiedEnvelope;
  } catch { /* verification failure is handled as RECEIPT_UNVERIFIED by the caller */ }
  return null;
}

// ── Outcome builders (keep the discriminated union satisfied) ────────────────────
async function runEnforced<T>(config: GuardConfig, factory: ExecuteFactory<T>, approved: ApprovedVerdict, redacted: ToolCallDescriptor): Promise<GuardOutcome<T>> {
  emit(config, { type: 'execution_started', at: iso(), action: approved.action, decisionId: approved.envelope.decision_id });
  try {
    const result = await factory(approved.envelope, redacted);
    return { executionAttempted: true, executed: true, enforced: true, result, verdict: approved, preflighted: true };
  } catch (error) {
    emit(config, { type: 'factory_error', at: iso(), action: approved.action });
    return { executionAttempted: true, executed: false, enforced: true, error, verdict: approved, preflighted: true };
  }
}
async function runUnenforced<T>(config: GuardConfig, factory: ExecuteFactory<T>, envelope: DecisionResultEnvelope | null, verdict: GuardVerdict, preflighted: boolean, redacted: ToolCallDescriptor): Promise<GuardOutcome<T>> {
  emit(config, { type: 'execution_started', at: iso() });
  try {
    const result = await factory(envelope, redacted);
    return { executionAttempted: true, executed: true, enforced: false, result, verdict, preflighted };
  } catch (error) {
    emit(config, { type: 'factory_error', at: iso() });
    return { executionAttempted: true, executed: false, enforced: false, error, verdict, preflighted };
  }
}
function blocked<T>(verdict: GuardVerdict, preflighted: boolean): GuardOutcome<T> {
  return { executionAttempted: false, executed: false, enforced: false, verdict, preflighted };
}

type UvArm =
  | { cause: IntegrityCause; failPolicy: 'closed' | 'open' | 'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  | { cause: AvailabilityCause; failPolicy: 'closed' | 'open' | 'lkg'; resolution: 'CLOSED'; action: 'STOP' }
  | { cause: AvailabilityCause; failPolicy: 'open'; resolution: 'OPEN_PASSTHROUGH'; action: 'CONTINUE' }
  | { cause: AvailabilityCause; failPolicy: 'lkg'; resolution: 'LKG_SUBSTITUTION'; action: 'CONTINUE' | 'CONTINUE_WITH_MONITORING'; lkgEnvelope: ReceiptVerifiedEnvelope };

function unavailableVerdict(parts: UvArm, count: number): UnavailableVerdict {
  return { kind: 'UNAVAILABLE', decisionMissing: true, unavailableCount: count, ...parts };
}

export async function guardToolCall<T>(
  call: ToolCallDescriptor,
  executeFactory: ExecuteFactory<T>,
  config: GuardConfig,
): Promise<GuardOutcome<T>> {
  const failPolicy = config.failPolicy ?? 'closed';

  // 12. redactor runs FIRST; everything downstream uses the redacted descriptor.
  let redacted: ToolCallDescriptor;
  try {
    redacted = config.redactor ? config.redactor(call) : call;
  } catch {
    // A redactor throw is a CONFIG_ERROR (integrity) => closed.
    breakerRecord(config);
    return closedIntegrity(config, 'CONFIG_ERROR', failPolicy);
  }
  const inputFp = fingerprint(redacted); // used for LKG lookup (dormant in v1)

  // 8/9. detector is fail-safe but a THROW is a DETECTOR_ERROR (integrity) => closed.
  const detector = config.detector ?? builtinDetector;
  let detection;
  try {
    detection = detector.detect(redacted);
  } catch {
    breakerRecord(config);
    return closedIntegrity(config, 'DETECTOR_ERROR', failPolicy);
  }

  // requireExplicitArtifacts strict SKIP gate: suppress only when nonContract===true AND no signal.
  const suppressedByStrict = config.requireExplicitArtifacts === true && redacted.nonContract === true
    && (!detection.artifacts || detection.artifacts.length === 0) && detection.confident && !detection.trigger;

  // SKIPPED path: not a contract call => execute with enforced:false, preflighted:false.
  if (!detection.trigger || suppressedByStrict) {
    emit(config, { type: 'detection_skip', at: iso(), signals: detection.signals, detectorVersion: detector.version });
    const verdict: GuardVerdict = { kind: 'SKIPPED', reason: 'NOT_A_CONTRACT_CALL', signals: detection.signals, detectorVersion: detector.version };
    return runUnenforced(config, executeFactory, null, verdict, false, redacted);
  }

  // config validation: lkg policy requires an LkgStore.
  if (failPolicy === 'lkg' && !config.lkg) {
    breakerRecord(config);
    return closedIntegrity(config, 'CONFIG_ERROR', failPolicy);
  }

  // build the preflight request from the detected artifacts.
  const request = {
    artifacts: detection.artifacts,
    context: { operation: config.operation ?? 'tool_call', environment: config.environment, audience: config.audience },
    previous_receipt: undefined as string | undefined,
    idempotency_key: undefined as string | undefined,
  };

  // request-attributable payload cap => PAYLOAD_TOO_LARGE (integrity) => closed.
  const cap = config.maxPayloadBytes ?? 1_000_000;
  if (Buffer.byteLength(JSON.stringify(request), 'utf8') > cap) {
    breakerRecord(config);
    return closedIntegrity(config, 'PAYLOAD_TOO_LARGE', failPolicy);
  }

  emit(config, { type: 'preflight_start', at: iso() });
  const pf = await preflightWithRetry(config, request);

  if (!pf.ok) {
    // UNAVAILABLE. Integrity => always closed + breaker. Availability => failPolicy.
    breakerRecord(config);
    const count = (breakers.get(config)?.fails.length) ?? 1;
    if (pf.integrity) {
      emit(config, { type: 'breaker_tripped', at: iso(), cause: pf.cause });
      const v = unavailableVerdict({ cause: pf.cause as IntegrityCause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
      return blocked(v, false);
    }
    // availability
    const availCause = pf.cause as AvailabilityCause;
    if (failPolicy === 'open' && !breakerTripped(config)) {
      emit(config, { type: 'preflight_unavailable', at: iso(), cause: availCause, action: 'CONTINUE' });
      const v = unavailableVerdict({ cause: availCause, failPolicy: 'open', resolution: 'OPEN_PASSTHROUGH', action: 'CONTINUE' }, count);
      return runUnenforced(config, executeFactory, null, v, false, redacted);
    }
    if (failPolicy === 'lkg') {
      const lkg = await tryLkg(config, inputFp);
      if (lkg) {
        emit(config, { type: 'preflight_unavailable', at: iso(), cause: availCause, action: lkg.action });
        const v = unavailableVerdict({ cause: availCause, failPolicy: 'lkg', resolution: 'LKG_SUBSTITUTION', action: lkg.action, lkgEnvelope: lkg.envelope }, count);
        return runUnenforced(config, executeFactory, lkg.envelope, v, false, redacted); // LKG NEVER enforces
      }
      // LKG unusable (dormant in v1: binding fields absent) => closed.
    }
    if (breakerTripped(config)) emit(config, { type: 'breaker_tripped', at: iso(), cause: availCause });
    const v = unavailableVerdict({ cause: availCause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
    return blocked(v, false);
  }

  // We have a response. Read the decision (envelope-first) and verify the receipt.
  const rd = readDecision(pf.response);
  if (rd.reason === 'UNREADABLE_DECISION' || !rd.envelope) {
    // Schema-invalid / no envelope => integrity => closed.
    breakerRecord(config);
    return closedIntegrity(config, 'SCHEMA_INVALID', failPolicy);
  }
  const envelope = rd.envelope;

  // 5. expiry check before honoring any decision.
  const expired = isExpired(envelope);

  const verified = await verifyEnvelope(config, envelope);
  const receiptVerified = !!verified;
  if (!receiptVerified) emit(config, { type: 'receipt_unverified', at: iso(), decisionId: envelope.decision_id });
  emit(config, { type: 'preflight_result', at: iso(), action: rd.executionAction, decisionId: envelope.decision_id });

  // A bad signature (verifyReceipts on, token present, verify failed) is an INTEGRITY attack signal.
  if (config.verifyReceipts !== false && !receiptVerified && envelope.receipt?.token) {
    breakerRecord(config);
    return closedIntegrity(config, 'RECEIPT_UNVERIFIED', failPolicy);
  }

  const action = rd.executionAction;

  // Non-executable decisions.
  if (action === 'STOP') return blocked({ kind: 'BLOCK', action: 'STOP', envelope, receiptVerified }, true);
  if (action === 'REQUEST_APPROVAL') return blocked({ kind: 'APPROVAL', action: 'REQUEST_APPROVAL', envelope, receiptVerified }, true);

  // An expired decision cannot be honored fresh => closed (integrity: wrong-time state).
  if (expired) { breakerRecord(config); return closedIntegrity(config, 'SCHEMA_INVALID', failPolicy); }

  // Executable: CONTINUE (ALLOW) or CONTINUE_WITH_MONITORING (MONITOR).
  const kind = action === 'CONTINUE' ? 'ALLOW' : 'MONITOR';
  const sinkWired = !!config.onEvent; // v1: onEvent is the telemetry sink for MONITOR.
  if (kind === 'MONITOR') {
    if (sinkWired) emit(config, { type: 'monitoring_required', at: iso(), decisionId: envelope.decision_id });
    else emit(config, { type: 'monitoring_unwired', at: iso(), decisionId: envelope.decision_id });
  }

  // observeOnly executes but never enforces.
  if (config.observeOnly) {
    emit(config, { type: 'observe_only_passthrough', at: iso(), action });
    const verdict: GuardVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
    return runUnenforced(config, executeFactory, envelope, verdict, true, redacted);
  }

  // enforced:true requires a LIVE receipt-verified ALLOW/MONITOR, and (MONITOR) a wired sink.
  const enforceable = receiptVerified && (kind === 'ALLOW' || sinkWired);
  if (enforceable) {
    const approved: ApprovedVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified: true }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified: true };
    return runEnforced(config, executeFactory, approved, redacted);
  }
  // MONITOR with no sink (monitoring_unwired): execute but enforced:false.
  const verdict: GuardVerdict = kind === 'ALLOW'
    ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
    : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
  return runUnenforced(config, executeFactory, envelope, verdict, true, redacted);
}

function closedIntegrity<T>(config: GuardConfig, cause: IntegrityCause, failPolicy: 'closed' | 'open' | 'lkg'): GuardOutcome<T> {
  const count = (breakers.get(config)?.fails.length) ?? 1;
  emit(config, { type: 'breaker_tripped', at: iso(), cause });
  const v = unavailableVerdict({ cause, failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
  return blocked(v, false);
}

function isExpired(envelope: DecisionResultEnvelope): boolean {
  const exp = envelope.expires_at;
  if (typeof exp !== 'string') return false;
  const t = Date.parse(exp);
  return Number.isFinite(t) && t < Date.now();
}

/** LKG substitution attempt. Dormant in v1: binding fields (ruleset_hash/environment/operation/
 * audience) are absent from decision-result.v1, so any binding that cannot be evaluated => UNUSABLE. */
async function tryLkg(config: GuardConfig, inputFp: string): Promise<{ envelope: ReceiptVerifiedEnvelope; action: 'CONTINUE' | 'CONTINUE_WITH_MONITORING' } | null> {
  if (!config.lkg) return null;
  let cached: DecisionResultEnvelope | null;
  try { cached = await config.lkg.get(inputFp); } catch { return null; }
  if (!cached) return null;
  // Receipt verification is UNCONDITIONAL for LKG (with verifyReceipts:false it cannot brand => unusable).
  const verified = await verifyEnvelope(config, cached);
  if (!verified) return null;
  // Eligibility (rule 15): decision ALLOW|WARN, unexpired, age<lkgMaxAgeMs, fingerprint + ruleset_hash
  // + environment + operation + audience all match. Any binding that cannot be evaluated => UNUSABLE.
  const dec = (cached.decision as string) ?? '';
  if (dec !== 'ALLOW' && dec !== 'WARN') return null;
  if (isExpired(cached)) return null;
  const maxAge = config.lkgMaxAgeMs ?? 900000;
  const evalAt = Date.parse(cached.evaluated_at);
  if (Number.isFinite(evalAt) && Date.now() - evalAt > maxAge) return null;
  // Binding fields are NOT present in the frozen schema => cannot be evaluated => UNUSABLE (closed).
  const bindings: Array<unknown> = [
    (cached as unknown as Record<string, unknown>).ruleset_hash,
    (cached as unknown as Record<string, unknown>).environment,
    (cached as unknown as Record<string, unknown>).operation,
    (cached as unknown as Record<string, unknown>).audience,
  ];
  if (bindings.some((b) => b === undefined)) return null; // any absent binding => UNUSABLE => closed
  const action = dec === 'ALLOW' ? 'CONTINUE' : 'CONTINUE_WITH_MONITORING';
  return { envelope: verified, action };
}
