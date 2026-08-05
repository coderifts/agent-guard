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
  DecisionResultEnvelope, UnavailableVerdict, Artifact,
} from './types.js';
import { builtinDetector } from './detector.js';
import { bindReceiptToEnvelope } from './receipt-binding.js';
import type { BindCause, VerifyReceiptResultLike } from './receipt-binding.js';
import { evaluateEnvelope } from './enforcement-gate.js';

// Per-config breaker state (time-window; not consecutive).
const breakers = new WeakMap<GuardConfig, { fails: number[] }>();

const nowMs = () => Date.now();
const iso = () => new Date().toISOString();

function emit(config: GuardConfig, e: GuardEvent): void {
  if (config.onEvent) { try { config.onEvent(e); } catch { /* onEvent never throws out */ } }
}

/**
 * Read host-owned previousReceipt once for this preflight. Does not store the result on config
 * or anywhere else — a getter may return a different value on the next call.
 */
function resolvePreviousReceipt(config: GuardConfig): string | undefined {
  const pr = config.previousReceipt;
  if (pr === undefined || pr === null) return undefined;
  let raw: unknown;
  if (typeof pr === 'function') {
    try { raw = pr(); } catch { return undefined; }
  } else {
    raw = pr;
  }
  if (typeof raw !== 'string') return undefined;
  const s = raw.trim();
  return s.length > 0 ? s : undefined;
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

/**
 * Verify the envelope's receipt AND bind it to THIS envelope (P0 substitution fix). Returns the
 * BRANDED envelope only when the receipt is valid, current, AND the LOCALLY-recomputed decision body
 * hash + fingerprint + operation/environment/audience scope all match. On a valid-but-unbound receipt
 * the `cause` is RECEIPT_ENVELOPE_MISMATCH; on a bad signature it is RECEIPT_UNVERIFIED. Fail-closed:
 * any mismatch returns { verified: null }.
 */
async function verifyEnvelope(
  config: GuardConfig,
  envelope: DecisionResultEnvelope | null,
): Promise<{ verified: ReceiptVerifiedEnvelope | null; cause?: BindCause }> {
  if (!envelope) return { verified: null };
  if (config.verifyReceipts === false) return { verified: null }; // opt-out => cannot brand => unenforceable + LKG unusable
  const token = envelope.receipt?.token;
  if (!token) return { verified: null };
  try {
    const r = await (config.client as unknown as {
      verifyReceipt(t: string): Promise<VerifyReceiptResultLike>;
    }).verifyReceipt(token);
    const bind = bindReceiptToEnvelope(
      envelope as unknown as Record<string, unknown>,
      r,
      { operation: config.operation, environment: config.environment, audience: config.audience },
    );
    if (bind.ok) return { verified: envelope as ReceiptVerifiedEnvelope };
    emit(config, { type: 'receipt_unverified', at: iso(), decisionId: envelope.decision_id, cause: bind.detail });
    return { verified: null, cause: bind.cause };
  } catch {
    // verification threw => treat as unverified (bad signature / transport)
    return { verified: null, cause: 'RECEIPT_UNVERIFIED' };
  }
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

/**
 * True iff at least one supplied artifact carries analyzable before/after content. A preflight
 * trigger with no such content cannot be analyzed by the server (an empty list comes back as an
 * opaque REQUEST_REJECTED), so the guard fails closed LOCALLY with MISSING_ARTIFACT_CONTENT instead.
 * Reads defensively — the caller's artifacts are untrusted runtime data.
 */
function hasAnalyzableContent(artifacts: Artifact[] | undefined): boolean {
  if (!Array.isArray(artifacts) || artifacts.length === 0) return false;
  return artifacts.some((a) => {
    if (!a || typeof a !== 'object') return false;
    const before = (a as { before?: unknown }).before;
    const after = (a as { after?: unknown }).after;
    return (typeof before === 'string' && before.length > 0) || (typeof after === 'string' && after.length > 0);
  });
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

  // MISSING_ARTIFACT_CONTENT — developer-adoption fail-closed (audit #1). The detector says a contract
  // change is happening (trigger:true) but the caller supplied NO analyzable content: no artifacts, or
  // artifacts without before/after. Sending an empty list to the server returns an opaque
  // REQUEST_REJECTED; instead fail closed LOCALLY with a clear, actionable cause so the developer knows
  // to pass artifacts:[{ id, type, before, after }]. The tool does NOT execute (fail-closed preserved).
  // This can only fire when preflight is genuinely required — a non-contract/readonly call already
  // returned via the SKIPPED path above. It is NOT a server-availability failure, so it does NOT trip
  // the breaker (a developer's missing content must not degrade the open-policy path for later calls).
  if (!hasAnalyzableContent(detection.artifacts)) {
    emit(config, { type: 'artifact_content_missing', at: iso(), cause: 'MISSING_ARTIFACT_CONTENT', signals: detection.signals });
    const count = (breakers.get(config)?.fails.length) ?? 0;
    const v = unavailableVerdict({ cause: 'MISSING_ARTIFACT_CONTENT', failPolicy, resolution: 'CLOSED', action: 'STOP' }, count);
    return blocked(v, false);
  }

  // config validation: lkg policy requires an LkgStore.
  if (failPolicy === 'lkg' && !config.lkg) {
    breakerRecord(config);
    return closedIntegrity(config, 'CONFIG_ERROR', failPolicy);
  }

  // build the preflight request from the detected artifacts.
  // previous_receipt: host-supplied only (GuardConfig.previousReceipt). Never hardcoded-undefined
  // forever — when the host provides a prior token (string or getter), thread it so the issuer can
  // hash it into the signed `prev` slot. The guard does not retain or advance the value.
  const request = {
    artifacts: detection.artifacts,
    context: { operation: config.operation ?? 'tool_call', environment: config.environment, audience: config.audience },
    previous_receipt: resolvePreviousReceipt(config),
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

  const bindResult = await verifyEnvelope(config, envelope);
  const verified = bindResult.verified;
  const receiptVerified = !!verified;
  if (!receiptVerified) emit(config, { type: 'receipt_unverified', at: iso(), decisionId: envelope.decision_id });
  emit(config, { type: 'preflight_result', at: iso(), action: rd.executionAction, decisionId: envelope.decision_id });

  // A receipt that fails to verify OR fails to BIND to this envelope (P0 substitution/replay/scope) is
  // an INTEGRITY attack signal => fail closed. RECEIPT_ENVELOPE_MISMATCH names a valid-but-unbound
  // receipt (e.g. a real BLOCK receipt wrapped in a forged ALLOW envelope); RECEIPT_UNVERIFIED a bad
  // signature. Both trip the breaker and STOP — the guard NEVER executes off an unbound receipt.
  if (config.verifyReceipts !== false && !receiptVerified && envelope.receipt?.token) {
    breakerRecord(config);
    return closedIntegrity(config, bindResult.cause ?? 'RECEIPT_UNVERIFIED', failPolicy);
  }

  // ── Client-side authorization gate (P0-b/c): mirror §106/§111/§115 before honoring any action. ──
  // A raw execution_action is NEVER trusted alone. The gate reconciles decision↔action (stricter
  // wins), honors safe_for_agent, fails closed on degraded, and binds the analyzed artifacts to what
  // we actually sent. Only an allow-class, safe, non-degraded, artifact-bound verdict is executable.
  const gate = evaluateEnvelope(pf.response, envelope as unknown as Record<string, unknown>, rd.executionAction, detection.artifacts);
  if (gate.verdict === 'fail-closed') {
    breakerRecord(config);
    return closedIntegrity(config, gate.cause, failPolicy);
  }
  if (gate.verdict === 'block-strict') {
    // A real (or stricter-reconciled) BLOCK / REQUIRE_APPROVAL — clean block; the factory never runs.
    return gate.decision === 'BLOCK'
      ? blocked({ kind: 'BLOCK', action: 'STOP', envelope, receiptVerified }, true)
      : blocked({ kind: 'APPROVAL', action: 'REQUEST_APPROVAL', envelope, receiptVerified }, true);
  }
  const kind = gate.kind; // 'ALLOW' | 'MONITOR' — allow-class, safe, non-degraded, artifact-bound.

  // An expired decision cannot be honored fresh => closed (integrity: wrong-time state).
  if (expired) { breakerRecord(config); return closedIntegrity(config, 'SCHEMA_INVALID', failPolicy); }

  // MONITOR gate: host must ASSERT monitoring is wired (monitoringSinkWired === true) AND supply
  // onEvent. Presence of a function alone is not enough — () => {} used to unlock this gate while
  // observing nothing. The package still cannot prove delivery; the declaration is a host claim.
  // Absent declaration = unwired (breaking for onEvent-only callers; closes the empty-callback hole).
  // Declared true without onEvent = contradiction → unwired (fail closed).
  const sinkWired = config.monitoringSinkWired === true && typeof config.onEvent === 'function';
  if (kind === 'MONITOR') {
    if (sinkWired) emit(config, { type: 'monitoring_required', at: iso(), decisionId: envelope.decision_id });
    else emit(config, { type: 'monitoring_unwired', at: iso(), decisionId: envelope.decision_id });
  }

  // observeOnly is an EXPLICIT report-only opt-in: execute but never enforce (the one sanctioned
  // unenforced-execution mode alongside failPolicy=open; both are documented opt-ins, not the default).
  if (config.observeOnly) {
    emit(config, { type: 'observe_only_passthrough', at: iso(), action: rd.executionAction });
    const verdict: GuardVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified };
    return runUnenforced(config, executeFactory, envelope, verdict, true, redacted);
  }

  // ── enforced ⟺ executed INVARIANT (contract-triggering path): execute ONLY when we can ENFORCE. ──
  // enforceable = a bound-verified receipt AND (MONITOR) a wired sink. Anything else FAILS CLOSED —
  // the guard NEVER runs the factory unenforced on a contract change. Closes CE-EP-06 (no receipt),
  // CE-EP-08 (verifyReceipts:false), CE-CC-04 (MONITOR without a monitoring sink).
  const enforceable = receiptVerified && (kind === 'ALLOW' || sinkWired);
  if (enforceable) {
    const approved: ApprovedVerdict = kind === 'ALLOW'
      ? { kind: 'ALLOW', action: 'CONTINUE', envelope, receiptVerified: true }
      : { kind: 'MONITOR', action: 'CONTINUE_WITH_MONITORING', envelope, receiptVerified: true };
    return runEnforced(config, executeFactory, approved, redacted);
  }
  breakerRecord(config);
  return closedIntegrity(config, receiptVerified ? 'MONITORING_UNWIRED' : 'RECEIPT_MISSING', failPolicy);
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
  // Receipt verification + BINDING is UNCONDITIONAL for LKG (verifyReceipts:false => cannot brand =>
  // unusable). An LKG envelope whose receipt does not bind to it (substitution) is also unusable.
  const { verified } = await verifyEnvelope(config, cached);
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
