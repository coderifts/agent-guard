/**
 * Native execution-grant helpers (9.6.0).
 *
 * Grant request is per guardToolCall invocation (local vars). The token is not
 * a verdict input and is not folded into any fingerprint preimage.
 */

export type ExecutionGrantConfig = {
  enabled: true;
  resolveStateNonce?: (ctx: {
    artifactId: string | null;
    toolName: string;
    args: unknown;
  }) => string | Promise<string>;
  /** Default 'v1' this wave. ATOMIC construction requires 'v2'. */
  grantVersion?: 'v1' | 'v2';
  /**
   * The V2 binding a grant request should carry (AUDIT P1 / RES-1).
   *
   * MEASURED before adding: the guard's authorize request sent only
   * `include_execution_grant` and `state_nonce`, and the SDK's
   * PreflightChangeSetRequest declares NEITHER these fields NOR `state_nonce` —
   * the guard builds its own request literal and posts it as `unknown`, so the
   * wire shape is guard-local. Adding them here is therefore a guard-side
   * config surface, not a claim that the SDK type endorses them.
   *
   * Every one is OPTIONAL and every one is sent only when set. A deployment
   * that does not configure a field gets it NAMED in the observation's
   * `v2_fields_absent`, never a placeholder on the wire.
   */
  executorId?: string;
  adapterId?: string;
  targetUri?: string;
  tenantId?: string;
  policyHash?: string;
  audienceHash?: string;
};

/** The V2 request fields, in the wire spelling. One list, used to send and to report. */
export const V2_WIRE_FIELDS = Object.freeze([
  ['executor_id', 'executorId'],
  ['adapter_id', 'adapterId'],
  ['target_uri', 'targetUri'],
  ['tenant_id', 'tenantId'],
  ['policy_hash', 'policyHash'],
  ['audience_hash', 'audienceHash'],
] as const);

export type V2WireResult = {
  /** Wire-name -> value, for the fields this deployment actually configured. */
  fields: Record<string, string>;
  /** Wire-names this deployment did NOT configure. Named, never placeheld. */
  absent: string[];
};

/**
 * Build the V2 field set for an authorize request.
 *
 * V1 sends nothing here: the fields describe a v2 binding, and attaching them
 * to a v1 request would assert a shape the grant does not have.
 *
 * A value that is not a non-empty string is ABSENT, not empty-string-sent. An
 * empty executor_id on the wire is indistinguishable from a real one that
 * happens to be blank, and the server would bind it.
 */
export function v2WireFields(
  config: { executionGrant?: ExecutionGrantConfig } | null | undefined,
): V2WireResult {
  const g = config && config.executionGrant;
  const fields: Record<string, string> = {};
  const absent: string[] = [];
  if (!g || g.grantVersion !== 'v2') {
    return { fields, absent: V2_WIRE_FIELDS.map(([wire]) => wire) };
  }
  for (const [wire, key] of V2_WIRE_FIELDS) {
    const v = (g as Record<string, unknown>)[key];
    if (typeof v === 'string' && v.length > 0) fields[wire] = v;
    else absent.push(wire);
  }
  return { fields, absent };
}

export type ExecutionGrantObservation = {
  requested: boolean;
  arrived: boolean;
  /** Which grant shape was requested. */
  grant_version?: 'v1' | 'v2';
  /**
   * The V2 binding this request actually carried, and what it could not.
   * `v2_fields_absent` is the honest half: a field the deployment never
   * configured is reported here rather than sent as an empty placeholder.
   */
  v2_fields_sent?: string[];
  v2_fields_absent?: string[];
};

export type ExecutionGrantCallContext = {
  execution_grant: string | null;
};

export function isExecutionGrantEnabled(config: { executionGrant?: ExecutionGrantConfig } | null | undefined): boolean {
  return !!(config && config.executionGrant && config.executionGrant.enabled === true);
}

export function readExecutionGrantToken(response: unknown): string | null {
  if (!response || typeof response !== 'object') return null;
  const g = (response as { execution_grant?: unknown }).execution_grant;
  return typeof g === 'string' && g.length > 0 ? g : null;
}

export function firstArtifactId(artifacts: unknown): string | null {
  if (!Array.isArray(artifacts)) return null;
  for (const a of artifacts) {
    if (a && typeof a === 'object' && typeof (a as { id?: unknown }).id === 'string') {
      const id = String((a as { id: string }).id).trim();
      if (id) return id;
    }
  }
  return null;
}

/** True when the thrown authorize error carries the named SIGNER_UNAVAILABLE code. */
export function isSignerUnavailableError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: unknown; body?: { code?: unknown } };
  if (e.code === 'SIGNER_UNAVAILABLE') return true;
  if (e.body && e.body.code === 'SIGNER_UNAVAILABLE') return true;
  return false;
}

export async function resolveStateNonceForCall(
  config: { executionGrant?: ExecutionGrantConfig },
  call: { toolName: string; arguments?: unknown; artifacts?: unknown },
  artifacts: unknown,
): Promise<{ ok: true; nonce?: string } | { ok: false }> {
  const resolver = config.executionGrant && config.executionGrant.resolveStateNonce;
  if (typeof resolver !== 'function') return { ok: true };
  try {
    const raw = await resolver({
      artifactId: firstArtifactId(artifacts) || firstArtifactId(call.artifacts),
      toolName: call.toolName,
      args: call.arguments,
    });
    if (raw == null || raw === '') return { ok: true };
    if (typeof raw !== 'string') return { ok: false };
    return { ok: true, nonce: raw };
  } catch {
    return { ok: false };
  }
}
