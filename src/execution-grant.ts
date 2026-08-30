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
   *
   * ── DEPRECATED ALIASES (1198) ────────────────────────────────────────────
   * The canonical home is the TOP LEVEL of the withCodeRifts input, where
   * executorId/adapterId/targetUri already lived before this config existed
   * (with-coderifts.ts:394-396) and where the ATOMIC construction check reads
   * them. Setting them here still works and still reaches the wire — but a
   * value here that DISAGREES with the top level is an initialization error,
   * because the two used to feed different halves of the system with nothing
   * reconciling them. See resolveV2Fields.
   *
   * Unreleased when this was written — added after the 14.1.0 release and never
   * published — so no adopter depends on the nested spelling.
   */
  executorId?: string;
  adapterId?: string;
  targetUri?: string;
  tenantId?: string;
  policyHash?: string;
  audienceHash?: string;
};

/**
 * THE CANONICAL V2 FIELD SET (roadmap 1198).
 *
 * MEASURED SPLIT-BRAIN, which is what this exists to end:
 *   · executorId / adapterId / targetUri lived in BOTH the top-level input
 *     (with-coderifts.ts:394-396 → the ATOMIC construction check and the
 *     posture tuple) and the nested executionGrant config (→ the authorize
 *     request). Nothing compared them, so a configuration could bind the
 *     profile to one executor and put another — or none — on the wire.
 *   · policyHash had a READER and no writer: atomic-profile.ts:247 passes
 *     `input.policyHash` to the posture verifier and with-coderifts.ts:911-915
 *     never forwarded it, so that binding was permanently undefined.
 *   · tenantId / audienceHash existed on the wire side only.
 *
 * This reads both spellings, REFUSES a disagreement, and returns one set that
 * the wire and the profile both use. A field neither side supplies stays
 * genuinely absent — the case 6bca531's named-absent was written for, and now
 * the only case it covers.
 */
export const V2_FIELD_KEYS = Object.freeze([
  'executorId', 'adapterId', 'targetUri', 'tenantId', 'policyHash', 'audienceHash',
] as const);

export type V2FieldKey = typeof V2_FIELD_KEYS[number];
export type V2Fields = Partial<Record<V2FieldKey, string>>;

/**
 * Resolve the canonical set from an input carrying either spelling.
 *
 * THROWS on disagreement. Preferring one silently is what produced the split:
 * a caller who set both would have one quietly ignored, with no way to see
 * which one survived.
 */
export function resolveV2Fields(input?: {
  executorId?: unknown;
  adapterId?: unknown;
  targetUri?: unknown;
  tenantId?: unknown;
  policyHash?: unknown;
  audienceHash?: unknown;
  executionGrant?: ExecutionGrantConfig | null;
} | null): V2Fields {
  const top = (input || {}) as Record<string, unknown>;
  const nested = ((input && input.executionGrant) || {}) as Record<string, unknown>;
  const out: V2Fields = {};
  const conflicts: string[] = [];

  for (const key of V2_FIELD_KEYS) {
    const t = typeof top[key] === 'string' && (top[key] as string).length > 0
      ? (top[key] as string) : undefined;
    const n = typeof nested[key] === 'string' && (nested[key] as string).length > 0
      ? (nested[key] as string) : undefined;

    if (t !== undefined && n !== undefined && t !== n) {
      conflicts.push(`  ${key}: top-level ${JSON.stringify(t)} vs executionGrant.${key} ${JSON.stringify(n)}`);
      continue;
    }
    const v = t !== undefined ? t : n;
    if (v !== undefined) out[key] = v;
  }

  if (conflicts.length > 0) {
    const err = new Error(
      'withCodeRifts: the V2 identity fields are configured in two places and they disagree.\n'
      + `${conflicts.join('\n')}\n\n`
      + 'These feed DIFFERENT halves of the system — the top level binds the ATOMIC construction '
      + 'check and the posture receipt, the executionGrant copy goes on the authorize request — so '
      + 'a disagreement builds a grant against one identity and verifies against another. Set each '
      + 'field ONCE, at the top level; the executionGrant spelling is a deprecated alias.',
    );
    (err as Error & { code: string }).code = 'V2_FIELDS_CONFLICT';
    throw err;
  }
  return out;
}

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
  // ONE SOURCE. Reading `config.executionGrant` directly here was half of the
  // 1198 split: the profile read the top level and the wire read the nested
  // copy, and a value set only at the top level never left the process.
  const resolved = resolveV2Fields(config as Parameters<typeof resolveV2Fields>[0]);
  for (const [wire, key] of V2_WIRE_FIELDS) {
    const v = resolved[key as V2FieldKey];
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
