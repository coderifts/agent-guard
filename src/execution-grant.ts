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
};

export type ExecutionGrantObservation = {
  requested: boolean;
  arrived: boolean;
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
