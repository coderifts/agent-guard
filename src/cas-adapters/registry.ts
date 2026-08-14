/**
 * Registry compareAndSwap CAS adapter — opaque registry/version token discipline over host-injected I/O.
 *
 * Uses executeIfUnchanged (conditional-write.ts). Does not invent a parallel outcome shape.
 * Token format is opaque to the guard (string equality only).
 *
 * Token encoding (this adapter only; not interpreted by the core):
 *   registry:v1:<host_registry_token>
 * Missing / empty token → REGISTRY_ABSENT_TOKEN.
 *
 * HONESTY: this adapter never talks to a registry client. The host callback performs
 * compareAndSwap(expected, newValue) (or equivalent) and reports {swapped|conflict}.
 * The adapter only normalizes tokens and maps the report onto ExecuteIfUnchangedOutcome.
 *
 * No registry SDKs — all I/O is host-injected.
 */

'use strict';

import {
  executeIfUnchanged,
  StaleVersionTokenAbort,
  tokensEqual,
  type ExecuteIfUnchangedOutcome,
  type VersionToken,
} from '../conditional-write.js';

/** Prefix for this adapter's opaque tokens (equality-only outside this module). */
export const REGISTRY_VERSION_TOKEN_PREFIX = 'registry:v1:';

/**
 * Token used when the registry key is absent / unversioned.
 * Hosts that measured absence should pass this as expected_token for first put.
 */
export const REGISTRY_ABSENT_TOKEN: VersionToken = 'registry:v1:absent';

/**
 * Build a VersionToken from a host registry revision / generation / etag-like value.
 * null / undefined / empty → REGISTRY_ABSENT_TOKEN.
 */
export function createRegistryVersionToken(
  token: string | number | bigint | null | undefined,
): VersionToken {
  if (token == null) return REGISTRY_ABSENT_TOKEN;
  if (typeof token === 'number' && !Number.isFinite(token)) return REGISTRY_ABSENT_TOKEN;
  const s = String(token).trim();
  if (s.length === 0) return REGISTRY_ABSENT_TOKEN;
  return `${REGISTRY_VERSION_TOKEN_PREFIX}${s}`;
}

/** Raw value embedded in a registry:v1: token (for host CAS APIs). Absent → null. */
export function registryTokenRaw(token: VersionToken | null | undefined): string | null {
  if (typeof token !== 'string' || !token.startsWith(REGISTRY_VERSION_TOKEN_PREFIX)) {
    return null;
  }
  if (token === REGISTRY_ABSENT_TOKEN) return null;
  const raw = token.slice(REGISTRY_VERSION_TOKEN_PREFIX.length);
  return raw.length > 0 ? raw : null;
}

/**
 * Host report after compareAndSwap (or equivalent).
 */
export type RegistryHostCasReport<T = unknown> =
  | {
      swapped: true;
      /** New registry token after successful swap; null/omit when unknown. */
      new_token?: string | number | bigint | null;
      result?: T;
    }
  | {
      swapped: false;
      /** Current token if observed on conflict; omit → null (no invented token). */
      current_token?: string | number | bigint | null;
    }
  | {
      status: 'committed';
      new_token?: string | number | bigint | null;
      result?: T;
    }
  | {
      status: 'conflict';
      current_token?: string | number | bigint | null;
    };

export type WriteRegistryIfUnchangedArgs<T = unknown> = {
  /** Token measured before the host decided to write (from createRegistryVersionToken). */
  expected_token: VersionToken;
  /** Re-read the registry key's current token. Pre-write and post-write when detect is on. */
  current_token: () =>
    | string
    | number
    | bigint
    | null
    | Promise<string | number | bigint | null>;
  /**
   * Host compareAndSwap. Receives the raw expected token for the CAS call.
   * Adapter does not invoke any registry client.
   */
  compareAndSwap: (ctx: {
    expected: string | null;
    expected_token: VersionToken;
  }) => RegistryHostCasReport<T> | Promise<RegistryHostCasReport<T>>;
  /**
   * Opt-in post-commit detection (default false).
   * When host omits new_token on success, detection is a no-op.
   */
  detect_stale_during_commit?: boolean;
};

export type RegistryWriteResult<T = unknown> = {
  new_token: string | null;
  result: T | undefined;
};

function normalizeRegistryReport<T>(report: RegistryHostCasReport<T>): {
  kind: 'committed' | 'conflict';
  new_token?: string | number | bigint | null;
  current_token?: string | number | bigint | null;
  result?: T;
} {
  if (!report || typeof report !== 'object') {
    throw new Error('writeRegistryIfUnchanged: host compareAndSwap must return RegistryHostCasReport');
  }
  if ('swapped' in report) {
    if (report.swapped === true) {
      return { kind: 'committed', new_token: report.new_token, result: report.result };
    }
    return { kind: 'conflict', current_token: report.current_token };
  }
  if (report.status === 'committed') {
    return { kind: 'committed', new_token: report.new_token, result: report.result };
  }
  if (report.status === 'conflict') {
    return { kind: 'conflict', current_token: report.current_token };
  }
  throw new Error('writeRegistryIfUnchanged: unknown host report shape');
}

/**
 * Conditional registry write: re-read token; if matches → host compareAndSwap.
 *
 * Mapping (host report → ExecuteIfUnchangedOutcome):
 *   swapped:true / status:committed   → committed
 *   swapped:false / status:conflict   → refused / stale_version_token
 *                                       current_token from host when supplied, else null
 *
 * Wired through executeIfUnchanged — not a parallel path.
 */
export async function writeRegistryIfUnchanged<T = unknown>(
  args: WriteRegistryIfUnchangedArgs<T>,
): Promise<ExecuteIfUnchangedOutcome<RegistryWriteResult<T>>> {
  const detect = args.detect_stale_during_commit === true;

  return executeIfUnchanged({
    expected_token: args.expected_token,
    current_token: async () => createRegistryVersionToken(await args.current_token()),
    detect_stale_during_commit: detect,
    expected_after_commit: detect
      ? async (written) => {
          if (typeof written.new_token === 'string' && written.new_token.trim().length > 0) {
            return createRegistryVersionToken(written.new_token);
          }
          return createRegistryVersionToken(await args.current_token());
        }
      : undefined,
    write: async () => {
      const report = await args.compareAndSwap({
        expected: registryTokenRaw(args.expected_token),
        expected_token: args.expected_token,
      });
      const norm = normalizeRegistryReport(report);
      if (norm.kind === 'conflict') {
        const cur =
          norm.current_token !== undefined
            ? createRegistryVersionToken(norm.current_token)
            : null;
        throw new StaleVersionTokenAbort(cur);
      }
      const new_token =
        norm.new_token === undefined || norm.new_token === null
          ? null
          : String(norm.new_token);
      return {
        new_token,
        result: norm.result,
      };
    },
  });
}

/** Re-export equality helper for hosts comparing tokens without importing core module. */
export { tokensEqual };
