/**
 * HTTP/API CAS adapter — ETag (If-Match) token discipline over host-injected I/O.
 *
 * Uses executeIfUnchanged (conditional-write.ts). Does not invent a parallel outcome shape.
 * Token format is opaque to the guard (string equality only).
 *
 * Token encoding (this adapter only; not interpreted by the core):
 *   api:v1:<raw_etag_or_version_header_value>
 * Missing / empty ETag → API_ABSENT_TOKEN.
 *
 * HONESTY: this adapter does NOT perform HTTP. The host callback MUST send If-Match (or
 * equivalent) itself. The adapter only normalizes tokens and maps the host-reported
 * {committed|precondition_failed} onto ExecuteIfUnchangedOutcome. Same class as
 * conditional_write_is_host_asserted_not_cas_verified — the package never claims it sent
 * the header.
 *
 * No fetch/undici — all I/O is host-injected.
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
export const API_VERSION_TOKEN_PREFIX = 'api:v1:';

/**
 * Token used when the resource has no ETag / version header yet (or host reported null).
 * Hosts that measured absence should pass this as expected_token for create-if-absent CAS.
 */
export const API_ABSENT_TOKEN: VersionToken = 'api:v1:absent';

/**
 * Build a VersionToken from a host-supplied ETag or version-header value.
 * null / undefined / empty / whitespace-only → API_ABSENT_TOKEN.
 * Surrounding weak/strong quote marks are stripped once for stable equality.
 */
export function createApiVersionToken(
  etag: string | null | undefined,
): VersionToken {
  if (etag == null) return API_ABSENT_TOKEN;
  let s = String(etag).trim();
  if (s.length === 0) return API_ABSENT_TOKEN;
  // Strip one layer of optional W/ and quotes: W/"abc" → abc, "abc" → abc
  if (s.startsWith('W/') || s.startsWith('w/')) s = s.slice(2).trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    s = s.slice(1, -1);
  }
  if (s.length === 0) return API_ABSENT_TOKEN;
  return `${API_VERSION_TOKEN_PREFIX}${s}`;
}

/** Raw value embedded in an api:v1: token (for host If-Match headers). Absent → null. */
export function apiTokenRaw(token: VersionToken | null | undefined): string | null {
  if (typeof token !== 'string' || !token.startsWith(API_VERSION_TOKEN_PREFIX)) return null;
  if (token === API_ABSENT_TOKEN) return null;
  const raw = token.slice(API_VERSION_TOKEN_PREFIX.length);
  return raw.length > 0 ? raw : null;
}

/**
 * Host report after attempting a conditional write.
 * The host is responsible for sending If-Match / If-None-Match / equivalent.
 */
export type ApiHostWriteReport<T = unknown> =
  | {
      status: 'committed';
      /** New ETag after write when the server returned one; null/omit when unknown. */
      new_etag?: string | null;
      result?: T;
    }
  | {
      status: 'precondition_failed';
      /** Current ETag if the host observed one (e.g. from 412 body / re-GET); omit → null. */
      current_etag?: string | null;
    };

export type WriteApiIfUnchangedArgs<T = unknown> = {
  /** Token measured before the host decided to write (from createApiVersionToken). */
  expected_token: VersionToken;
  /**
   * Re-read the resource ETag (or equivalent version header).
   * Called by executeIfUnchanged before write and again after write when detect is on.
   */
  current_etag: () => string | null | Promise<string | null>;
  /**
   * Host performs the conditional HTTP write.
   * `if_match` is the raw expected ETag for the If-Match header (null when ABSENT).
   * Adapter does not send the request — host must.
   */
  write: (ctx: {
    if_match: string | null;
    expected_token: VersionToken;
  }) => ApiHostWriteReport<T> | Promise<ApiHostWriteReport<T>>;
  /**
   * Opt-in post-commit detection (default false — byte-identical when off).
   * Requires a meaningful intended post-ETag: when the host omits new_etag on success,
   * detection is a no-op (cannot know intended post state without inventing tokens).
   */
  detect_stale_during_commit?: boolean;
};

export type ApiWriteResult<T = unknown> = {
  new_etag: string | null;
  result: T | undefined;
};

/**
 * Conditional API write: re-read ETag; if token matches expected → host write with If-Match context.
 *
 * Mapping (host report → ExecuteIfUnchangedOutcome):
 *   committed (+ optional new_etag)     → committed (version_token = expected; result carries new_etag)
 *   precondition_failed (412 class)     → refused / stale_version_token
 *                                         current_token from current_etag when host supplied it,
 *                                         else null (no invented token)
 *
 * Missing new_etag on success: stored as null on result; detect_stale_during_commit is a no-op
 * unless new_etag is a non-empty string (honest — no ABSENT fabrication as "expected after").
 *
 * Wired through executeIfUnchanged — not a parallel path.
 */
export async function writeApiIfUnchanged<T = unknown>(
  args: WriteApiIfUnchangedArgs<T>,
): Promise<ExecuteIfUnchangedOutcome<ApiWriteResult<T>>> {
  const detect = args.detect_stale_during_commit === true;

  return executeIfUnchanged({
    expected_token: args.expected_token,
    current_token: async () => createApiVersionToken(await args.current_etag()),
    detect_stale_during_commit: detect,
    expected_after_commit: detect
      ? async (written) => {
          if (typeof written.new_etag === 'string' && written.new_etag.trim().length > 0) {
            return createApiVersionToken(written.new_etag);
          }
          // No intended post-ETag: return live re-read so tokensEqual is tautological (detect no-op).
          return createApiVersionToken(await args.current_etag());
        }
      : undefined,
    write: async () => {
      const report = await args.write({
        if_match: apiTokenRaw(args.expected_token),
        expected_token: args.expected_token,
      });
      if (!report || typeof report !== 'object') {
        throw new Error('writeApiIfUnchanged: host write must return ApiHostWriteReport');
      }
      if (report.status === 'precondition_failed') {
        const cur =
          report.current_etag !== undefined
            ? createApiVersionToken(report.current_etag)
            : null;
        throw new StaleVersionTokenAbort(cur);
      }
      if (report.status !== 'committed') {
        throw new Error(
          `writeApiIfUnchanged: unknown host report status ${String((report as { status?: unknown }).status)}`,
        );
      }
      const new_etag =
        report.new_etag === undefined || report.new_etag === null
          ? null
          : String(report.new_etag);
      return {
        new_etag,
        result: report.result,
      };
    },
  });
}

/** Re-export equality helper for hosts comparing tokens without importing core module. */
export { tokensEqual };
