/**
 * Database optimistic-lock CAS adapter — version-column / rowversion discipline over host-injected I/O.
 *
 * Uses executeIfUnchanged (conditional-write.ts). Does not invent a parallel outcome shape.
 * Token format is opaque to the guard (string equality only).
 *
 * Token encoding (this adapter only; not interpreted by the core):
 *   db:v1:<version_column_value>
 * Missing / empty version → DB_ABSENT_TOKEN.
 *
 * HONESTY: this adapter never composes SQL and never opens a connection. The host callback
 * performs the UPDATE … WHERE version = $expected (or equivalent) and reports rows_affected
 * or an explicit committed/conflict shape. Same honesty class as host-asserted conditional write.
 *
 * No pg/mysql/sqlite drivers — all I/O is host-injected.
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
export const DB_VERSION_TOKEN_PREFIX = 'db:v1:';

/**
 * Token used when the row has no version yet (insert path) or host reported null.
 * Hosts that measured absence should pass this as expected_token for first write.
 */
export const DB_ABSENT_TOKEN: VersionToken = 'db:v1:absent';

/**
 * Build a VersionToken from a host-read version column / rowversion / xmin-style value.
 * null / undefined / empty → DB_ABSENT_TOKEN. Numbers are stringified (no format invention).
 */
export function createDbVersionToken(
  version: string | number | bigint | null | undefined,
): VersionToken {
  if (version == null) return DB_ABSENT_TOKEN;
  if (typeof version === 'number' && !Number.isFinite(version)) return DB_ABSENT_TOKEN;
  const s = String(version).trim();
  if (s.length === 0) return DB_ABSENT_TOKEN;
  return `${DB_VERSION_TOKEN_PREFIX}${s}`;
}

/** Raw version embedded in a db:v1: token (for host SQL bind params). Absent → null. */
export function dbTokenRaw(token: VersionToken | null | undefined): string | null {
  if (typeof token !== 'string' || !token.startsWith(DB_VERSION_TOKEN_PREFIX)) return null;
  if (token === DB_ABSENT_TOKEN) return null;
  const raw = token.slice(DB_VERSION_TOKEN_PREFIX.length);
  return raw.length > 0 ? raw : null;
}

/**
 * Host report after attempting an optimistic-lock write.
 * Prefer rows_affected (UPDATE … WHERE version = $expected) or explicit committed/conflict.
 */
export type DbHostWriteReport<T = unknown> =
  | {
      status: 'committed';
      /** Version after write when the host can report it; null/omit when unknown. */
      new_version?: string | number | bigint | null;
      result?: T;
    }
  | {
      /** Optimistic lock lost — zero rows updated. */
      status: 'conflict';
      /** Current version if the host re-read it; omit → null (no invented token). */
      current_version?: string | number | bigint | null;
    }
  | {
      /**
       * Alternate committed shape: rows_affected > 0 means committed.
       * rows_affected === 0 means conflict (mapped to refused).
       */
      rows_affected: number;
      new_version?: string | number | bigint | null;
      result?: T;
    };

export type WriteDbIfUnchangedArgs<T = unknown> = {
  /** Token measured before the host decided to write (from createDbVersionToken). */
  expected_token: VersionToken;
  /** Re-read the row version column. Called pre-write and post-write when detect is on. */
  current_version: () =>
    | string
    | number
    | bigint
    | null
    | Promise<string | number | bigint | null>;
  /**
   * Host performs the optimistic-lock mutation (SQL/query builder — never composed here).
   * Receives the raw expected version for the WHERE clause bind.
   */
  write: (ctx: {
    expected_version: string | null;
    expected_token: VersionToken;
  }) => DbHostWriteReport<T> | Promise<DbHostWriteReport<T>>;
  /**
   * Opt-in post-commit detection (default false).
   * When host omits new_version on success, detection is a no-op (cannot know intended post state).
   */
  detect_stale_during_commit?: boolean;
};

export type DbWriteResult<T = unknown> = {
  new_version: string | null;
  result: T | undefined;
  rows_affected?: number;
};

function normalizeDbReport<T>(report: DbHostWriteReport<T>): {
  kind: 'committed' | 'conflict';
  new_version: string | number | bigint | null | undefined;
  current_version?: string | number | bigint | null;
  result?: T;
  rows_affected?: number;
} {
  if ('rows_affected' in report && typeof (report as { rows_affected?: unknown }).rows_affected === 'number') {
    const r = report as {
      rows_affected: number;
      new_version?: string | number | bigint | null;
      result?: T;
    };
    if (r.rows_affected === 0) {
      return {
        kind: 'conflict',
        new_version: undefined,
        current_version: undefined,
        rows_affected: 0,
      };
    }
    return {
      kind: 'committed',
      new_version: r.new_version,
      result: r.result,
      rows_affected: r.rows_affected,
    };
  }
  if ('status' in report && (report as { status?: string }).status === 'conflict') {
    const r = report as {
      status: 'conflict';
      current_version?: string | number | bigint | null;
    };
    return {
      kind: 'conflict',
      new_version: undefined,
      current_version: r.current_version,
    };
  }
  if ('status' in report && (report as { status?: string }).status === 'committed') {
    const r = report as {
      status: 'committed';
      new_version?: string | number | bigint | null;
      result?: T;
    };
    return {
      kind: 'committed',
      new_version: r.new_version,
      result: r.result,
    };
  }
  throw new Error('writeDbIfUnchanged: host write must return DbHostWriteReport');
}

/**
 * Conditional DB write: re-read version; if token matches → host optimistic-lock write.
 *
 * Mapping (host report → ExecuteIfUnchangedOutcome):
 *   committed / rows_affected > 0     → committed
 *   conflict / rows_affected === 0    → refused / stale_version_token
 *                                       current_token from current_version when supplied,
 *                                       else null (no invented token)
 *
 * Wired through executeIfUnchanged — not a parallel path. Never composes SQL.
 */
export async function writeDbIfUnchanged<T = unknown>(
  args: WriteDbIfUnchangedArgs<T>,
): Promise<ExecuteIfUnchangedOutcome<DbWriteResult<T>>> {
  const detect = args.detect_stale_during_commit === true;

  return executeIfUnchanged({
    expected_token: args.expected_token,
    current_token: async () => createDbVersionToken(await args.current_version()),
    detect_stale_during_commit: detect,
    expected_after_commit: detect
      ? async (written) => {
          if (typeof written.new_version === 'string' && written.new_version.trim().length > 0) {
            return createDbVersionToken(written.new_version);
          }
          return createDbVersionToken(await args.current_version());
        }
      : undefined,
    write: async () => {
      const report = await args.write({
        expected_version: dbTokenRaw(args.expected_token),
        expected_token: args.expected_token,
      });
      const norm = normalizeDbReport(report);
      if (norm.kind === 'conflict') {
        const cur =
          norm.current_version !== undefined
            ? createDbVersionToken(norm.current_version)
            : null;
        throw new StaleVersionTokenAbort(cur);
      }
      const new_version =
        norm.new_version === undefined || norm.new_version === null
          ? null
          : String(norm.new_version);
      return {
        new_version,
        result: norm.result,
        rows_affected: norm.rows_affected,
      };
    },
  });
}

/** Re-export equality helper for hosts comparing tokens without importing core module. */
export { tokensEqual };
