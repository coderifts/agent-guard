/**
 * Filesystem CAS adapter — mtime + content-hash VersionToken and atomic-rename write.
 *
 * Uses the host contract helper executeIfUnchanged (conditional-write.ts). Does not invent
 * a parallel outcome shape. Token format is opaque to the guard (string equality only).
 *
 * Token encoding (this adapter only; not interpreted by the core):
 *   fs:v1:<mtime_ms>:<sha256_hex_of_file_bytes>
 * Missing file → createFsVersionToken still works for "absent" via a dedicated absent token
 * only if we choose; for create we require the file to exist (ENOENT throws) so hosts
 * measure an existing prior. For write of new files, expected_token may be ABSENT_TOKEN.
 */

'use strict';

import { createHash, randomBytes } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  executeIfUnchanged,
  StaleVersionTokenAbort,
  tokensEqual,
  type ExecuteIfUnchangedOutcome,
  type VersionToken,
  type VersionedContent,
} from '../conditional-write.js';
import type { PriorContentResolver } from '../freshness.js';

/** Prefix for this adapter's opaque tokens (equality-only outside this module). */
export const FS_VERSION_TOKEN_PREFIX = 'fs:v1:';

/**
 * Token used when the path does not exist yet (create-if-absent CAS).
 * Hosts that measured absence should pass this as expected_token for first write.
 */
export const FS_ABSENT_TOKEN: VersionToken = 'fs:v1:absent';

function sha256hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/** Extract content-hash segment from an fs:v1 token (null if absent/malformed). */
export function fsTokenContentHash(token: VersionToken | null | undefined): string | null {
  if (typeof token !== 'string' || !token.startsWith(FS_VERSION_TOKEN_PREFIX)) return null;
  if (token === FS_ABSENT_TOKEN) return null;
  const rest = token.slice(FS_VERSION_TOKEN_PREFIX.length);
  const colon = rest.indexOf(':');
  if (colon < 0) return null;
  const hash = rest.slice(colon + 1);
  return /^[a-f0-9]{64}$/.test(hash) ? hash : null;
}

/**
 * Build a VersionToken from path: mtime (ms) + sha256 of file bytes.
 * Throws on I/O errors other than callers may catch. ENOENT → returns FS_ABSENT_TOKEN
 * so hosts can CAS create vs create-raced.
 */
export async function createFsVersionToken(filePath: string): Promise<VersionToken> {
  let st;
  try {
    st = await fsp.stat(filePath);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? String((err as { code?: string }).code)
      : '';
    if (code === 'ENOENT') return FS_ABSENT_TOKEN;
    throw err;
  }
  if (!st.isFile()) {
    // Directories / specials are not content CAS targets for this adapter.
    throw new Error(`createFsVersionToken: not a regular file: ${filePath}`);
  }
  const buf = await fsp.readFile(filePath);
  const hash = sha256hex(buf);
  const mtimeMs = Math.trunc(st.mtimeMs);
  return `${FS_VERSION_TOKEN_PREFIX}${mtimeMs}:${hash}`;
}

/**
 * Read file content + version token for VersionedContent (host reporting / preflight prior).
 * ENOENT → content '' and FS_ABSENT_TOKEN.
 */
export async function readVersionedFile(filePath: string): Promise<VersionedContent> {
  const version_token = await createFsVersionToken(filePath);
  if (version_token === FS_ABSENT_TOKEN) {
    return { content: '', version_token };
  }
  const content = await fsp.readFile(filePath, 'utf8');
  return { content, version_token };
}

export type WriteFileIfUnchangedArgs = {
  path: string;
  /** Token measured before the host decided to write (from createFsVersionToken). */
  expected_token: VersionToken;
  /** Full new file contents (utf8 string or Buffer). */
  content: string | Buffer;
};

/**
 * Conditional write: re-stat+re-hash; if token matches expected → temp file + atomic rename.
 *
 * MEASURED windows (pre-fix, 2fcd74e-era):
 *   1. executeIfUnchanged: current_token() then await write() — no re-check in between.
 *   2. write(): writeFile(tmp) then rename(tmp,target) with NO re-stat of target before rename
 *      (fs.ts former lines 106–108) — concurrent mutation of target is clobbered by rename.
 *
 * Closures:
 *   - Pre-rename: re-createFsVersionToken(target); on mismatch abort rename, unlink tmp,
 *     throw StaleVersionTokenAbort → refused/stale_version_token (write did not land).
 *   - Post-rename: detect_stale_during_commit — content-hash of path must match sha256(body);
 *     mismatch → committed_stale_detected (write landed; someone overwrote after rename).
 *
 * Wired through executeIfUnchanged — not a parallel path.
 */
export async function writeFileIfUnchanged(
  args: WriteFileIfUnchangedArgs,
): Promise<ExecuteIfUnchangedOutcome<{ path: string; bytes: number; written_content_hash: string }>> {
  const target = path.resolve(args.path);
  const body = typeof args.content === 'string' ? Buffer.from(args.content, 'utf8') : args.content;
  const writtenHash = sha256hex(body);

  return executeIfUnchanged({
    expected_token: args.expected_token,
    current_token: () => createFsVersionToken(target),
    detect_stale_during_commit: true,
    // Post-commit: token content-hash must equal sha256 of what we wrote (mtime may vary).
    expected_after_commit: async (result) => {
      // Synthesize a comparable token: re-read path; equality is content-hash based via tokensEqual
      // only if full token matches — mtime always changes on write, so we return the LIVE post
      // token only when its hash matches writtenHash; else return a sentinel that cannot match.
      const post = await createFsVersionToken(target);
      const postHash = fsTokenContentHash(post);
      if (postHash === result.written_content_hash) return post;
      // Force mismatch → committed_stale_detected (detection, not rollback).
      return `${FS_VERSION_TOKEN_PREFIX}0:stale_during_commit_mismatch`;
    },
    write: async () => {
      const dir = path.dirname(target);
      await fsp.mkdir(dir, { recursive: true });
      const tmp = path.join(
        dir,
        `.coderifts-cas-${path.basename(target)}-${process.pid}-${randomBytes(6).toString('hex')}.tmp`,
      );
      try {
        await fsp.writeFile(tmp, body);
        // Close pre-rename window: if target moved since the executeIfUnchanged check, do not clobber.
        const still = await createFsVersionToken(target);
        if (!tokensEqual(args.expected_token, still)) {
          try {
            await fsp.unlink(tmp);
          } catch {
            /* ignore */
          }
          throw new StaleVersionTokenAbort(still);
        }
        // Atomic replace on same filesystem (POSIX rename; Windows overwrite where supported).
        await fsp.rename(tmp, target);
      } catch (err) {
        if (err instanceof StaleVersionTokenAbort) throw err;
        // Best-effort cleanup of temp — never leave partial target from failed rename.
        try {
          await fsp.unlink(tmp);
        } catch {
          /* ignore */
        }
        throw err;
      }
      return { path: target, bytes: body.length, written_content_hash: writtenHash };
    },
  });
}

/**
 * Opt-in PriorContentResolver that reads a file path from tool arguments.
 * Returns file utf8 content for freshness measurement (string only — tokens travel separately
 * via versioned_content / conditioned_on_token on the call context).
 *
 * Plug-in: pass as GuardConfig.resolvePriorContent / withCodeRifts({ resolvePriorContent }).
 */
export function createFsPriorContentResolver(options?: {
  /**
   * Map artifactId → absolute or relative file path.
   * If omitted, uses req.path or arguments-style path when provided on the resolve request.
   */
  pathForArtifact?: (artifactId: string) => string | null | undefined;
}): PriorContentResolver {
  const pathForArtifact = options?.pathForArtifact;
  return async (req) => {
    let filePath: string | undefined =
      typeof req.path === 'string' && req.path.length > 0 ? req.path : undefined;
    if (!filePath && pathForArtifact) {
      const mapped = pathForArtifact(req.artifactId);
      if (typeof mapped === 'string' && mapped.length > 0) filePath = mapped;
    }
    if (!filePath) return null;
    try {
      return await fsp.readFile(filePath, 'utf8');
    } catch (err: unknown) {
      const code = err && typeof err === 'object' && 'code' in err
        ? String((err as { code?: string }).code)
        : '';
      if (code === 'ENOENT') return null;
      throw err;
    }
  };
}

/** Re-export equality helper for hosts comparing tokens without importing core module. */
export { tokensEqual };
