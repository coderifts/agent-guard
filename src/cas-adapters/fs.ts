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
  const hash = createHash('sha256').update(buf).digest('hex');
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
 * If token moved → refused (stale_version_token); original file left intact; no partial leave-behind.
 * Wired through executeIfUnchanged — not a parallel path.
 */
export async function writeFileIfUnchanged(
  args: WriteFileIfUnchangedArgs,
): Promise<ExecuteIfUnchangedOutcome<{ path: string; bytes: number }>> {
  const target = path.resolve(args.path);
  const body = typeof args.content === 'string' ? Buffer.from(args.content, 'utf8') : args.content;

  return executeIfUnchanged({
    expected_token: args.expected_token,
    current_token: () => createFsVersionToken(target),
    write: async () => {
      const dir = path.dirname(target);
      await fsp.mkdir(dir, { recursive: true });
      const tmp = path.join(
        dir,
        `.coderifts-cas-${path.basename(target)}-${process.pid}-${randomBytes(6).toString('hex')}.tmp`,
      );
      try {
        await fsp.writeFile(tmp, body);
        // Atomic replace on same filesystem (POSIX rename; Windows overwrite where supported).
        await fsp.rename(tmp, target);
      } catch (err) {
        // Best-effort cleanup of temp — never leave partial target from failed rename.
        try {
          await fsp.unlink(tmp);
        } catch {
          /* ignore */
        }
        throw err;
      }
      return { path: target, bytes: body.length };
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
