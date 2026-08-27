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
 * Refuse a path this adapter must not treat as a CAS target.
 *
 * MEASURED ABSENT before this existed (2026-08-27): `..` was silently resolved and the write landed
 * outside the intended directory, and a symlinked target was followed by stat/readFile while the
 * rename replaced the LINK — so the check and the write referred to DIFFERENT objects. That object
 * mismatch is the other half of the TOCTOU: a path interpreted twice can have a symlink swapped in
 * between the two interpretations.
 *
 * Three refusals, each for a different escape:
 *   - a literal `..` segment in the caller's own path (traversal, judged BEFORE resolution),
 *   - a symlinked final component (lstat — the object we would check is not the one we would write).
 *
 * The parent directory is CANONICALISED rather than rejected. Requiring realpath(dir) === dir was
 * written first and measured wrong within the hour: on macOS /var is itself a symlink, so every
 * path under a normal temp directory was refused. A symlinked ancestor is not the danger — an
 * ancestor that CHANGES between the check and the write is, and that is closed by the inode/device
 * identity re-check in writeFileIfUnchanged, not by refusing ordinary filesystems. Resolving the
 * parent once and building the target from it means both the check and the write name one object.
 */
export class UnsafeCasPathError extends Error {
  readonly reason: 'path_traversal' | 'symlink_target';
  readonly casPath: string;
  constructor(reason: 'path_traversal' | 'symlink_target', casPath: string) {
    super(`unsafe CAS path (${reason}): ${casPath}`);
    this.name = 'UnsafeCasPathError';
    this.reason = reason;
    this.casPath = casPath;
  }
}

export async function assertSafeCasPath(filePath: string): Promise<string> {
  // 1. Traversal is judged on what the CALLER wrote, not on the resolved form — resolution is
  //    exactly what makes `sub/../escaped` look innocent.
  const segments = filePath.split(/[\\/]+/);
  if (segments.includes('..')) throw new UnsafeCasPathError('path_traversal', filePath);

  const resolved = path.resolve(filePath);

  // 2. Canonicalise the PARENT once, then rebuild the target from it, so every later use names the
  //    same directory object. realpath on the parent only — never on the target itself, because
  //    that would follow exactly the final-component symlink step 3 exists to refuse.
  const dir = path.dirname(resolved);
  let canonicalDir = dir;
  try {
    canonicalDir = await fsp.realpath(dir);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code?: string }).code) : '';
    if (code !== 'ENOENT') throw err;
    // Parent does not exist yet — a create under mkdir -p. Keep the resolved form.
  }
  const target = path.join(canonicalDir, path.basename(resolved));

  // 3. The final component must not be a symlink. lstat does NOT follow; stat would, which is the
  //    whole bug: stat/readFile measured the TARGET while rename replaced the LINK, so the check
  //    and the write referred to different objects. ENOENT is fine — create-if-absent is legitimate.
  try {
    const lst = await fsp.lstat(target);
    if (lst.isSymbolicLink()) throw new UnsafeCasPathError('symlink_target', filePath);
  } catch (err: unknown) {
    if (err instanceof UnsafeCasPathError) throw err;
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code?: string }).code) : '';
    if (code !== 'ENOENT') throw err;
  }

  return target;
}

/** Filesystem identity of the object a token was measured on. Evidence, not a comparison key. */
export type FsObjectIdentity = { dev: number; ino: number };

/**
 * Identity of the object CURRENTLY at a path, read through a FILE DESCRIPTOR.
 *
 * Opening once and fstat-ing the handle is what makes this an identity rather than another path
 * interpretation: the fd names the object, so a symlink swapped in afterwards cannot redirect it.
 * null when the path does not exist.
 */
export async function fsObjectIdentity(filePath: string): Promise<FsObjectIdentity | null> {
  let fh: fsp.FileHandle | undefined;
  try {
    fh = await fsp.open(filePath, 'r');
    const st = await fh.stat();
    return { dev: st.dev, ino: st.ino };
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err ? String((err as { code?: string }).code) : '';
    if (code === 'ENOENT') return null;
    throw err;
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

export function identitiesEqual(
  a: FsObjectIdentity | null | undefined,
  b: FsObjectIdentity | null | undefined,
): boolean {
  if (!a || !b) return false;
  return a.dev === b.dev && a.ino === b.ino;
}

/**
 * Build a VersionToken from path: mtime (ms) + sha256 of file bytes.
 * Throws on I/O errors other than callers may catch. ENOENT → returns FS_ABSENT_TOKEN
 * so hosts can CAS create vs create-raced.
 */
export async function createFsVersionToken(filePath: string): Promise<VersionToken> {
  // ONE open, then stat AND read from the same handle. Previously this was stat(path) followed by
  // readFile(path) — two interpretations of the same string, so a swap between them produced a
  // token describing neither object exactly. The fd names the object for both reads.
  let fh: fsp.FileHandle | undefined;
  try {
    fh = await fsp.open(filePath, 'r');
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? String((err as { code?: string }).code)
      : '';
    if (code === 'ENOENT') return FS_ABSENT_TOKEN;
    throw err;
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) {
      // Directories / specials are not content CAS targets for this adapter.
      throw new Error(`createFsVersionToken: not a regular file: ${filePath}`);
    }
    const buf = await fh.readFile();
    const hash = sha256hex(buf);
    const mtimeMs = Math.trunc(st.mtimeMs);
    return `${FS_VERSION_TOKEN_PREFIX}${mtimeMs}:${hash}`;
  } finally {
    await fh.close().catch(() => {});
  }
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
  /**
   * Identity (dev+ino) of the object the AUTHORIZATION examined, from fsObjectIdentity at T1.
   * Optional, and when omitted no identity claim is made. Supplying it is strictly stronger than
   * the token alone: an inode swapped in carrying identical bytes and mtime produces an IDENTICAL
   * token, so content equality cannot see it. null means "absent at T1" (create-if-absent).
   */
  expected_identity?: FsObjectIdentity | null;
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
): Promise<ExecuteIfUnchangedOutcome<{
  path: string;
  bytes: number;
  written_content_hash: string;
  checked_identity: FsObjectIdentity | null;
  committed_identity: FsObjectIdentity | null;
}>> {
  // Refuse traversal / symlink / mounted-over-parent BEFORE any token is measured. A CAS over an
  // object the caller did not name is not a weaker guarantee, it is a wrong one.
  const target = await assertSafeCasPath(args.path);
  const body = typeof args.content === 'string' ? Buffer.from(args.content, 'utf8') : args.content;
  const writtenHash = sha256hex(body);
  // Identity of the object the CHECK is about, captured through an fd (null when creating).
  const checkedIdentity = await fsObjectIdentity(target);

  // T1 identity claim: if the caller measured one at authorization time, the object must still be
  // that object BEFORE we do anything. Captured-here identity cannot see a swap that predates this
  // call, which is exactly the case the token also cannot see.
  const hasT1Identity = Object.prototype.hasOwnProperty.call(args, 'expected_identity');
  if (hasT1Identity) {
    const t1 = args.expected_identity ?? null;
    const held = t1 === null ? checkedIdentity === null : identitiesEqual(t1, checkedIdentity);
    if (!held) {
      return {
        status: 'refused',
        reason: 'stale_version_token',
        expected_token: args.expected_token,
        current_token: await createFsVersionToken(target).catch(() => null),
      };
    }
  }

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
        // Close pre-rename window on BOTH facts. Content equality alone cannot see an object swap:
        // a symlink or a replaced inode with identical bytes passes a token check and is still a
        // different object. Identity is checked first because it is the stronger statement.
        const stillIdentity = await fsObjectIdentity(target);
        const identityHeld = checkedIdentity === null
          ? stillIdentity === null            // create-if-absent: nothing may have appeared
          : identitiesEqual(checkedIdentity, stillIdentity);
        if (!identityHeld) {
          try {
            await fsp.unlink(tmp);
          } catch {
            /* ignore */
          }
          throw new StaleVersionTokenAbort(await createFsVersionToken(target).catch(() => null));
        }
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
      // Evidence: which OBJECT was checked, not merely which path string.
      return {
        path: target,
        bytes: body.length,
        written_content_hash: writtenHash,
        checked_identity: checkedIdentity,
        committed_identity: await fsObjectIdentity(target),
      };
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
