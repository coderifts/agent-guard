/**
 * Default-wire helper for the FS CAS adapter.
 *
 * Only when the target AND the full-file body are unambiguously inferable
 * (`args.path` + `args.contents` / `args.content`, Write-style). Edit fragments
 * (`old_string`/`new_string`) are NOT a full-file write — leave those opt-in.
 * API / DB / registry adapters stay opt-in.
 *
 * This layer performs writeFileIfUnchanged (the FS adapter), not a token
 * pre-check around an unconditional host write — that would be a silent
 * `committed` claim.
 */
'use strict';

import { isExecuteIfUnchangedOutcome } from '../cas-attestation.js';
import type { ExecuteIfUnchangedOutcome } from '../conditional-write.js';
import type { VersionToken } from '../conditional-write.js';
import type { FsObjectIdentity } from './fs.js';
import { assertSafeCasPath, createFsVersionToken, fsObjectIdentity, writeFileIfUnchanged } from './fs.js';

/** Unambiguous fs target: a non-empty `path` string on tool arguments (Write convention). */
export function inferFsPathFromArgs(args: unknown): string | null {
  if (!args || typeof args !== 'object') return null;
  const path = (args as { path?: unknown }).path;
  if (typeof path !== 'string') return null;
  const trimmed = path.trim();
  if (!trimmed) return null;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return null;
  return trimmed;
}

/**
 * Full-file body for a Write-style tool. `contents` wins; `content` only when this
 * is not an Edit (no old_string/new_string). Fragments are not a whole-file CAS.
 */
export function inferFullFileWriteContent(args: unknown): string | null {
  if (!args || typeof args !== 'object') return null;
  const a = args as Record<string, unknown>;
  if (typeof a.contents === 'string') return a.contents;
  if (typeof a.content === 'string' && a.old_string == null && a.new_string == null) {
    return a.content;
  }
  return null;
}

/**
 * Options carrying the AUTHORIZATION-TIME measurement into the write.
 */
export type FsCasWireOptions = {
  /**
   * Token of the state the AUTHORIZATION examined, measured at T1 by the runner — before preflight,
   * not at write time. This is the whole fix: see the note on wrapWriteWithFsCas.
   */
  expected_token?: VersionToken | null;
  /** Identity (dev+ino) of that same T1 object. Catches an inode swap the token cannot see. */
  expected_identity?: FsObjectIdentity | null;
};

/** The pair a runner measures at T1. Both halves describe the SAME observation. */
export type FsAuthorizationMeasurement = {
  expected_token: VersionToken;
  expected_identity: FsObjectIdentity | null;
};

/**
 * Wire the FS adapter when path + full-file contents are both present.
 * Otherwise run the host write unchanged. If the host already returned an
 * ExecuteIfUnchangedOutcome, pass it through (do not wrap again).
 *
 * THE TOKEN MUST COME FROM T1. This function used to call createFsVersionToken HERE, inside
 * executeFactory — after preflight (T1) and after the T2 recheck — and then condition the write on
 * that self-fetched value. Measured on 12.0.0: with a writer landing between T2 and that read, the
 * CAS adopted the interfering state as its legitimate starting point and still reported
 * status:'committed' with enforced:true. It was a real check of a vacuous window — it asked whether
 * the state had changed since a read a microsecond earlier, which is a question whose answer is
 * always no and which says nothing about the state the authorization actually examined.
 *
 * Now the expected token is supplied by the caller from the T1 measurement. When it is ABSENT we do
 * NOT fall back to self-fetching, because that is precisely the vacuous claim: the write runs
 * unwrapped and the guarantee is NON_ATOMIC, which is the honest thing to report and which
 * requireConditionalWrite will refuse. A weaker guarantee is reportable; a false one is not.
 */
export async function wrapWriteWithFsCas<T>(
  args: unknown,
  write: () => Promise<T> | T,
  opts?: FsCasWireOptions,
): Promise<T | ExecuteIfUnchangedOutcome<unknown>> {
  const filePath = inferFsPathFromArgs(args);
  const content = inferFullFileWriteContent(args);
  const expected = opts && typeof opts.expected_token === 'string' ? opts.expected_token : null;

  if (filePath && content != null && expected !== null) {
    return writeFileIfUnchanged({
      path: filePath,
      expected_token: expected,
      content,
      ...(opts && 'expected_identity' in opts ? { expected_identity: opts.expected_identity ?? null } : {}),
    });
  }
  const raw = await write();
  if (isExecuteIfUnchangedOutcome(raw)) return raw;
  return raw;
}

/**
 * The T1 measurement itself — call this in the RUNNER, before preflight, and pass the result to
 * wrapWriteWithFsCas. Returns null when this call is not an inferable full-file FS write, or when
 * the path is unsafe / unreadable (a token we could not measure is not a token we may claim).
 */
export async function measureFsAuthorization(args: unknown): Promise<FsAuthorizationMeasurement | null> {
  const filePath = inferFsPathFromArgs(args);
  const content = inferFullFileWriteContent(args);
  if (!filePath || content == null) return null;
  try {
    const target = await assertSafeCasPath(filePath);
    // Identity FIRST, then the token: both must describe the same observation, and taking identity
    // first means a swap between them makes the token the newer of the two, which the pre-rename
    // re-check then catches rather than silently accepting.
    const expected_identity = await fsObjectIdentity(target);
    const expected_token = await createFsVersionToken(target);
    return { expected_token, expected_identity };
  } catch {
    return null;
  }
}

/** Convenience: the token half only. */
export async function measureFsAuthorizationToken(args: unknown): Promise<VersionToken | null> {
  const m = await measureFsAuthorization(args);
  return m ? m.expected_token : null;
}
