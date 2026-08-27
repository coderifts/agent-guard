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
import { createFsVersionToken, writeFileIfUnchanged } from './fs.js';

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
 * Wire the FS adapter when path + full-file contents are both present.
 * Otherwise run the host write unchanged. If the host already returned an
 * ExecuteIfUnchangedOutcome, pass it through (do not wrap again).
 *
 * KNOWN-OPEN RESIDUAL — the expected token is SELF-FETCHED, not authorization-bound.
 * createFsVersionToken runs HERE, inside executeFactory: after preflight (T1) and after the T2
 * execution-time recheck. So the token describes whatever state the file holds at write time, not
 * the state the authorization examined. The CAS then asks "did this change since I read it a
 * microsecond ago", which is a real check of a vacuous window: a writer that lands between T2 and
 * this read has its state adopted as the legitimate starting point, and the outcome still reports
 * status:'committed'. Measured, not inferred — see guard.ts's "no observed_token_at_commit CAS".
 * Closing it means threading a token measured at authorization into this call rather than reading
 * one here; that is a behavioural change with its own proof and is deliberately NOT done here.
 */
export async function wrapWriteWithFsCas<T>(
  args: unknown,
  write: () => Promise<T> | T,
): Promise<T | ExecuteIfUnchangedOutcome<unknown>> {
  const filePath = inferFsPathFromArgs(args);
  const content = inferFullFileWriteContent(args);
  if (filePath && content != null) {
    let expected: string;
    try {
      expected = await createFsVersionToken(filePath);
    } catch {
      return write();
    }
    return writeFileIfUnchanged({
      path: filePath,
      expected_token: expected,
      content,
    });
  }
  const raw = await write();
  if (isExecuteIfUnchangedOutcome(raw)) return raw;
  return raw;
}
