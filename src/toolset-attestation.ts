/**
 * cr.toolset.attest.v1 issuance (guard side) — "Represented".
 *
 * Wire/signing input MIRRORS app src/verdict-core/toolset-attestation.js. The guard SIGNS via a
 * host-provided sign(bytes) callback — never a raw key in config. CodeRifts never holds the
 * declaration key. Custody model copied from tryIssueCoverageAttestation and
 * tryIssueMonitoringAttestation, deliberately: one custody story for every host-signed artifact,
 * not a third one per envelope.
 *
 * Signer throw / null / empty signature → omit the token; never unsigned.
 * Absent config → undefined, byte-identical to not calling this at all.
 *
 * ── WHY ISSUANCE LIVES HERE ─────────────────────────────────────────────────────────────────
 * The spec's own reasoning: a declaration typed by hand is the failure mode the artifact exists
 * to prevent. This module is the only place that holds the actual tool table, so the entries are
 * GENERATED from the registered tools — name, input schema, resolved mutation class — and never
 * from config. A host can choose whether to declare; it cannot choose what the declaration says.
 *
 * ── THE VOCABULARY MAPPING, and it is the point of this module ──────────────────────────────
 * The guard's mutation vocabulary is WIDER than the envelope's, exactly as with coverage:
 *   guard     readonly | mutating | mutating_shell | mutating_vcs | mutating_deploy
 *   envelope  readonly | mutating
 *
 * Every `mutating_*` collapses to `mutating`. That is not information loss the envelope hides:
 * the declared sentence is about which tools CAN MUTATE a governed target, and all four mutating
 * classes answer that question the same way. Emitting `mutating_shell` would be rejected by the
 * app kernel as `bad_mutation_class` — so the mapping happens here, where the meaning is known,
 * rather than minting a token that fails verification.
 */
'use strict';

import { createHash } from 'node:crypto';
import type { ProtectedTool, ToolMutationClass } from './tool-registry.js';

export const TOOLSET_ATTEST_VERSION = 'cr.toolset.attest.v1';
export const TOOLSET_ATTEST_SIGNING_PREFIX = 'crtoolsetattest.v1';
export const TOOLSET_ATTEST_ENVELOPE_TAG = 'cr.toolset.attest.v1';

/**
 * The declared sentence, byte-identical to the app kernel's closed set of one.
 * A different sentence is MALFORMED there, not a weaker declaration.
 */
export const TOOLSET_ATTEST_STATEMENT =
  'this is the complete set of tools that can mutate a governed target';

/** Envelope classes. Two — the guard's five collapse onto these. */
const ENVELOPE_CLASSES = ['mutating', 'readonly'] as const;

/** Mirrors the app kernel's MAX_ENTRIES. A larger table is a packaging problem, not a set. */
const MAX_ENTRIES = 512;

export type ToolsetAttestationSigner = (
  bytes: Uint8Array,
) => Uint8Array | Promise<Uint8Array>;

export type ToolsetAttestationConfig = {
  /** Customer-held declaration key id. Named on the token; resolved later against a registry. */
  kid: string;
  /** Host signs the UTF-8 signing-input bytes. Returns raw Ed25519 signature. Never a raw key. */
  signer: ToolsetAttestationSigner;
  /**
   * The accountable party. Required — without a named declarer, "accountable" is empty and the
   * artifact means nothing.
   */
  declarer: string;
  /** Framework name. Must be supplied WITH frameworkVersion or not at all. */
  framework?: string;
  /** Framework version. Must be supplied WITH framework or not at all. */
  frameworkVersion?: string;
  /** Optional scope label. */
  sessionId?: string;
};

export type ToolsetDeclarationEntry = {
  name: string;
  mutation_class: 'mutating' | 'readonly';
  input_schema_digest?: string;
};

const scalar = (v: unknown): string => (v == null ? '' : String(v));
const optional = (v: unknown): string =>
  (v != null && String(v).length > 0 ? String(v) : '');

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Every mutating_* answers "can this mutate a governed target?" the same way. */
function toEnvelopeClass(cls: ToolMutationClass): 'mutating' | 'readonly' {
  return cls === 'readonly' ? 'readonly' : 'mutating';
}

/**
 * Stable JSON for an input schema. Object keys sorted at every depth so a re-serialised schema
 * does not change the digest; arrays keep their order because order is meaningful in a schema.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

/**
 * Canonical set digest. MUST stay byte-identical to the app kernel's computeSetDigest — a second,
 * subtly different digest would mint tokens that verify as UNBOUND against the real set.
 * Pinned by a test that requires the app kernel and compares outputs.
 */
export function computeToolsetDigest(
  entries: readonly ToolsetDeclarationEntry[],
): { ok: true; digest: string; tool_count: number; mutating_count: number }
  | { ok: false; reason: string } {
  if (!Array.isArray(entries)) return { ok: false, reason: 'entries_not_array' };
  if (entries.length === 0) return { ok: false, reason: 'entries_empty' };
  if (entries.length > MAX_ENTRIES) return { ok: false, reason: 'entries_too_many' };

  const seen = new Set<string>();
  const rows: string[][] = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object') return { ok: false, reason: 'entry_not_object' };
    const name = e.name;
    const cls = e.mutation_class;
    const sd = e.input_schema_digest;
    if (typeof name !== 'string' || !name || name.length > 128) return { ok: false, reason: 'bad_entry_name' };
    if (name.includes('|')) return { ok: false, reason: 'delimiter_in_entry_name' };
    if (!(ENVELOPE_CLASSES as readonly string[]).includes(cls)) return { ok: false, reason: 'bad_mutation_class' };
    if (sd != null) {
      if (typeof sd !== 'string' || !sd.startsWith('sha256:') || sd.includes('|')) {
        return { ok: false, reason: 'bad_input_schema_digest' };
      }
    }
    if (seen.has(name)) return { ok: false, reason: 'duplicate_entry_name' };
    seen.add(name);
    rows.push([name, cls, sd == null ? '' : sd]);
  }
  rows.sort((a, b) => (a[0] < b[0] ? -1 : (a[0] > b[0] ? 1 : 0)));

  const canonical = rows.map((r) => r.join(' ')).join('');
  return {
    ok: true,
    digest: 'sha256:' + sha256hex(canonical),
    tool_count: rows.length,
    mutating_count: rows.filter((r) => r[1] === 'mutating').length,
  };
}

/**
 * Build declaration entries from the REGISTERED TOOL TABLE. This is the whole point: the
 * declaration describes what was registered, not what someone typed.
 */
export function declarationEntriesFromTools(
  tools: readonly ProtectedTool[],
): ToolsetDeclarationEntry[] {
  const out: ToolsetDeclarationEntry[] = [];
  for (const t of tools) {
    if (!t || typeof t.name !== 'string' || !t.name) continue;
    const entry: ToolsetDeclarationEntry = {
      name: t.name,
      mutation_class: toEnvelopeClass(t._coderifts.mutationClass),
    };
    if (t.inputSchema !== undefined) {
      entry.input_schema_digest = 'sha256:' + sha256hex(stableStringify(t.inputSchema));
    }
    out.push(entry);
  }
  return out;
}

export function toolsetAttestSigningInput(body: Record<string, unknown>): string {
  const parts = [
    TOOLSET_ATTEST_SIGNING_PREFIX,
    scalar(body.kid),
    scalar(body.declarer),
    scalar(body.statement),
    scalar(body.set_digest),
    scalar(body.declared_at),
    optional(body.session_id),
    optional(body.receipt_digest),
    optional(body.framework),
    optional(body.framework_version),
    optional(body.guard_version),
    body.tool_count == null ? '' : String(body.tool_count),
    body.mutating_count == null ? '' : String(body.mutating_count),
    optional(body.scope_note),
  ];
  return parts.join('|');
}

const SIGNED_STRING_FIELDS = [
  'kid', 'declarer', 'statement', 'set_digest', 'declared_at',
  'session_id', 'receipt_digest', 'scope_note',
  'framework', 'framework_version', 'guard_version',
];

function fieldHasDelimiter(body: Record<string, unknown>): boolean {
  for (const k of SIGNED_STRING_FIELDS) {
    const v = body[k];
    if (typeof v === 'string' && v.includes('|')) return true;
  }
  return false;
}

/**
 * Issue a cr.toolset.attest.v1 token from the registered tool table.
 * Returns undefined when config is absent, the table is unusable, the framework pair is
 * unpaired, or the host signer throws — never an unsigned token.
 */
export async function tryIssueToolsetAttestation(args: {
  config?: ToolsetAttestationConfig | null;
  tools: readonly ProtectedTool[] | null | undefined;
  guardVersion?: string | null;
  receiptDigest?: string | null;
  scopeNote?: string | null;
  now?: string;
}): Promise<string | undefined> {
  const cfg = args.config;
  if (!cfg || typeof cfg.kid !== 'string' || !cfg.kid || typeof cfg.signer !== 'function') {
    return undefined;
  }
  if (typeof cfg.declarer !== 'string' || cfg.declarer.length === 0) return undefined;

  // An unpaired framework pins nothing; the app kernel rejects it as framework_version_unpaired.
  // Refuse to mint rather than emit a token that fails verification.
  const hasFw = typeof cfg.framework === 'string' && cfg.framework.length > 0;
  const hasFwV = typeof cfg.frameworkVersion === 'string' && cfg.frameworkVersion.length > 0;
  if (hasFw !== hasFwV) return undefined;

  const tools = args.tools;
  if (!Array.isArray(tools) || tools.length === 0) return undefined;

  const entries = declarationEntriesFromTools(tools);
  const digest = computeToolsetDigest(entries);
  if (!digest.ok) return undefined;

  const body: Record<string, unknown> = {
    v: TOOLSET_ATTEST_VERSION,
    kid: cfg.kid,
    declarer: cfg.declarer,
    statement: TOOLSET_ATTEST_STATEMENT,
    set_digest: digest.digest,
    declared_at: args.now || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    tool_count: digest.tool_count,
    mutating_count: digest.mutating_count,
  };
  if (typeof cfg.sessionId === 'string' && cfg.sessionId) body.session_id = cfg.sessionId;
  if (typeof args.receiptDigest === 'string' && args.receiptDigest) body.receipt_digest = args.receiptDigest;
  if (hasFw) {
    body.framework = cfg.framework;
    body.framework_version = cfg.frameworkVersion;
  }
  if (typeof args.guardVersion === 'string' && args.guardVersion) body.guard_version = args.guardVersion;
  if (typeof args.scopeNote === 'string' && args.scopeNote) body.scope_note = args.scopeNote;

  if (fieldHasDelimiter(body)) return undefined;

  const input = Buffer.from(toolsetAttestSigningInput(body), 'utf8');
  let sig: Uint8Array;
  try {
    sig = await cfg.signer(input);
  } catch {
    return undefined;
  }
  if (sig == null) return undefined;
  const sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  if (sigBuf.length === 0) return undefined;

  return [
    TOOLSET_ATTEST_ENVELOPE_TAG,
    cfg.kid,
    b64url(Buffer.from(JSON.stringify(body), 'utf8')),
    b64url(sigBuf),
  ].join('|');
}

export function kidFromToolsetAttestation(token: string | undefined | null): string | null {
  if (typeof token !== 'string' || token.length === 0) return null;
  const parts = token.split('|');
  if (parts.length !== 4 || parts[0] !== TOOLSET_ATTEST_ENVELOPE_TAG) return null;
  return parts[1] || null;
}
