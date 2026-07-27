/**
 * @coderifts/agent-guard — process-local session-taint detector (SEPARATE surface).
 *
 * Implements session-taint-detector-SPEC.md verbatim: a multi-call taint tracker that flags when a
 * session both accumulates contract taint AND emits an SSOT sink — closing the gap where a sequence
 * passes single-call DG-1 yet mutates SSOT. Additive: the frozen `builtinDetector.detect()` is NOT
 * touched. Versioned SEPARATELY (session-taint/1.0.0), monotonic toward caution.
 *
 * Normative: flag ⇔ ssot_sink_events ≠ ∅ ∧ tainted. Fixture-faithful classifier order (§1.6: NON_SINK
 * first, so snapshot/prettier stay under-set — a documented, Peter-accepted quirk; flag unaffected).
 */

import type { ToolCallDescriptor } from './types.js';

export const SESSION_TAINT_VERSION = 'session-taint/1.0.0';

// ── §1.3 classifiers ─────────────────────────────────────────────────────────────────────────
const NON_SSOT_RE = /(^|\/)(tests?|__tests__|fixtures?|__mocks__|src\/internal)\//i;
const PIPELINE_SCRATCH_RE = /(^|\/)(build|\.cache|codegen|idl)(\/|$)/i;
const PROSE_RE = /(^|\/)(README|CHANGELOG|LICENSE)(\.\w+)?$|\.md$/i;
const SSOT_PATH_RE = /(^|\/)(openapi|swagger|asyncapi)[^/]*\.(ya?ml|json)$|(^|\/)mcp\.json$|\.graphql$|\.gql$|(^|\/)idl\/.*\.proto$|(^|\/)specs?\/.*\.(ya?ml|json)$|openapi\.yaml|schema\.graphql|asyncapi\.yaml/i;
const MIGRATION_RE = /(^|\/)migrations?\//i;
const CODE_OR_CONFIG_RE = /\.(ts|tsx|js|jsx)$/i;

const CONTRACT_CONTENT_RE = /\bopenapi\s*[:=]|\bswagger\s*[:=]|\basyncapi\s*[:=]|syntax\s*=\s*["']proto3|["']inputSchema["']|\btype\s+Query\b|(^|\n)\s*paths\s*:/i;
const STAGING_NAME_RE = /\.b64$|enc\/|field-map|flags\.json|optional_fields|required_fields|service\.idl|frags\/|BREAKING_DROP/i;

const NON_SINK_RE = /validate-frags|gen-docs|reload-flags|snapshot-spec|prettier|npm test|npm install|npx prettier/i;
const SSOT_INVALIDATE_RE = /archive-old-spec/i;
const SSOT_SINK_RE = /dsl-to-openapi|merge-spec|publish-fixture|promote-spec|sync-graphql|b64join-write|decode-promote|apply-field-map|render-openapi|idl\/compile|generate-and-test|compile_spec_bundle|install-proto|install-mcp|promote-asyncapi|repack-extract|codegen\/build\.js|codegen\/apply|codegen\/render/i;

export type PathClass = 'prose' | 'scratch' | 'migration' | 'ssot' | 'code_or_config' | 'other';

export function pathClass(p: string): PathClass {
  if (PROSE_RE.test(p)) return 'prose';
  if (NON_SSOT_RE.test(p) || PIPELINE_SCRATCH_RE.test(p)) return 'scratch';
  if (MIGRATION_RE.test(p)) return 'migration';
  if (SSOT_PATH_RE.test(p)) return 'ssot';
  if (CODE_OR_CONFIG_RE.test(p) || p.startsWith('src/') || p.startsWith('config/') || p === 'package.json') return 'code_or_config';
  return 'other';
}

// ── state model (§1.1) ───────────────────────────────────────────────────────────────────────
export type PendingRename = { from: string; to: string } | { drop: string };

export interface SessionState {
  scratch_writes: string[];
  contract_looking_scratch: string[];
  encoded_fragments: string[];
  intermediate_artifacts: string[];
  pending_renames: PendingRename[];
  optional_fields_added: string[];
  required_fields_declared: string[];
  ssot_paths_touched: string[];
  ssot_sink_events: string[];
  ssot_invalidated: boolean;
  reverse_snapshot: boolean;
  formatter_only_ssot: boolean;
  store_keys: string[];
  tainted: boolean;
}

export function emptySessionState(): SessionState {
  return {
    scratch_writes: [], contract_looking_scratch: [], encoded_fragments: [], intermediate_artifacts: [],
    pending_renames: [], optional_fields_added: [], required_fields_declared: [], ssot_paths_touched: [],
    ssot_sink_events: [], ssot_invalidated: false, reverse_snapshot: false, formatter_only_ssot: false,
    store_keys: [], tainted: false,
  };
}

/** Serialize to the fixture's projected form (pending_renames -> "from->to" | "drop:name"). */
export function projectState(s: SessionState): Record<string, unknown> {
  return {
    scratch_writes: s.scratch_writes.slice(),
    encoded_fragments: s.encoded_fragments.slice(),
    pending_renames: s.pending_renames.map((r) => ('drop' in r ? `drop:${r.drop}` : `${r.from}->${r.to}`)),
    optional_fields_added: s.optional_fields_added.slice(),
    required_fields_declared: s.required_fields_declared.slice(),
    ssot_paths_touched: s.ssot_paths_touched.slice(),
    contract_looking_scratch: s.contract_looking_scratch.slice(),
    intermediate_artifacts: s.intermediate_artifacts.slice(),
    ssot_sink_events: s.ssot_sink_events.slice(),
    ssot_invalidated: s.ssot_invalidated,
    reverse_snapshot: s.reverse_snapshot,
    formatter_only_ssot: s.formatter_only_ssot,
    store_keys: s.store_keys.slice(),
    tainted: s.tainted,
  };
}

// ── §2.2 extractors ──────────────────────────────────────────────────────────────────────────
function asRecord(args: unknown): Record<string, unknown> { return args && typeof args === 'object' ? (args as Record<string, unknown>) : {}; }

function extractPaths(args: unknown): string[] {
  const a = asRecord(args); const out: string[] = [];
  for (const k of ['path', 'target', 'file', 'dest', 'filename', 'destination']) if (typeof a[k] === 'string') out.push(a[k] as string);
  return out;
}
function extractContent(args: unknown): string {
  const a = asRecord(args); const parts: string[] = [];
  for (const k of ['contents', 'content', 'new_string', 'old_string', 'patch', 'value', 'command']) if (typeof a[k] === 'string') parts.push(a[k] as string);
  return parts.join('\n');
}

// ── §2.3 encoded-fragment heuristic (fixture-faithful — do not "fix" without regenerating) ──────
function isEncodedFragment(path: string | undefined, content: string): boolean {
  if (path && /part\.|enc\/|\.b64$|pkg\.part/i.test(path)) return true;
  const c = content.replace(/\s+/g, '');
  if (c.length >= 8 && c.length < 80 && /^[A-Za-z0-9+/=]+$/.test(c)) return true;
  return false;
}

// ── §2.4 command classification (ORDER: NON_SINK first, fixture-faithful §1.6) ──────────────────
export type CmdClass = 'non_sink' | 'ssot_invalidate' | 'ssot_sink' | 'reverse_snapshot' | 'formatter' | 'unknown_script';

export function classifyCommand(command: string, action: string, cfg: SessionTaintConfig = {}): CmdClass {
  const s = `${command || ''} ${action || ''}`;
  const extraNon = cfg.extraNonSinkPatterns || [];
  const extraSink = cfg.extraSinkPatterns || [];
  if (NON_SINK_RE.test(s) || extraNon.some((r) => r.test(s))) return 'non_sink';
  if (SSOT_INVALIDATE_RE.test(s)) return 'ssot_invalidate';
  if (SSOT_SINK_RE.test(s) || action === 'compile_spec_bundle' || extraSink.some((r) => r.test(s))) return 'ssot_sink';
  if (/snapshot/i.test(s)) return 'reverse_snapshot';
  if (/prettier|format/i.test(s)) return 'formatter';
  return 'unknown_script';
}

function pushUniq(arr: string[], v: string): void { if (v != null && !arr.includes(v)) arr.push(v); }

// ── §2.5 transition ────────────────────────────────────────────────────────────────────────────
export function updateSession(state: SessionState, call: { toolName?: string; arguments?: unknown }, cfg: SessionTaintConfig = {}): SessionState {
  const s: SessionState = JSON.parse(JSON.stringify(state)); // pure: new state
  const args = asRecord(call && call.arguments);
  const paths = extractPaths(args);
  const content = extractContent(args);
  const tool = call && call.toolName;

  // store
  if (tool === 'store' && typeof args.key === 'string') {
    pushUniq(s.store_keys, args.key);
    if (/spec_|api_|openapi|schema/i.test(args.key) || /BREAKING|ROUTE|FIELD|REMOVE|MANDATORY|required|optional/i.test(String(args.value))) {
      pushUniq(s.intermediate_artifacts, `store:${args.key}`);
    }
  }
  // apply
  if (tool === 'apply' && typeof args.action === 'string') {
    if (classifyCommand('', args.action, cfg) === 'ssot_sink') s.ssot_sink_events.push(args.action);
  }
  // Bash / command
  if (tool === 'Bash' || typeof args.command === 'string') {
    const cmd = typeof args.command === 'string' ? args.command : '';
    const kind = classifyCommand(cmd, '', cfg);
    if (kind === 'ssot_sink') s.ssot_sink_events.push(cmd);
    if (kind === 'ssot_invalidate') s.ssot_invalidated = true;
    if (kind === 'reverse_snapshot') s.reverse_snapshot = true;
    if (kind === 'formatter' && (SSOT_PATH_RE.test(cmd) || /openapi|swagger|asyncapi|\.graphql|\.gql|mcp\.json|schema/i.test(cmd))) s.formatter_only_ssot = true;
  }

  // path-bearing writes/edits
  for (const p of paths) {
    const pc = pathClass(p);
    const isScratch = pc === 'scratch' || NON_SSOT_RE.test(p) || PIPELINE_SCRATCH_RE.test(p);

    if (isScratch) {
      pushUniq(s.scratch_writes, p);
      if (CONTRACT_CONTENT_RE.test(content) || STAGING_NAME_RE.test(p + content)) pushUniq(s.contract_looking_scratch, p);
      if (PIPELINE_SCRATCH_RE.test(p)) pushUniq(s.intermediate_artifacts, p);
      if (isEncodedFragment(p, content) || /\.b64$/i.test(p) || /enc\//i.test(p) || /pkg\.part/i.test(p)) pushUniq(s.encoded_fragments, p);
      if (/field-map|flags\.json|optional_fields|required_fields|\.idl$/i.test(p)) pushUniq(s.intermediate_artifacts, p);
    }

    if (pc === 'ssot' && !(tool === 'Bash' && /prettier/i.test(typeof args.command === 'string' ? args.command : ''))) pushUniq(s.ssot_paths_touched, p);

    // field-map JSON
    if (/field-map/i.test(p)) {
      let obj: unknown;
      try { obj = JSON.parse(content); } catch { obj = null; }
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
          if (k === '__drop' && Array.isArray(v)) { for (const d of v) s.pending_renames.push({ drop: String(d) }); }
          else if (typeof v === 'string') s.pending_renames.push({ from: k, to: v });
        }
      }
    }
    // flags.json optional/required
    if (/flags\.json/i.test(p)) {
      for (const m of content.matchAll(/"(\w+)":\s*"optional"/g)) pushUniq(s.optional_fields_added, m[1]);
      for (const m of content.matchAll(/"(\w+)":\s*"required"/g)) pushUniq(s.required_fields_declared, m[1]);
    }
    // list files
    if (/optional_fields/i.test(p)) for (const line of content.split('\n')) if (line.trim()) pushUniq(s.optional_fields_added, line.trim());
    if (/required_fields/i.test(p)) for (const line of content.split('\n')) if (line.trim()) pushUniq(s.required_fields_declared, line.trim());
    // ST-009 yaml heuristics
    if (NON_SSOT_RE.test(p) && /required:\s*\[[^\]]*owner_id/.test(content)) pushUniq(s.required_fields_declared, 'owner_id');
    if (NON_SSOT_RE.test(p) && /owner_id:\s*\{type: string\}/.test(content)) pushUniq(s.optional_fields_added, 'owner_id');

    if (/\.idl$/i.test(p) || p.startsWith('idl/')) pushUniq(s.intermediate_artifacts, p);
  }

  // body flags (with/without path)
  if (/BREAKING_DROP|FIELD .* REMOVE|MANDATORY/i.test(content)) pushUniq(s.intermediate_artifacts, paths[0] || 'inline_flag');

  s.tainted = computeTainted(s);
  return s;
}

// ── §3.2 taint predicate ─────────────────────────────────────────────────────────────────────
export function computeTainted(s: SessionState): boolean {
  return (
    s.contract_looking_scratch.length > 0
    || s.encoded_fragments.length > 0
    || s.intermediate_artifacts.length > 0
    || s.store_keys.some((k) => /spec_|api_|schema|openapi/i.test(k))
    || s.pending_renames.length > 0
    || s.optional_fields_added.some((f) => s.required_fields_declared.includes(f))
    || (s.required_fields_declared.length > 0 && s.optional_fields_added.length > 0)
    || s.ssot_invalidated === true
  );
}

// ── §3.3/§3.4 evaluate ───────────────────────────────────────────────────────────────────────
export interface SessionEval { flag: boolean; trip: boolean; key_signal: string | null; }

export function deriveKeySignal(s: SessionState): string {
  if (s.ssot_invalidated) return 'delete_recreate_ssot_via_session';
  if (s.encoded_fragments.length) return 'encoded_scratch_then_ssot_promotion';
  if (s.optional_fields_added.some((f) => s.required_fields_declared.includes(f)) || (s.required_fields_declared.length && s.optional_fields_added.length)) return 'cumulative_required_flip';
  if (s.pending_renames.length) return 'cumulative_rename_via_codegen';
  if (s.contract_looking_scratch.length) return 'scratch_to_ssot_promotion';
  if (s.intermediate_artifacts.length) return 'cross_call_reassembly_to_ssot';
  return 'session_ssot_sink_with_taint';
}

/** flag ⇔ (ssot_sink_events ≠ ∅ || sink_seen) ∧ (tainted || overflow). */
export function evaluate(state: SessionState, prevFlagged = false, opts: { overflow?: boolean; sinkSeen?: boolean } = {}): SessionEval {
  const sink = state.ssot_sink_events.length > 0 || opts.sinkSeen === true;
  const taint = state.tainted || opts.overflow === true;
  const flag = sink && taint;
  return { flag, trip: flag && !prevFlagged, key_signal: flag ? deriveKeySignal(state) : null };
}

// ── §4/§5 tracker + config ───────────────────────────────────────────────────────────────────
export interface SessionTaintConfig {
  extraSinkPatterns?: RegExp[];
  extraNonSinkPatterns?: RegExp[];
  maxCalls?: number;
  maxPathsTracked?: number;
  maxSinkEvents?: number;
  maxStateBytes?: number;
  ttlMs?: number;
  bindCwd?: boolean;
  sessionId?: string;
  sessionTaintSeverity?: 'caution' | 'stop'; // Q6: default 'caution' (forces preflight, not hard STOP)
}

export interface SessionTaintObservation {
  flag: boolean;
  trip: boolean;
  key_signal: string | null;
  state: Readonly<SessionState>;
  version: typeof SESSION_TAINT_VERSION;
  overflow: boolean;
  severity: 'caution' | 'stop';
}

const DEF = { maxCalls: 256, maxPathsTracked: 512, maxSinkEvents: 64, maxStateBytes: 256_000, ttlMs: 3_600_000 };

export class SessionTaintTracker {
  readonly version = SESSION_TAINT_VERSION;
  private state = emptySessionState();
  private prevFlag = false;
  private callCount = 0;
  private overflow = false;
  private sinkSeen = false;
  private lastObserveAt = 0;
  private cfg: SessionTaintConfig;

  constructor(config: SessionTaintConfig = {}) { this.cfg = config; }

  private pathTotal(): number {
    const s = this.state;
    return s.scratch_writes.length + s.contract_looking_scratch.length + s.encoded_fragments.length
      + s.intermediate_artifacts.length + s.ssot_paths_touched.length;
  }

  observe(call: ToolCallDescriptor): SessionTaintObservation {
    const now = this.now();
    // §4.3 TTL: soft reset to a fresh session on expiry.
    if (this.lastObserveAt && now - this.lastObserveAt > (this.cfg.ttlMs ?? DEF.ttlMs)) this.reset();
    this.lastObserveAt = now;

    const next = updateSession(this.state, call, this.cfg);
    // §4.3 caps → sticky overflow forces taint (monotonic caution; NOT drop-oldest).
    this.callCount++;
    if (this.callCount > (this.cfg.maxCalls ?? DEF.maxCalls)) this.overflow = true;
    if (this.pathTotal() > (this.cfg.maxPathsTracked ?? DEF.maxPathsTracked)) this.overflow = true;
    if (JSON.stringify(next).length > (this.cfg.maxStateBytes ?? DEF.maxStateBytes)) this.overflow = true;
    // maxSinkEvents: stop growing the list but keep sink presence sticky.
    if (next.ssot_sink_events.length > (this.cfg.maxSinkEvents ?? DEF.maxSinkEvents)) {
      next.ssot_sink_events = next.ssot_sink_events.slice(0, this.cfg.maxSinkEvents ?? DEF.maxSinkEvents);
    }
    this.state = next;
    if (this.state.ssot_sink_events.length > 0) this.sinkSeen = true;

    return this.snapshot();
  }

  status(): SessionTaintObservation { return this.snapshot(); }

  reset(): void {
    this.state = emptySessionState(); this.prevFlag = false; this.callCount = 0;
    this.overflow = false; this.sinkSeen = false; this.lastObserveAt = 0;
  }

  private snapshot(): SessionTaintObservation {
    const eva = evaluate(this.state, this.prevFlag, { overflow: this.overflow, sinkSeen: this.sinkSeen });
    if (eva.flag) this.prevFlag = true;
    return {
      flag: eva.flag, trip: eva.trip, key_signal: eva.key_signal,
      state: projectState(this.state) as unknown as SessionState,
      version: SESSION_TAINT_VERSION, overflow: this.overflow,
      severity: this.cfg.sessionTaintSeverity || 'caution',
    };
  }

  // Date.now is fine at runtime; isolated for testability.
  private now(): number { return Date.now(); }
}
