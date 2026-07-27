/**
 * @coderifts/agent-guard — builtinDetector (the trust core).
 *
 * Fail-safe + versioned. Precedence (frozen spec): explicit artifacts > filesTouched patterns >
 * diff/content markers > toolName > intent (add-only). A contract surface whose change cannot be
 * proven inert triggers (confident=false => trigger=true). The Grok corpus of 68 vectors is the
 * mandatory fixture set; this detector passes all 68 (46 trigger, 22 no-trigger).
 */

import { gunzipSync } from 'node:zlib';
import type { TriggerDetector, ToolCallDescriptor, Artifact } from './types.js';

// builtin/1.1.0: additive deep-argument-scan (DG-1) — walks ALL argument values (any key, depth,
// arrays) + bounded decode of encoded payloads, monotonic toward caution. Output shape unchanged.
export const DETECTOR_VERSION = 'builtin/1.1.0';

// ── Path classification ────────────────────────────────────────────────────────
const CONTRACT_PATH_RE = [
  /openapi/i, /swagger/i, /asyncapi/i,
  /\.graphql$/i, /\.gql$/i, /\.proto$/i, /\.pb($|\.)/i,
  /(^|\/)[\w.-]*mcp[\w.-]*\.json$/i, /tools-catalog\.json$/i,
  /schema\.prisma$/i, /(^|\/)migrations?\//i, /(^|\/)alembic\//i,
  /(^|\/)buf\.ya?ml$/i, /\.spectral\.ya?ml$/i,
  /(^|\/)\.github\/workflows\//i, /(^|\/)\.husky\//i,
  /api[-_]?contract/i, /service-definition/i, /(^|\/)contracts?\//i,
  /schemas?\/components?\//i, /\bcontract\.json$/i,
  /(^|\/)spec\.(ya?ml|json)$/i, /api[-_/]spec\.(ya?ml|json)$/i, /-api\.(ya?ml|yml)$/i, /current-api/i,
  /(^|\/)(src\/)?generated\//i, /(^|\/)gen\//i, /\.pb\.go$/i, /openapi\.d\.ts$/i,
];
// Paths whose content is NOT a production SSOT — contract-looking content there does not trigger.
const NON_SSOT_PATH_RE = [
  /(^|\/)tests?\//i, /(^|\/)__tests__\//i, /(^|\/)__mocks__\//i, /\/fixtures?\//i, /(^|\/)mocks?\//i,
  /\.test\.[jt]sx?$/i, /\.spec\.[jt]sx?$/i,
  /(^|\/)src\/internal\//i,
  /(^|\/)node_modules\//i,
];
// Prose files: never a contract regardless of content markers inside them.
const PROSE_PATH_RE = [/(^|\/)README(\.\w+)?$/i, /(^|\/)CHANGELOG(\.\w+)?$/i, /(^|\/)LICENSE(\.\w+)?$/i, /\.md$/i];
// Code files that ARE a wire/contract surface when they carry route/dto/rpc markers.
const CODE_CONTRACT_PATH_RE = [/(^|\/)src\/routes?\//i, /(^|\/)routes?\//i, /(^|\/)app\/api\//i, /(^|\/)src\/dto\//i, /dto/i, /routers?\//i, /\.prisma$/i, /\.tf$/i, /server\/routers?\//i];
const GATE_PATH_RE = [/(^|\/)\.github\/workflows\//i, /(^|\/)\.husky\//i, /\.spectral\.ya?ml$/i, /(^|\/)buf\.ya?ml$/i];
const LOCKFILE_RE = /(package-lock\.json|pnpm-lock\.ya?ml|yarn\.lock|composer\.lock|Cargo\.lock)$/i;

// ── Content markers ────────────────────────────────────────────────────────────
const CONTRACT_CONTENT_RE = [
  /\bopenapi\s*[:=]\s*["']?3/i, /["']openapi["']\s*:/i, /\bswagger\s*[:=]/i, /["']swagger["']\s*:/i,
  /\basyncapi\s*[:=]/i, /["']asyncapi["']\s*:/i,
  /(^|\n)\s*paths\s*:/i, /["']paths["']\s*:/i,
  /syntax\s*=\s*["']proto3/i, /(^|\n)\s*message\s+\w+\s*\{/i,
  /\btype\s+(Query|Mutation|Subscription)\b/i,
  /["']tools["']\s*:\s*\[/i, /["']inputSchema["']\s*:/i,
  /\/v\d+\/[\w{}.-]*\s*:/,                                   // versioned route-path key
  /\bchannels\s*:/i,
];
const CONTRACT_STRUCTURE_RE = [
  /(get|post|put|delete|patch)\s*:\s*\{?/i,
  /message\s+\w+\s*\{[^}]*=\s*\d+/i,
  /\/v\d+\/[\w{}.-]*\s*:/,
  /"name"\s*:\s*"[^"]+"[\s,}]*"?inputSchema/i,
];
// Real (breaking-capable) change markers on a single changed line.
const REAL_CHANGE_RE = [
  /required\s*:\s*\[/i, /["']required["']\s*:\s*\[/i,
  /\btype\s*:\s*\w+/i, /nullable\s*:/i, /:\s*\w+!/,
  /additionalProperties\s*:\s*(true|false)/i, /["']additionalProperties["']/i,
  /\bDROP\s+COLUMN\b/i, /\bALTER\s+COLUMN\b/i, /alter_column\s*\(/i, /new_column_name/i, /\bRENAME\b/i, /DROP\s+TABLE/i,
  /@IsString|@IsOptional|response_model|z\.string|@unique/i,
  /app\.(get|post|put|delete|patch)\s*\(/i, /@router\.(get|post|put|delete|patch)/i,
  /\/v\d+\//,
  /continue-on-error|if:\s*false|:\s*off\b|'off'|"off"/i, /\bignore\s*:/i, /(^|\n)\s*breaking\s*:/i,
];
// Inert keys (a change touching ONLY these is a contract no-op).
const INERT_KEY_RE = [
  /^description\s*:/i, /^["']description["']\s*:/i,
  /^summary\s*:/i, /^title\s*:/i, /^contact\s*:/i, /^name\s*:/i,
  /^examples?\s*:/i, /^["']examples?["']\s*:/i,
  /^x-[\w-]+\s*:/i, /^["']x-[\w-]+["']\s*:/i,
];

const READ_ONLY_TOOLS = new Set(['read', 'grep', 'glob', 'ls', 'cat', 'view', 'search', 'list', 'get']);
const FORMATTER_RE = /\b(prettier|eslint\s+--fix|gofmt|rustfmt|black|clang-format|dprint)\b/i;
const GATE_KEYWORD_RE = /coderifts|agent-guard|contract-check|contract\b|preflight|spectral|\bbuf\b/i;

function anyMatch(res: RegExp[], s: string): boolean { return res.some((r) => r.test(s)); }

function argString(args: unknown): string {
  if (args == null) return '';
  if (typeof args === 'string') return args;
  try { return JSON.stringify(args); } catch { return ''; }
}

function changeText(call: ToolCallDescriptor): string {
  const parts: string[] = [];
  if (call.diff) parts.push(call.diff);
  const a = call.arguments as Record<string, unknown> | undefined;
  if (a && typeof a === 'object') {
    for (const k of ['new_string', 'old_string', 'contents', 'content', 'patch', 'command']) {
      const v = (a as Record<string, unknown>)[k];
      if (typeof v === 'string') parts.push(v);
    }
    const edits = (a as Record<string, unknown>).edits;
    if (Array.isArray(edits)) for (const e of edits) parts.push(argString(e));
  }
  return parts.join('\n');
}

function commandText(call: ToolCallDescriptor): string {
  const a = call.arguments as Record<string, unknown> | undefined;
  const c = a && typeof a === 'object' ? (a as Record<string, unknown>).command : undefined;
  return typeof c === 'string' ? c : '';
}

function allPaths(call: ToolCallDescriptor): string[] {
  const out = [...(call.filesTouched || [])];
  const a = call.arguments as Record<string, unknown> | undefined;
  if (a && typeof a === 'object' && typeof (a as Record<string, unknown>).path === 'string') out.push((a as Record<string, unknown>).path as string);
  return out;
}

function isContractPath(p: string): boolean {
  if (anyMatch(NON_SSOT_PATH_RE, p)) return false;
  if (anyMatch(PROSE_PATH_RE, p)) return false;
  return anyMatch(CONTRACT_PATH_RE, p);
}

/** The lines a change ACTUALLY adds/removes: diff +/- when a diff is present, else set-difference of
 * old_string vs new_string (context lines shared by both are NOT changes). */
function changedLines(call: ToolCallDescriptor): string[] {
  if (call.diff) {
    return call.diff.split('\n').filter((l) => l.startsWith('+') || l.startsWith('-')).map((l) => l.slice(1));
  }
  const out: string[] = [];
  const a = call.arguments as Record<string, unknown> | undefined;
  const pushSetDiff = (oldS: unknown, newS: unknown) => {
    const oldL = typeof oldS === 'string' ? oldS.split('\n') : [];
    const newL = typeof newS === 'string' ? newS.split('\n') : [];
    const oldSet = new Set(oldL.map((l) => l.trim()));
    const newSet = new Set(newL.map((l) => l.trim()));
    for (const l of newL) if (!oldSet.has(l.trim())) out.push(l);
    for (const l of oldL) if (!newSet.has(l.trim())) out.push(l);
  };
  if (a && typeof a === 'object') {
    pushSetDiff((a as Record<string, unknown>).old_string, (a as Record<string, unknown>).new_string);
    const contents = (a as Record<string, unknown>).contents ?? (a as Record<string, unknown>).content;
    if (typeof contents === 'string') for (const l of contents.split('\n')) out.push(l); // new file: all lines are "added"
    const patch = (a as Record<string, unknown>).patch;
    if (typeof patch === 'string') for (const l of patch.split('\n')) if (l.startsWith('+') || l.startsWith('-')) out.push(l.slice(1));
    const edits = (a as Record<string, unknown>).edits;
    if (Array.isArray(edits)) for (const e of edits) if (e && typeof e === 'object') pushSetDiff((e as Record<string, unknown>).old_string, (e as Record<string, unknown>).new_string);
  }
  return out;
}

function migrationDestructive(text: string): boolean {
  return /\bDROP\s+COLUMN\b|\bALTER\s+COLUMN\b|new_column_name|alter_column|\bRENAME\b|DROP\s+TABLE|DROP\s+CONSTRAINT/i.test(text);
}
function migrationIndexOnly(text: string): boolean {
  return /CREATE\s+INDEX/i.test(text) && !migrationDestructive(text) && !/ADD\s+COLUMN|DROP\b/i.test(text);
}

/** Gate/policy file whose change disables or weakens a contract gate. */
function gateDisabled(call: ToolCallDescriptor): boolean {
  const paths = allPaths(call);
  if (!paths.some((p) => anyMatch(GATE_PATH_RE, p))) return false;
  const text = changeText(call);
  if (!GATE_KEYWORD_RE.test(text)) return false;
  const lines = changedLines(call);
  // an added comment-out of a gate line, OR an explicit weakening keyword
  const commentedOut = lines.some((l) => /^\s*(#|\/\/)/.test(l) && GATE_KEYWORD_RE.test(l));
  const weakened = anyMatch(REAL_CHANGE_RE, text) || /continue-on-error|if:\s*false|:\s*off\b|ignore\s*:/i.test(text);
  return commentedOut || weakened;
}

/** Lockfile whose change redirects/major-bumps a CONTRACT package. */
function lockfileContractChange(call: ToolCallDescriptor): boolean {
  const paths = allPaths(call);
  if (!paths.some((p) => LOCKFILE_RE.test(p))) return false;
  const text = changeText(call);
  const contractPkg = /@[\w.-]+\/(openapi|graphql|proto|asyncapi|schema)\b|(openapi|graphql|proto|asyncapi|schema)@\d/i.test(text);
  if (!contractPkg) return false;
  return /"resolved"\s*:/i.test(text) || /@\d+\.\d+\.\d+/.test(text) || /@\d+['":]/.test(text);
}

function isInertOnly(call: ToolCallDescriptor): boolean {
  const text = changeText(call);
  const paths = allPaths(call);

  // lockfile integrity-only (no resolved redirect / contract-package change)
  if (paths.some((p) => LOCKFILE_RE.test(p)) && !lockfileContractChange(call)) {
    if (/"integrity"\s*:/i.test(text) && !/"resolved"\s*:/i.test(text)) return true;
  }
  // migration index-only
  if (paths.some((p) => /migrations?\/|alembic\//i.test(p)) && migrationIndexOnly(text)) return true;
  // gate files: unrelated change (no gate keyword) is inert; a gate change is NOT inert (realChangePresent decides).
  if (paths.some((p) => anyMatch(GATE_PATH_RE, p))) {
    if (!GATE_KEYWORD_RE.test(text) && !anyMatch(REAL_CHANGE_RE, text)) return true;
    return false;
  }
  // formatter command on a contract file (semantic no-op)
  const cmd = commandText(call);
  if (cmd && FORMATTER_RE.test(cmd)) return true;
  // example/value payload change only (not a schema change)
  if (/\b(examples?|value)\s*:/i.test(text) && !anyMatch(REAL_CHANGE_RE, text)) return true;

  const lines = changedLines(call);
  if (lines.length === 0) return false;
  let sawReal = false; let sawInert = false;
  for (const raw of lines) {
    const t = raw.trim();
    if (t === '') { sawInert = true; continue; }
    if (/^#|^\/\/|^\/\*|\*\/|^\*/.test(t)) { sawInert = true; continue; }         // comment
    if (/^```/.test(t)) { sawInert = true; continue; }                            // md fence
    if (/^["'].*["']$/.test(t) && !t.includes(':')) { sawInert = true; continue; } // bare quoted string (e.g. graphql description), not "key":"val"
    if (/generated|timestamp/i.test(t)) { sawInert = true; continue; }
    if (anyMatch(INERT_KEY_RE, t)) { sawInert = true; continue; }                 // description/summary/x-*/name/...
    if (anyMatch(REAL_CHANGE_RE, t) || anyMatch(CONTRACT_STRUCTURE_RE, t) || anyMatch(CONTRACT_CONTENT_RE, t)) { sawReal = true; continue; }
    if (/^[\w"']+\??\s*:\s*\S/.test(t)) { sawReal = true; continue; }             // a field/property declaration (add/remove)
    // neutral line: ignore
  }
  return sawInert && !sawReal;
}

function realChangePresent(call: ToolCallDescriptor): boolean {
  const text = changeText(call);
  if (migrationDestructive(text)) return true;
  if (gateDisabled(call)) return true;
  if (lockfileContractChange(call)) return true;
  for (const raw of changedLines(call)) {
    const t = raw.trim();
    if (anyMatch(INERT_KEY_RE, t)) continue;
    if (anyMatch(REAL_CHANGE_RE, t)) return true;
    if (/^[\w"']+\??\s*:\s*\S/.test(t) && !/^(paths|components|info|servers|channels|tools|get|post|put|delete|patch)\s*:/i.test(t)) return true; // field decl add/remove
  }
  return false;
}

function intentMentionsContract(intent?: string): boolean {
  if (!intent) return false;
  return /openapi|swagger|graphql|protobuf|\bproto\b|asyncapi|mcp\s*manifest|mcp\.json|json\s*schema|\bschema\b|required\s+field|\bendpoint\b|wire\s*format|api\s*spec|contract\s*(file|change|surface)/i.test(intent);
}

function commandMutatesContract(call: ToolCallDescriptor): boolean {
  const cmd = commandText(call);
  if (!cmd) return false;
  if (FORMATTER_RE.test(cmd)) return false;
  const touchesContract = allPaths(call).some(isContractPath)
    || /(>|>>|-o\s|mv\s|ln\s+-sf?\s|git\s+mv\s|cp\s)[^\n|]*(openapi|swagger|asyncapi|\.graphql|\.gql|\.proto|\.pb\b|mcp[.-]?\w*\.json|schema\.prisma|spec\.(ya?ml|json))/i.test(cmd)
    || anyMatch(CONTRACT_CONTENT_RE, cmd);
  const mutates = /(>|>>|\bmv\b|\bcp\b|\bln\s|git\s+mv|curl|wget|-o\b|base64\s+-d|xxd|\bjq\b|\bsed\b|\btee\b|echo|printf|\bcat\b)/i.test(cmd);
  return touchesContract && mutates;
}

// ── Deep argument scan (DG-1 hardening) — additive, bounded, monotonic toward caution ──────────
// Caps (stated): recursion depth 8; total scanned bytes 262144 (256KB); per-value decode output
// 65536 (64KB); decode chain levels 3 (base64→json→…); opacity min length 40 chars.
const DEEP_MAX_DEPTH = 8;
const DEEP_MAX_BYTES = 262144;
const DEEP_DECODE_MAX_BYTES = 65536;
const DEEP_DECODE_LEVELS = 3;
const OPAQUE_MIN_LEN = 40;

interface DeepScan {
  contractContent: boolean;   // a contract marker found in a value (raw or decoded)
  pathContractSsot: boolean;  // a contract SSOT path found in a path-like value
  pathNonSsot: boolean;       // a non-SSOT path found (suppressor)
  pathLikeCount: number;      // number of path-like values seen
  proseCount: number;         // path-like values that are prose (README/CHANGELOG/.md/LICENSE)
  opaque: boolean;            // an encoded-looking value that could not be classified
  capHit: boolean;            // depth/byte cap exceeded (un-scannable) — fail-safe trigger
}

/** A short, single-line, filename-ish value we should test against the PATH regexes (never content). */
function looksLikePath(v: string): boolean {
  return v.length > 0 && v.length <= 256 && !/[\n\r{}<>]/.test(v) && /(^|\/)[\w.@-]+\.[A-Za-z0-9]+$/.test(v.trim());
}

/** Bounded set of decodings of a value (base64, hex, url, gzip+base64, json-string-unescape). */
function decodeCandidates(v: string): string[] {
  const out: string[] = [];
  const push = (s: string | null) => { if (s && s.length > 0 && s.length <= DEEP_DECODE_MAX_BYTES) out.push(s); };
  const compact = v.replace(/\s+/g, '');
  // base64 (charset excludes ':' so plaintext YAML/JSON contracts never match)
  if (compact.length >= 16 && compact.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
    try { push(Buffer.from(compact, 'base64').toString('utf8')); } catch { /* ignore */ }
    try { const b = Buffer.from(compact, 'base64'); push(gunzipSync(b).toString('utf8')); } catch { /* not gzip */ }
  }
  // hex
  if (compact.length >= 16 && compact.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(compact)) {
    try { push(Buffer.from(compact, 'hex').toString('utf8')); } catch { /* ignore */ }
  }
  // url-encoded
  if (/%[0-9a-fA-F]{2}/.test(v)) {
    try { push(decodeURIComponent(v)); } catch { /* ignore */ }
  }
  // JSON string literal / double-encoded (unescape one JSON level)
  if (/\\["\\/]|^\s*"/.test(v)) {
    try { const p = JSON.parse(v); if (typeof p === 'string') push(p); } catch { /* ignore */ }
  }
  return out;
}

/** True iff a value looks encoded (long base64/hex) — used to decide opacity when unclassifiable. */
function looksEncoded(v: string): boolean {
  const c = v.replace(/\s+/g, '');
  if (c.length < OPAQUE_MIN_LEN) return false;
  return (/^[A-Za-z0-9+/]+={0,2}$/.test(c) && c.length % 4 === 0) || (/^[0-9a-fA-F]+$/.test(c) && c.length % 2 === 0);
}

/** Recursively scan every string value in `arguments` (any key, depth, array) + bounded decode. */
function deepArgScan(call: ToolCallDescriptor): DeepScan {
  const acc: DeepScan = { contractContent: false, pathContractSsot: false, pathNonSsot: false, pathLikeCount: 0, proseCount: 0, opaque: false, capHit: false };
  let budget = DEEP_MAX_BYTES;

  const scanString = (s: string) => {
    // path-like values -> classify against path regexes (never run path regexes on content).
    if (looksLikePath(s)) {
      acc.pathLikeCount++;
      if (anyMatch(NON_SSOT_PATH_RE, s)) acc.pathNonSsot = true;
      else if (anyMatch(PROSE_PATH_RE, s)) acc.proseCount++;
      else if (isContractPath(s)) acc.pathContractSsot = true;
      return;
    }
    // content: existing contract regexes on the raw value.
    if (anyMatch(CONTRACT_CONTENT_RE, s) || anyMatch(CONTRACT_STRUCTURE_RE, s)) { acc.contractContent = true; return; }
    // bounded decode chain (base64/hex/url/gzip/json), re-scanning each level.
    let level = [s];
    for (let d = 0; d < DEEP_DECODE_LEVELS && !acc.contractContent; d++) {
      const next: string[] = [];
      for (const val of level) {
        for (const dec of decodeCandidates(val)) {
          if (anyMatch(CONTRACT_CONTENT_RE, dec) || anyMatch(CONTRACT_STRUCTURE_RE, dec)) { acc.contractContent = true; break; }
          next.push(dec);
        }
        if (acc.contractContent) break;
      }
      level = next;
    }
    // opacity: looked encoded but nothing classifiable came out -> unscannable -> caution.
    if (!acc.contractContent && looksEncoded(s) && level.every((x) => !isReadableText(x))) acc.opaque = true;
  };

  const walk = (node: unknown, depth: number) => {
    if (acc.capHit || budget <= 0) return;
    if (depth > DEEP_MAX_DEPTH) { acc.capHit = true; return; }
    if (typeof node === 'string') {
      budget -= node.length;
      if (budget <= 0) { acc.capHit = true; return; }
      scanString(node);
    } else if (Array.isArray(node)) {
      for (const el of node) { if (acc.capHit) break; walk(el, depth + 1); }
    } else if (node && typeof node === 'object') {
      for (const val of Object.values(node as Record<string, unknown>)) { if (acc.capHit) break; walk(val, depth + 1); }
    }
  };

  try { walk(call.arguments, 0); } catch { acc.capHit = true; } // scan error -> fail-safe
  return acc;
}

/** A decoded blob that is mostly printable text (so a failed-to-classify decode isn't "opaque"). */
function isReadableText(s: string): boolean {
  if (!s) return false;
  let printable = 0;
  const n = Math.min(s.length, 512);
  for (let i = 0; i < n; i++) { const c = s.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++; }
  return printable / n > 0.85;
}

export const builtinDetector: TriggerDetector = {
  version: DETECTOR_VERSION,
  detect(call: ToolCallDescriptor) {
    const signals: string[] = [];
    const artifacts: Artifact[] = Array.isArray(call.artifacts) ? call.artifacts : [];

    if (artifacts.length > 0) return { trigger: true, artifacts, signals: ['explicit_artifacts'], confident: true };

    if (READ_ONLY_TOOLS.has(String(call.toolName).toLowerCase()) && !commandMutatesContract(call)) {
      return { trigger: false, artifacts: [], signals: ['non_mutating_tool'], confident: true };
    }

    const paths = allPaths(call);
    const contractPath = paths.some(isContractPath);
    const codeContractPath = paths.some((p) => anyMatch(CODE_CONTRACT_PATH_RE, p) && !anyMatch(NON_SSOT_PATH_RE, p));
    const change = changeText(call);
    const inProse = paths.length > 0 && paths.every((p) => anyMatch(PROSE_PATH_RE, p));
    const contentMarker = anyMatch(CONTRACT_CONTENT_RE, change) && !paths.some((p) => anyMatch(NON_SSOT_PATH_RE, p)) && !inProse;
    const shellMutation = commandMutatesContract(call);
    const gate = gateDisabled(call);
    const lockContract = lockfileContractChange(call);

    const contractSurface = contractPath || contentMarker || shellMutation || codeContractPath || gate || lockContract;

    if (contractSurface) {
      if (shellMutation) { signals.push('shell_mutates_contract'); return { trigger: true, artifacts, signals, confident: true }; }
      if (gate) { signals.push('contract_gate_disabled'); return { trigger: true, artifacts, signals, confident: true }; }
      if (lockContract) { signals.push('lockfile_contract_redirect'); return { trigger: true, artifacts, signals, confident: true }; }
      if (isInertOnly(call)) { signals.push('inert_change_only'); return { trigger: false, artifacts: [], signals, confident: true }; }
      if (realChangePresent(call) || contentMarker || anyMatch(CONTRACT_STRUCTURE_RE, change)) {
        signals.push('contract_change'); return { trigger: true, artifacts, signals, confident: true };
      }
      signals.push('ambiguous_contract_surface');
      return { trigger: true, artifacts, signals, confident: false };
    }

    // ── DG-1: deep argument scan (runs AFTER the read-only short-circuit + whitelist surface path;
    // additive, monotonic toward caution — only flips false->true / lowers confident). ──
    const deep = deepArgScan(call);
    if (deep.contractContent || deep.pathContractSsot) {
      // Apply the SAME suppressors to the newly-seen input: non-SSOT / prose destination, inert-only.
      const deepInProse = deep.pathLikeCount > 0 && deep.proseCount === deep.pathLikeCount && !deep.pathContractSsot;
      if (!deep.pathNonSsot && !deepInProse && !isInertOnly(call)) {
        signals.push(deep.contractContent ? 'arguments_deep_contract' : 'arguments_deep_path');
        return { trigger: true, artifacts, signals, confident: false };
      }
    }
    if (deep.opaque || deep.capHit) {
      signals.push(deep.capHit ? 'arguments_scan_capped' : 'arguments_opaque');
      return { trigger: true, artifacts, signals, confident: false };
    }

    if (intentMentionsContract(call.intent)) {
      signals.push('intent_contract_reference');
      return { trigger: true, artifacts, signals, confident: false };
    }

    signals.push('no_contract_signal');
    return { trigger: false, artifacts: [], signals, confident: true };
  },
};
