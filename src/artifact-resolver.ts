/**
 * artifactResolver — automatic base/head contract artifacts from a pure git snapshot (artifact-
 * resolver-SPEC v1.0). The companion to MISSING_ARTIFACT_CONTENT: it answers "where do before/after
 * come from?" by turning `git diff --name-only` + blob reads into `artifacts[] { id, type, before,
 * after }` ready for preflight — OR honest `unresolved[]` entries. It NEVER decides, scores, or
 * touches the fingerprint (§0.1); `report.claim.produces_verdict` is ALWAYS false.
 *
 * PURE + DETERMINISTIC (§0.3): git I/O is the host's job and enters as the `blobs` input; the same
 * snapshot + changedFiles + config yields byte-identical artifacts/unresolved/coverage.
 *
 * Anti-fabrication (§4.2 / A1/A2): a missing $ref target, unreadable blob, or ambiguous SSOT becomes
 * an `unresolved` entry with a code — NEVER an invented component, stub, or half-bundle.
 */

import { parseDoc, stableStringify, YamlLiteError } from './resolver-yaml.js';
import { matchAny, firstMatchIndex } from './resolver-glob.js';

export type ArtifactType = 'openapi' | 'graphql' | 'grpc' | 'asyncapi' | 'mcp_manifest';

export type ResolvedArtifact = { id: string; type: ArtifactType; before: string; after: string };

export type UnresolvedReason =
  | 'unreadable_blob' | 'missing_ref_target' | 'ref_cycle' | 'ref_depth_exceeded'
  | 'ambiguous_ssot' | 'unsupported_encoding' | 'type_ambiguous' | 'empty_changed_contract'
  | 'config_ssot_missing' | 'external_ref_forbidden' | 'parse_error';

export type UnresolvedEntry = { path: string; reason: UnresolvedReason; detail?: string; related_paths?: string[] };

export type ResolveCoverage = 'COMPLETE' | 'PARTIAL' | 'UNRESOLVED' | 'EMPTY';

export type BlobValue = string | null | { error: UnresolvedReason; detail?: string };

export type ResolveInput = {
  repository?: string;
  baseRef: string;
  headRef: string;
  changedFiles: string[];
  /** Pure snapshot keyed `${ref}:${path}` → text | null (absent) | { error }. */
  blobs: Record<string, BlobValue>;
};

export type ResolveConfig = {
  maxRefDepth?: number;
  followExternalRefs?: boolean;
  ssotPrefer?: string[];
  generatedGlobs?: string[];
  pathTypeHints?: Record<string, ArtifactType>;
  allowBinary?: boolean;
  openApiAssembly?: 'bundle_inline' | 'root_only';
  /** Matrix flags (§5.1 pairing / §5 strict SSOT). */
  forceSameSurfaceGroup?: string[];
  requireSsotIfConfigured?: boolean;
};

export type SsotSelection = { chosen: string; deferred: string[]; reason: 'ssotPrefer' | 'generated_deprioritized' | 'single' };

export type ResolveResult = {
  artifacts: ResolvedArtifact[];
  unresolved: UnresolvedEntry[];
  coverage: ResolveCoverage;
  report: {
    version: 'artifact-resolver-report/1.0';
    baseRef: string;
    headRef: string;
    contract_paths_discovered: string[];
    ignored_non_contract: string[];
    ssot_selections: SsotSelection[];
    claim: { artifacts_ready_for_preflight: boolean; produces_verdict: false };
  };
};

const DEFAULT_GENERATED = ['**/generated/**', '**/gen/**'];
const VENDOR_GLOBS = ['**/node_modules/**', '**/vendor/**'];

// ── path helpers (POSIX) ─────────────────────────────────────────────────────────────────────────
function normalizePath(p: string): string {
  let s = p.replace(/\\/g, '/').trim();
  while (s.startsWith('./')) s = s.slice(2);
  return s;
}
function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}
function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}
function extname(p: string): string {
  const b = basename(p);
  const i = b.lastIndexOf('.');
  return i === -1 ? '' : b.slice(i + 1).toLowerCase();
}
function resolveRelative(dir: string, rel: string): string {
  const parts = (dir ? dir.split('/') : []).concat(normalizePath(rel).split('/'));
  const out: string[] = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return out.join('/');
}

// ── discovery (§2) ──────────────────────────────────────────────────────────────────────────────
/**
 * Path → ArtifactType from the filename only (no content sniff). Exported so binder-level
 * lifting can reuse the SAME table as resolve() without inventing a second extension map.
 * Returns null when the path is not a known contract-artifact name (e.g. README.md).
 */
export function classifyByName(path: string): ArtifactType | null {
  const b = basename(path).toLowerCase();
  const ext = extname(path);
  const yamlJson = ext === 'yaml' || ext === 'yml' || ext === 'json';
  if (yamlJson && (b.includes('openapi') || b.includes('swagger'))) return 'openapi';
  if (yamlJson && b.includes('asyncapi')) return 'asyncapi';
  if (ext === 'graphql' || ext === 'gql') return 'graphql';
  if (ext === 'proto') return 'grpc';
  if (b === 'mcp.json' || b === 'tools-catalog.json') return 'mcp_manifest';
  return null;
}
function classifyByContent(text: string | undefined): ArtifactType | null {
  if (!text) return null;
  if (/(^|\n)\s*["']?openapi["']?\s*:\s*["']?[23]/.test(text) || (/swagger\s*:/.test(text) && /paths\s*:/.test(text))) return 'openapi';
  if (/(^|\n)\s*["']?asyncapi["']?\s*:/.test(text)) return 'asyncapi';
  if (/\btype\s+Query\b|\btype\s+Mutation\b|\bschema\s*\{/.test(text)) return 'graphql';
  if (/syntax\s*=\s*["']proto[23]["']/.test(text)) return 'grpc';
  try {
    const j = JSON.parse(text);
    if (j && Array.isArray(j.tools) && j.tools.some((t: unknown) => t && typeof t === 'object' && 'inputSchema' in (t as object))) return 'mcp_manifest';
  } catch { /* not json */ }
  return null;
}
/** *mcp*.json (not exactly mcp.json) needs a content check (tools + inputSchema) per the §2.3 table. */
function isMcpByNameNeedingContent(path: string): boolean {
  const b = basename(path).toLowerCase();
  return extname(path) === 'json' && b.includes('mcp') && b !== 'mcp.json';
}

// ── $ref scanning + bounded inliner (§4) ──────────────────────────────────────────────────────────
const REF_RE = /\$ref["']?\s*:\s*["']?([^"'\s,}]+)["']?/g;
function scanRefs(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  REF_RE.lastIndex = 0;
  while ((m = REF_RE.exec(text)) !== null) out.push(m[1]);
  return out;
}
function isExternalRef(ref: string): boolean { return /^[a-z][a-z0-9+.-]*:\/\//i.test(ref) || ref.startsWith('//'); }
function isInternalRef(ref: string): boolean { return ref.startsWith('#'); }
function splitRef(ref: string): { file: string; pointer: string } {
  const i = ref.indexOf('#');
  return i === -1 ? { file: ref, pointer: '' } : { file: ref.slice(0, i), pointer: ref.slice(i + 1) };
}
function jsonPointer(doc: unknown, pointer: string): unknown {
  if (pointer === '' || pointer === '/') return doc;
  const parts = pointer.replace(/^\//, '').split('/').map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'));
  let cur: unknown = doc;
  for (const part of parts) {
    if (cur && typeof cur === 'object' && part in (cur as Record<string, unknown>)) cur = (cur as Record<string, unknown>)[part];
    else return undefined;
  }
  return cur;
}
function slugify(s: string): string { return s.replace(/[^A-Za-z0-9]+/g, '_'); }

class RefError extends Error {
  reason: UnresolvedReason;
  related?: string;
  constructor(reason: UnresolvedReason, related?: string) { super(reason); this.reason = reason; this.related = related; }
}

/** Assemble one side (base/head) into a deterministic JSON bundle. Throws RefError on any ref failure. */
function assembleSide(
  rootPath: string, rootText: string, refSide: string, input: ResolveInput, config: ResolveConfig, deps: Set<string>,
): string {
  const maxDepth = config.maxRefDepth ?? 8;
  let root: unknown;
  try { root = parseDoc(rootText); } catch (e) {
    if (e instanceof YamlLiteError) throw new RefError('parse_error');
    throw e;
  }
  const components: Record<string, unknown> = {};

  const inline = (node: unknown, curDir: string, depth: number, stack: Set<string>): unknown => {
    if (Array.isArray(node)) return node.map((n) => inline(n, curDir, depth, stack));
    if (node && typeof node === 'object') {
      const rec = node as Record<string, unknown>;
      if (typeof rec.$ref === 'string') {
        const ref = rec.$ref;
        if (isExternalRef(ref)) throw new RefError('external_ref_forbidden'); // v1: out of pure-git scope
        if (isInternalRef(ref)) return { ...rec }; // JSON pointer within doc — self-contained, kept as-is
        const { file, pointer } = splitRef(ref);
        const targetPath = resolveRelative(curDir, file);
        const key = `${targetPath}#${pointer}`;
        if (depth + 1 > maxDepth) throw new RefError('ref_depth_exceeded', targetPath);
        if (stack.has(key)) throw new RefError('ref_cycle', targetPath);
        const blob = getBlob(input, refSide, targetPath);
        if (blob === null || blob === undefined) throw new RefError('missing_ref_target', targetPath);
        if (typeof blob === 'object') throw new RefError(blob.error, targetPath);
        deps.add(targetPath);
        let targetDoc: unknown;
        try { targetDoc = parseDoc(blob); } catch { throw new RefError('parse_error', targetPath); }
        const resolved = jsonPointer(targetDoc, pointer);
        if (resolved === undefined) throw new RefError('missing_ref_target', targetPath);
        const inlined = inline(resolved, dirname(targetPath), depth + 1, new Set([...stack, key]));
        const slug = slugify(`${targetPath}__${pointer}`);
        components[slug] = inlined;
        return { $ref: `#/components/${slug}` };
      }
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(rec)) out[k] = inline(rec[k], curDir, depth, stack);
      return out;
    }
    return node;
  };

  const inlinedRoot = inline(root, dirname(rootPath), 0, new Set()) as Record<string, unknown>;
  if (Object.keys(components).length > 0) {
    const existing = (inlinedRoot.components && typeof inlinedRoot.components === 'object') ? inlinedRoot.components as Record<string, unknown> : {};
    inlinedRoot.components = { ...existing, ...components };
  }
  return stableStringify(inlinedRoot);
}

// ── blob access ───────────────────────────────────────────────────────────────────────────────
function getBlob(input: ResolveInput, ref: string, path: string): BlobValue | undefined {
  return input.blobs[`${ref}:${path}`];
}

// ── load a selected root → artifact | unresolved (§3 + §4) ─────────────────────────────────────
type LoadResult = { artifact: ResolvedArtifact; deps: string[] } | { unresolved: UnresolvedEntry };

function loadRoot(path: string, type: ArtifactType, input: ResolveInput, config: ResolveConfig): LoadResult {
  const baseBlob = getBlob(input, input.baseRef, path);
  const headBlob = getBlob(input, input.headRef, path);

  if (baseBlob && typeof baseBlob === 'object') return { unresolved: { path, reason: baseBlob.error } };
  if (headBlob && typeof headBlob === 'object') return { unresolved: { path, reason: headBlob.error } };

  const baseNull = baseBlob === null || baseBlob === undefined;
  const headNull = headBlob === null || headBlob === undefined;
  if (baseNull && headNull) return { unresolved: { path, reason: 'empty_changed_contract' } };

  let before = baseNull ? '' : (baseBlob as string);
  let after = headNull ? '' : (headBlob as string);
  const deps = new Set<string>();

  const assemble = (type === 'openapi' || type === 'asyncapi') && (config.openApiAssembly ?? 'bundle_inline') === 'bundle_inline';
  if (assemble) {
    try {
      if (before !== '' && scanRefs(before).some((r) => !isInternalRef(r))) before = assembleSide(path, before, input.baseRef, input, config, deps);
      if (after !== '' && scanRefs(after).some((r) => !isInternalRef(r))) after = assembleSide(path, after, input.headRef, input, config, deps);
    } catch (e) {
      if (e instanceof RefError) return { unresolved: { path, reason: e.reason, ...(e.related ? { related_paths: [e.related] } : {}) } };
      throw e;
    }
  }

  const id = input.repository ? `${input.repository}:${type}:${path}` : `${type}:${path}`;
  return { artifact: { id, type, before, after }, deps: [...deps] };
}

// ── SSOT grouping (union-find) + selection (§5) ─────────────────────────────────────────────────
type Candidate = { path: string; type: ArtifactType };

function selectGroups(candidates: Candidate[], config: ResolveConfig, generatedGlobs: string[]):
{ selections: SsotSelection[]; chosen: Candidate[]; ambiguous: string[] } {
  const n = candidates.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; };
  const union = (a: number, b: number) => { const ra = find(a); const rb = find(b); if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb); };

  // forceSameSurfaceGroup: union all listed candidates.
  if (Array.isArray(config.forceSameSurfaceGroup)) {
    const idxs = candidates.map((c, i) => (config.forceSameSurfaceGroup!.includes(c.path) ? i : -1)).filter((i) => i >= 0);
    for (let k = 1; k < idxs.length; k += 1) union(idxs[0], idxs[k]);
  }
  // generated↔source auto-pairing: per type, if the type mixes generated + non-generated → union all.
  const byType = new Map<ArtifactType, number[]>();
  candidates.forEach((c, i) => { const a = byType.get(c.type) ?? []; a.push(i); byType.set(c.type, a); });
  for (const idxs of byType.values()) {
    const gen = idxs.filter((i) => matchAny(generatedGlobs, candidates[i].path));
    if (gen.length > 0 && gen.length < idxs.length) for (let k = 1; k < idxs.length; k += 1) union(idxs[0], idxs[k]);
  }

  const groups = new Map<number, number[]>();
  for (let i = 0; i < n; i += 1) { const r = find(i); const g = groups.get(r) ?? []; g.push(i); groups.set(r, g); }

  const selections: SsotSelection[] = [];
  const chosen: Candidate[] = [];
  const ambiguous: string[] = [];

  for (const g of groups.values()) {
    const members = g.map((i) => candidates[i].path).sort();
    if (members.length === 1) {
      chosen.push(candidates[g[0]]);
      selections.push({ chosen: members[0], deferred: [], reason: 'single' });
      continue;
    }
    // ssotPrefer first-match wins.
    const prefRanked = members.map((p) => ({ p, rank: firstMatchIndex(config.ssotPrefer, p) })).filter((x) => x.rank >= 0);
    if (prefRanked.length > 0) {
      prefRanked.sort((a, b) => (a.rank - b.rank) || (a.p < b.p ? -1 : 1));
      const chosenPath = prefRanked[0].p;
      chosen.push(candidates[g.find((i) => candidates[i].path === chosenPath)!]);
      selections.push({ chosen: chosenPath, deferred: members.filter((m) => m !== chosenPath), reason: 'ssotPrefer' });
      continue;
    }
    // generated deprioritization: exactly one non-generated source wins.
    const nongen = members.filter((p) => !matchAny(generatedGlobs, p));
    if (nongen.length === 1) {
      const chosenPath = nongen[0];
      chosen.push(candidates[g.find((i) => candidates[i].path === chosenPath)!]);
      selections.push({ chosen: chosenPath, deferred: members.filter((m) => m !== chosenPath), reason: 'generated_deprioritized' });
      continue;
    }
    // else ambiguous — no pick-by-guess.
    ambiguous.push(...members);
  }
  return { selections, chosen, ambiguous };
}

// ── the pure resolve (§1.1) ─────────────────────────────────────────────────────────────────────
export function resolve(input: ResolveInput, config: ResolveConfig = {}): ResolveResult {
  const generatedGlobs = config.generatedGlobs ?? DEFAULT_GENERATED;

  // 1-2. normalize + stable-dedupe changedFiles.
  const seen = new Set<string>();
  const paths: string[] = [];
  for (const raw of (Array.isArray(input.changedFiles) ? input.changedFiles : [])) {
    const p = normalizePath(raw);
    if (p && !seen.has(p)) { seen.add(p); paths.push(p); }
  }

  // 3-4. discover contract candidates vs ignored non-contract.
  const candidates: Candidate[] = [];
  const ignored: string[] = [];
  for (const p of paths) {
    if (matchAny(VENDOR_GLOBS, p)) { ignored.push(p); continue; }
    let type: ArtifactType | null = config.pathTypeHints?.[p] ?? classifyByName(p);
    if (type === null || isMcpByNameNeedingContent(p)) {
      const peek = firstDefinedText(getBlob(input, input.headRef, p), getBlob(input, input.baseRef, p));
      const sniff = classifyByContent(peek);
      if (isMcpByNameNeedingContent(p)) type = sniff === 'mcp_manifest' ? 'mcp_manifest' : (type ?? sniff);
      else type = sniff;
    }
    if (type) candidates.push({ path: p, type });
    else ignored.push(p);
  }

  const unresolved: UnresolvedEntry[] = [];
  let effectiveCandidates = candidates;

  // strict SSOT: a required, declared, exact ssotPrefer path that is absent → config_ssot_missing.
  if (config.requireSsotIfConfigured && Array.isArray(config.ssotPrefer)) {
    const missing = config.ssotPrefer.filter((pref) => !hasGlobChar(pref) && !existsInTree(input, pref));
    const hasGenerated = candidates.some((c) => matchAny(generatedGlobs, c.path));
    if (missing.length > 0 && hasGenerated) {
      for (const pref of missing) unresolved.push({ path: pref, reason: 'config_ssot_missing' });
      effectiveCandidates = candidates.filter((c) => !matchAny(generatedGlobs, c.path)); // deprioritized generated suppressed
    }
  }

  // 5. SSOT grouping + selection.
  const { selections, chosen, ambiguous } = selectGroups(effectiveCandidates, config, generatedGlobs);
  for (const p of [...new Set(ambiguous)].sort()) unresolved.push({ path: p, reason: 'ambiguous_ssot' });

  // 7. load each selected root → artifact | unresolved; reclassify $ref dependency files.
  const artifacts: ResolvedArtifact[] = [];
  const selBySel = new Map(selections.map((s) => [s.chosen, s]));
  for (const c of chosen.slice().sort((a, b) => (a.path < b.path ? -1 : 1))) {
    const res = loadRoot(c.path, c.type, input, config);
    if ('artifact' in res) {
      artifacts.push(res.artifact);
      const sel = selBySel.get(c.path);
      for (const dep of res.deps) {
        const idx = ignored.indexOf(dep);
        if (idx >= 0) ignored.splice(idx, 1);
        if (sel && !sel.deferred.includes(dep) && dep !== c.path) sel.deferred.push(dep);
      }
      if (sel) sel.deferred.sort();
    } else {
      unresolved.push(res.unresolved);
    }
  }

  // 6/7. coverage (§7).
  const A = artifacts.length;
  const U = unresolved.length;
  const chosenCount = chosen.length;
  let coverage: ResolveCoverage;
  if (chosenCount === 0 && U === 0) coverage = 'EMPTY';
  else if (U === 0 && A >= 1 && A === chosenCount) coverage = 'COMPLETE';
  else if (A >= 1 && U >= 1) coverage = 'PARTIAL';
  else coverage = 'UNRESOLVED';

  // sort outputs deterministically (§6).
  artifacts.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  unresolved.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : (a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : 0)));
  ignored.sort();
  const contractDiscovered = effectiveCandidates.map((c) => c.path).slice().sort();

  return {
    artifacts,
    unresolved,
    coverage,
    report: {
      version: 'artifact-resolver-report/1.0',
      baseRef: input.baseRef,
      headRef: input.headRef,
      contract_paths_discovered: contractDiscovered,
      ignored_non_contract: ignored,
      ssot_selections: selections,
      claim: {
        artifacts_ready_for_preflight: coverage === 'COMPLETE' || coverage === 'EMPTY',
        produces_verdict: false,
      },
    },
  };
}

function firstDefinedText(...vals: (BlobValue | undefined)[]): string | undefined {
  for (const v of vals) if (typeof v === 'string') return v;
  return undefined;
}
function hasGlobChar(p: string): boolean { return /[*?]/.test(p); }
function existsInTree(input: ResolveInput, path: string): boolean {
  return typeof getBlob(input, input.baseRef, path) === 'string' || typeof getBlob(input, input.headRef, path) === 'string';
}
