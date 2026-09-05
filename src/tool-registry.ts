/**
 * guardToolRegistry — the agent-runtime tool-table boundary (guard-tool-registry-SPEC v1.0).
 *
 * The layer ABOVE the shipped `guardToolCall`: it takes the host's raw tool list and returns a tool
 * table in which every mutating capability is wrapped so it cannot execute without entering
 * `guardToolCall`, and construction FAILS CLOSED if a mutator would remain raw. That is a property
 * of the returned table — tools the host registers elsewhere are outside it.
 *
 * Scope honesty (enforcement-architecture §1): this secures **Placement A — the agent-host runtime
 * tool boundary ONLY**. It NEVER claims merge (Placement B / sibling #7) or deploy inescapability;
 * `claim.inescapable_merge` / `claim.inescapable_deploy` are ALWAYS false here.
 *
 * Determinism (§7): same tool names + classes + config flags → same registry, coverage, guarded set.
 * Anti-fabrication: unknown tools default to MUTATING (never a false COMPLETE); never invent a tool.
 * Non-leakage (§1.2): each raw `execute` is captured in a NEW closure, is never a property of the
 * returned ProtectedTool, the tools array + each tool are frozen, and raw executors live only in a
 * WeakMap keyed by the protected object. `result.tools` is the sole return surface.
 */

import { guardToolCall } from './guard.js';
import type { GuardConfig, ToolCallDescriptor, DecisionResultEnvelope, Artifact } from './types.js';
import { classifyByName } from './artifact-resolver.js';
import type { ArtifactType } from './artifact-resolver.js';
import { collectFreshnessCallContext } from './freshness.js';
import { runAutoRecheckLoop, normalizeAutoRecheck } from './auto-recheck.js';
import { normalizeAutoDerive, runAutoDerive, attachDerivation } from './auto-derive.js';
import type { AutoDeriveObservation } from './auto-derive.js';
import { measureFsAuthorization, wrapWriteWithFsCas } from './cas-adapters/fs-default-wire.js';

// ── public types (§1.1) ─────────────────────────────────────────────────────────────────────────
export type ToolMutationClass =
  | 'readonly'
  | 'mutating'
  | 'mutating_shell'
  | 'mutating_vcs'
  | 'mutating_deploy'
  | 'mutating_publish'
  | 'mutating_schema';

export type RawTool = {
  name: string;
  description?: string;
  inputSchema?: unknown;
  execute: (
    args: unknown,
    execution?: import('./types.js').ExecutionGrantCallContext,
  ) => Promise<unknown> | unknown;
  mutationClass?: ToolMutationClass;
  meta?: Record<string, unknown>;
};

export type ProtectedTool = {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
  readonly meta?: Record<string, unknown>;
  /** The ONLY entry point exposed to the agent runtime (guarded for mutators, direct for readonly). */
  readonly execute: (args: unknown) => Promise<unknown>;
  readonly _coderifts: {
    readonly guarded: boolean;
    readonly mutationClass: ToolMutationClass;
    /** guard operation bound for this tool (diagnostic; mutators only). */
    readonly operation?: string;
  };
};

export type EnforcementCoverage = 'COMPLETE' | 'PARTIAL' | 'BYPASSED' | 'UNKNOWN';

export type RegistryCoverageReport = {
  version: 'guard-tool-registry-report/1.0';
  coverage: EnforcementCoverage;
  protected_tools: string[];
  guarded_mutators: string[];
  readonly_passthrough: string[];
  unguarded_mutators: string[];
  unknown_treated_as: 'mutating' | 'readonly' | 'reject';
  claim: {
    inescapable_runtime: boolean;
    inescapable_merge: false;
    inescapable_deploy: false;
  };
  siblings: {
    merge_gate: 'required_separate_#7';
    artifact_resolver: 'sibling_#4';
  };
  warnings: string[];
};

export type ToolBinder = (tool: RawTool, args: unknown, cls: ToolMutationClass) => ToolCallDescriptor;

export type GuardToolRegistryConfig = {
  guard?: GuardConfig;
  unknownToolPolicy?: 'mutating' | 'readonly' | 'reject';
  classify?: Record<string, ToolMutationClass>;
  failOnUnguardedMutator?: boolean;
  binders?: Record<string, ToolBinder>;
  forceReadonly?: string[];
};

export type RegistryResult = {
  tools: ProtectedTool[];
  coverage: EnforcementCoverage;
  report: RegistryCoverageReport;
};

export type RegistryConstructionErrorCode =
  | 'GUARD_CONFIG_INVALID'
  | 'UNKNOWN_TOOL'
  | 'DUPLICATE_TOOL_NAME'
  | 'INVALID_TOOL'
  | 'FORCE_READONLY_MUTATOR';

/** Fail-closed construction error (§3) — thrown at CONSTRUCTION, never at first agent call. */
export class RegistryConstructionError extends Error {
  readonly code: RegistryConstructionErrorCode;
  readonly toolName?: string;
  constructor(code: RegistryConstructionErrorCode, message: string, toolName?: string) {
    super(message);
    this.name = 'RegistryConstructionError';
    this.code = code;
    this.toolName = toolName;
  }
}

// ── §2.3 conservative name heuristics (case-insensitive substring; subclasses before generic) ─────
const MUTATING_GENERIC = ['write', 'edit', 'create', 'update', 'delete', 'remove', 'apply_patch', 'applypatch', 'str_replace', 'notebook_edit', 'multi_edit', 'insert'];
const MUTATING_SHELL = ['bash', 'shell', 'terminal', 'run_command', 'exec', 'powershell'];
const MUTATING_VCS = ['git_commit', 'git_push', 'git_merge', 'commit', 'push'];
const MUTATING_DEPLOY = ['deploy', 'kubectl_apply', 'helm_upgrade', 'release'];
const MUTATING_PUBLISH = ['npm_publish', 'publish_package', 'twine_upload', 'cargo_publish'];
const MUTATING_SCHEMA = ['register_tools', 'update_manifest', 'mcp_register'];
const READONLY = ['read', 'grep', 'glob', 'search', 'list', 'ls', 'cat', 'get', 'fetch', 'web_search', 'browser_navigate'];

const MUTATING_CLASSES: ToolMutationClass[] = ['mutating', 'mutating_shell', 'mutating_vcs', 'mutating_deploy', 'mutating_publish', 'mutating_schema'];
function isMutatingClass(cls: ToolMutationClass): boolean {
  return cls !== 'readonly';
}

function matchesAny(hay: string, patterns: string[]): boolean {
  return patterns.some((p) => hay.includes(p));
}

/**
 * §2.3 heuristic class from the NAME (subclasses checked before the generic table; MUTATING WINS over
 * a readonly substring). Returns null when nothing matches (→ unknownPolicy path §2.1 step 6).
 */
function heuristicClass(name: string): ToolMutationClass | null {
  const n = String(name || '').toLowerCase();
  if (matchesAny(n, MUTATING_SHELL)) return 'mutating_shell';
  if (matchesAny(n, MUTATING_VCS) || n.startsWith('git_')) return 'mutating_vcs';
  if (matchesAny(n, MUTATING_DEPLOY)) return 'mutating_deploy';
  if (matchesAny(n, MUTATING_PUBLISH)) return 'mutating_publish';
  if (matchesAny(n, MUTATING_SCHEMA)) return 'mutating_schema';
  if (matchesAny(n, MUTATING_GENERIC)) return 'mutating';       // includes fetch_and_write → 'write' → mutating wins
  if (matchesAny(n, READONLY)) return 'readonly';
  return null;
}

type Resolution = {
  cls: ToolMutationClass;
  source: 'classify' | 'mutationClass' | 'forceReadonly' | 'heuristic' | 'unknown';
};

/** §2.1 EXACT resolution order. Throws UNKNOWN_TOOL when unclassified under unknownToolPolicy 'reject'. */
function resolveClass(tool: RawTool, config: GuardToolRegistryConfig, unknownPolicy: 'mutating' | 'readonly' | 'reject'): Resolution {
  const classify = config.classify || {};
  if (Object.prototype.hasOwnProperty.call(classify, tool.name)) return { cls: classify[tool.name], source: 'classify' };
  if (tool.mutationClass) return { cls: tool.mutationClass, source: 'mutationClass' };
  if (Array.isArray(config.forceReadonly) && config.forceReadonly.includes(tool.name)) return { cls: 'readonly', source: 'forceReadonly' };
  const h = heuristicClass(tool.name);
  if (h) return { cls: h, source: 'heuristic' };
  if (unknownPolicy === 'reject') {
    throw new RegistryConstructionError('UNKNOWN_TOOL', `tool '${tool.name}' is unclassified and unknownToolPolicy='reject'`, tool.name);
  }
  return { cls: unknownPolicy === 'readonly' ? 'readonly' : 'mutating', source: 'unknown' };
}

/** §4 — guard operation bound per class (deploy MUST be 'deploy'; §106 T7 a merge receipt is insufficient). */
function operationForClass(cls: ToolMutationClass, name: string, guardOperation?: string): string {
  switch (cls) {
    case 'mutating_shell': return 'tool_call';
    case 'mutating_vcs': return /merge/i.test(name) ? 'merge' : 'tool_call';
    case 'mutating_deploy': return 'deploy';
    case 'mutating_publish': return 'publish';
    case 'mutating_schema': return 'tool_call';
    case 'mutating':
    default: return guardOperation ?? 'tool_call';
  }
}

/**
 * Default binder (S3 layer 1): promote host-supplied content onto the descriptor.
 *
 * 1) args.artifacts — always wins when present (L6). Never merge with synthesised edit sides.
 * 2) Explicit edit sides the host ALREADY supplied (str_replace-style):
 *      a) args.old_string + args.new_string + args.path
 *      b) args.edits[] entries each with old_string + new_string + args.path
 *    Both sides must be non-empty strings. Path must classify as a contract artifact via
 *    classifyByName (artifact-resolver). Nothing is invented — this is renaming onto artifacts[].
 *
 * LIMITATION (documented, intentional): the lifted before/after are EDIT FRAGMENTS (old_string /
 * new_string as the agent emitted them), NOT whole specification files. The server will preflight a
 * partial document. A later host-snapshot layer can supply full-file before/after; that is a
 * different and better source and must not be confused with this rename-only lift.
 *
 * Why BOTH sides must be non-empty: hasAnalyzableContent is an OR (before OR after non-empty).
 * An artifact with empty/missing before and a real after would PASS the local check and reach the
 * server as a one-sided pair — a create/replace where the truth is an edit. That is a fabricated
 * before by omission. We refuse to lift rather than cross that line.
 */
function defaultBinder(tool: RawTool, args: unknown): ToolCallDescriptor {
  const d: ToolCallDescriptor = { toolName: tool.name, arguments: args };
  if (!args || typeof args !== 'object') return d;
  const a = args as Record<string, unknown>;

  // Host-supplied artifacts always win — forward only, never merge with edit-side synthesis.
  if (Array.isArray(a.artifacts)) {
    d.artifacts = a.artifacts as ToolCallDescriptor['artifacts'];
    return d;
  }

  const path = typeof a.path === 'string' ? a.path : '';
  if (!path) return d; // no path → no id/type; guessing either would be inference

  // Type + "is this a contract-artifact path" from the resolver's existing path classifier only.
  // null ⇒ not a known contract-artifact name (e.g. README.md) ⇒ do not lift.
  const type: ArtifactType | null = classifyByName(path);
  if (!type) return d;

  const bothSides = (oldS: unknown, newS: unknown): boolean =>
    typeof oldS === 'string' && oldS.length > 0
    && typeof newS === 'string' && newS.length > 0;

  // Multi-edit: one artifact per entry that has both non-empty sides (fragments, not whole files).
  if (Array.isArray(a.edits)) {
    const lifted: Artifact[] = [];
    for (let i = 0; i < a.edits.length; i++) {
      const e = a.edits[i];
      if (!e || typeof e !== 'object') continue;
      const er = e as Record<string, unknown>;
      if (!bothSides(er.old_string, er.new_string)) continue; // never one-sided
      lifted.push({
        id: `${type}:${path}#${i}`,
        type,
        before: er.old_string as string,
        after: er.new_string as string,
      });
    }
    if (lifted.length > 0) d.artifacts = lifted;
    return d;
  }

  // Single str_replace-style edit.
  if (bothSides(a.old_string, a.new_string)) {
    d.artifacts = [{
      id: `${type}:${path}`,
      type,
      before: a.old_string as string,
      after: a.new_string as string,
    }];
  }
  return d;
}

// raw executors kept OFF the protected object (§1.2 opaque handle).
const RAW_EXECUTORS = new WeakMap<ProtectedTool, RawTool['execute']>();

function freezeTool(t: ProtectedTool): ProtectedTool {
  Object.freeze(t._coderifts);
  return Object.freeze(t);
}

/** readonly passthrough: exposed execute is a NEW closure over raw.execute; guarded=false; no preflight. */
function passthroughProtected(tool: RawTool, cls: ToolMutationClass): ProtectedTool {
  const rawExecute = tool.execute;
  const protectedTool: ProtectedTool = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    meta: tool.meta,
    execute: async (args: unknown) => rawExecute(args),   // new function, not === rawExecute
    _coderifts: { guarded: false, mutationClass: cls },
  };
  RAW_EXECUTORS.set(protectedTool, rawExecute);
  return freezeTool(protectedTool);
}

/** §1.4 — mutator wrapped so EVERY invocation enters guardToolCall before raw.execute. guarded=true. */
function wrapWithGuard(tool: RawTool, cls: ToolMutationClass, config: GuardToolRegistryConfig): ProtectedTool {
  const rawExecute = tool.execute;
  const guardBase = config.guard as GuardConfig;
  const operation = operationForClass(cls, tool.name, guardBase.operation);
  const guardCfg: GuardConfig = { ...guardBase, operation };
  const binder: ToolBinder = (config.binders && config.binders[tool.name]) || ((t, a) => defaultBinder(t, a));

  const protectedTool: ProtectedTool = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
    meta: tool.meta,
    execute: async (args: unknown) => {
      const deriveCfg = normalizeAutoDerive(guardCfg.autoDerive);
      // 1375 — stamp the class the registry ALREADY resolved onto the descriptor. A custom binder
      // may legitimately rebuild the descriptor and drop it, so it is applied after the binder, not
      // inside it; a binder that deliberately sets its own class keeps it.
      const rebindRaw = () => {
        const c = binder(tool, args, cls);
        return c && c.mutationClass === undefined ? { ...c, mutationClass: cls } : c;
      };
      let lastDerivation: AutoDeriveObservation['derivation'] | null = null;
      const rebind = async () => {
        const c = rebindRaw();
        if (!deriveCfg) return c;
        const d = await runAutoDerive({
          bound: c,
          rawArgs: args,
          cfg: deriveCfg,
          config: guardCfg,
        });
        lastDerivation = d.derivation;
        return d.call;
      };
      const rebindAndRemeasure = async () => {
        const c = await rebind();
        casAuth = await measureFsAuthorization(args);
        return c;
      };
      const call = await rebind();
      // RUNNER collects prior content (async host I/O) and passes VALUES into the pure guard path.
      // The guard never invokes resolvePriorContent itself.
      const refreshContext = async (c: ToolCallDescriptor) => collectFreshnessCallContext({
        call: {
          toolName: c.toolName,
          artifacts: c.artifacts,
          arguments: c.arguments,
        },
        resolvePriorContent: guardCfg.resolvePriorContent,
      });
      const fctx = await refreshContext(call);
      // T1 CAS MEASUREMENT — taken HERE, in the runner, before preflight, alongside the freshness
      // collection. It must not be taken inside the factory: a token read at write time describes
      // whatever state the file holds then, not the state the authorization examined, which is the
      // vacuous window measured on 12.0.0. Re-measured on rebind (below) so an auto-recheck loop
      // conditions on the state IT authorized rather than on the first pass's.
      let casAuth = await measureFsAuthorization(args);
      const factory = async (
        _envelope: DecisionResultEnvelope | null,
        redacted: ToolCallDescriptor,
        execution?: import('./types.js').ExecutionGrantCallContext,
      ) => {
        const rawArgs = redacted ? redacted.arguments : args;
        return wrapWriteWithFsCas(
          rawArgs,
          () => (execution ? rawExecute(rawArgs, execution) : rawExecute(rawArgs)),
          casAuth
            ? { expected_token: casAuth.expected_token, expected_identity: casAuth.expected_identity }
            : {},
        );
      };
      const outcome = normalizeAutoRecheck(guardCfg.autoRecheck)
        ? await runAutoRecheckLoop({
          call,
          factory,
          config: guardCfg,
          callContext: fctx,
          rebind: rebindAndRemeasure,
          refreshContext,
        })
        : await guardToolCall(call, factory, guardCfg, fctx);
      return attachDerivation(outcome, lastDerivation);
    },
    _coderifts: { guarded: true, mutationClass: cls, operation },
  };
  RAW_EXECUTORS.set(protectedTool, rawExecute);
  return freezeTool(protectedTool);
}

/**
 * Construct the frozen, fail-closed protected tool registry (§1.3). Pure + deterministic.
 * @throws {RegistryConstructionError} per §3 (default failOnUnguardedMutator=true).
 */
export function guardToolRegistry(rawTools: RawTool[], config: GuardToolRegistryConfig = {}): RegistryResult {
  const failHard = config.failOnUnguardedMutator !== false; // default true
  const unknownPolicy = config.unknownToolPolicy ?? 'mutating';

  const input = Array.isArray(rawTools) ? rawTools : [];

  // §3 INVALID_TOOL — missing execute (not a function) or empty name.
  for (const tool of input) {
    if (!tool || typeof tool.name !== 'string' || tool.name.trim() === '') {
      throw new RegistryConstructionError('INVALID_TOOL', 'a tool has a missing or empty name');
    }
    if (typeof tool.execute !== 'function') {
      throw new RegistryConstructionError('INVALID_TOOL', `tool '${tool.name}' has no execute function`, tool.name);
    }
  }

  // §3 DUPLICATE_TOOL_NAME.
  const seen = new Set<string>();
  for (const tool of input) {
    if (seen.has(tool.name)) {
      throw new RegistryConstructionError('DUPLICATE_TOOL_NAME', `duplicate tool name '${tool.name}'`, tool.name);
    }
    seen.add(tool.name);
  }

  // determinism: sort by name ASC (§1.3).
  const sorted = input.slice().sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const guardedMutators: string[] = [];
  const readonlyPassthrough: string[] = [];
  const warnings: string[] = [];
  const staged: Array<{ tool: RawTool; cls: ToolMutationClass; forced: boolean }> = [];
  let anyForced = false;
  let anyUnknownReadonly = false;

  for (const tool of sorted) {
    const { cls, source } = resolveClass(tool, config, unknownPolicy); // may throw UNKNOWN_TOOL
    // §1.5 forced-readonly-on-mutator (break-glass): resolved readonly via an OVERRIDE while the NAME
    // heuristic is a real mutator. Trusted self-declaration (tool.mutationClass) is NOT forced.
    const forced = cls === 'readonly'
      && (source === 'classify' || source === 'forceReadonly')
      && isMutating(heuristicClass(tool.name));
    if (forced) {
      anyForced = true;
      warnings.push(`force_readonly_on_mutator_heuristic:${tool.name}`);
    }
    // forceReadonly listed this tool but resolution took explicit mutationClass first — break-glass
    // request was silently a no-op. Emit a warning so callers are not given false safety.
    if (
      Array.isArray(config.forceReadonly)
      && config.forceReadonly.includes(tool.name)
      && source === 'mutationClass'
    ) {
      warnings.push(`force_readonly_ignored_explicit_mutation_class:${tool.name}`);
    }
    if (source === 'unknown' && cls === 'readonly') anyUnknownReadonly = true;
    staged.push({ tool, cls, forced });
  }

  // §3 FORCE_READONLY_MUTATOR — break-glass open under default failHard ⇒ cannot claim inescapability.
  if (anyForced && failHard) {
    throw new RegistryConstructionError('FORCE_READONLY_MUTATOR', `forceReadonly/classify downgraded a heuristic mutator to readonly while failOnUnguardedMutator is true`);
  }

  // §3 GUARD_CONFIG_INVALID — a mutator will be wrapped but no valid guard.client to wrap it with.
  const willWrap = staged.some((s) => isMutating(s.cls) && !s.forced);
  const validGuard = !!(config.guard && (config.guard as GuardConfig).client);
  if (willWrap && !validGuard) {
    throw new RegistryConstructionError('GUARD_CONFIG_INVALID', 'a mutating tool is present but config.guard.client is missing/invalid');
  }

  // build protected tools.
  const protectedTools: ProtectedTool[] = [];
  for (const { tool, cls, forced } of staged) {
    if (cls === 'readonly') {
      readonlyPassthrough.push(tool.name);
      protectedTools.push(passthroughProtected(tool, 'readonly'));
    } else {
      guardedMutators.push(tool.name);
      protectedTools.push(wrapWithGuard(tool, cls, config));
    }
    void forced;
  }

  // invariant (§1.3 / G1): no mutating-class protected tool without guarded===true.
  for (const p of protectedTools) {
    if (isMutatingClass(p._coderifts.mutationClass) && p._coderifts.guarded !== true) {
      throw new RegistryConstructionError('GUARD_CONFIG_INVALID', `invariant violated: '${p.name}' is a mutator exposed without a guard`, p.name);
    }
  }

  // §5.1 coverage verdict (mechanical). rawM is empty in this strict impl (every mutator is wrapped);
  // BYPASSED comes only from `forced`; PARTIAL only from unknown→readonly.
  const M = guardedMutators.length; // resolved-mutating count (all wrapped)
  const G = guardedMutators.length;
  let coverage: EnforcementCoverage;
  if (anyForced) {
    coverage = 'BYPASSED';
  } else if (unknownPolicy === 'readonly' && anyUnknownReadonly) {
    coverage = 'PARTIAL';
  } else if (M === G) {
    coverage = 'COMPLETE';
  } else {
    coverage = 'PARTIAL';
  }

  if (unknownPolicy === 'readonly' && anyUnknownReadonly && !warnings.includes('unknown_treated_as_readonly')) {
    warnings.push('unknown_treated_as_readonly');
  }

  const inescapableRuntime = coverage === 'COMPLETE' && failHard;

  const report: RegistryCoverageReport = {
    version: 'guard-tool-registry-report/1.0',
    coverage,
    protected_tools: protectedTools.map((p) => p.name),
    guarded_mutators: guardedMutators.slice(),
    readonly_passthrough: readonlyPassthrough.slice(),
    unguarded_mutators: [], // strict impl: always [] (COMPLETE ⇒ [] by G4; forced tools are readonly)
    unknown_treated_as: unknownPolicy,
    claim: {
      inescapable_runtime: inescapableRuntime,
      inescapable_merge: false,
      inescapable_deploy: false,
    },
    siblings: {
      merge_gate: 'required_separate_#7',
      artifact_resolver: 'sibling_#4',
    },
    warnings,
  };

  Object.freeze(report.claim);
  Object.freeze(report.siblings);
  Object.freeze(report);

  return {
    tools: Object.freeze(protectedTools) as ProtectedTool[],
    coverage,
    report,
  };
}

function isMutating(cls: ToolMutationClass | null): boolean {
  return cls != null && cls !== 'readonly';
}
