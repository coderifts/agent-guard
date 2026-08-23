/**
 * S1 auto-derive — wrap-layer before/after pair from the tool call + current-state readers.
 *
 * Default OFF. Frozen guardToolCall is unchanged. Host args.artifacts always win.
 * BEFORE comes from a reader of the SAME target (fs path / api / db / registry).
 * AFTER is the call's intended write content. Missing target → before:null
 * (derivation_note before_unavailable); empty file → before:"".
 *
 * Reader throw/timeout → today's fragment path (binder lift); never block on derivation.
 * Observation-only: derivation is not a fingerprint preimage field.
 */

import { promises as fsp } from 'node:fs';
import { classifyByName } from './artifact-resolver.js';
import type { ArtifactType, ResolveConfig } from './artifact-resolver.js';
import type { GuardConfig, GuardEvent, ToolCallDescriptor, Artifact } from './types.js';

export const AUTO_DERIVE_SOURCE = 'guard_auto_derived' as const;
export const AUTO_DERIVE_READ_TIMEOUT_MS = 2000;

export type AutoDeriveMode = 'host_supplied' | 'auto_derived' | 'fragment_only';

export type AutoDeriveTargetKind = 'fs' | 'api' | 'db' | 'registry';

export type AutoDeriveTarget = {
  kind: AutoDeriveTargetKind;
  key: string;
};

export type AutoDeriveNote = {
  target: string;
  note: 'before_unavailable' | 'reader_threw' | 'reader_timeout' | 'not_contract_path';
};

export type AutoDeriveObservation = {
  derivation?: {
    mode: AutoDeriveMode;
    targets: ReadonlyArray<AutoDeriveTarget>;
    notes?: ReadonlyArray<AutoDeriveNote>;
  };
};

export type AutoDeriveReader = (
  key: string,
) => string | null | Promise<string | null>;

/** Current-state readers. Return null = absent (not empty). Throw/timeout → fragment fallback. */
export type AutoDeriveReaders = {
  fs?: AutoDeriveReader;
  api?: AutoDeriveReader;
  db?: AutoDeriveReader;
  registry?: AutoDeriveReader;
};

export type AutoDeriveConfig = {
  readers?: AutoDeriveReaders;
  /** CAP-202 resolve() config (pathTypeHints, ssotPrefer). Optional; not required for fs reads. */
  resolveConfig?: ResolveConfig;
};

export type DerivedArtifact = {
  id: string;
  type: ArtifactType;
  before: string | null;
  after: string;
  source: typeof AUTO_DERIVE_SOURCE;
};

function iso(): string {
  return new Date().toISOString();
}

function emit(config: GuardConfig, e: GuardEvent): void {
  if (config.onEvent) {
    try { config.onEvent(e); } catch { /* onEvent never throws out */ }
  }
}

/** Default fs reader: utf8 contents, ENOENT → null (absent ≠ empty). Other errors throw. */
export async function defaultFsReader(filePath: string): Promise<string | null> {
  try {
    return await fsp.readFile(filePath, 'utf8');
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? String((err as { code?: string }).code)
      : '';
    if (code === 'ENOENT') return null;
    throw err;
  }
}

function looksLikeResolveConfig(o: object): boolean {
  return 'ssotPrefer' in o
    || 'generatedGlobs' in o
    || 'pathTypeHints' in o
    || 'openApiAssembly' in o
    || 'maxRefDepth' in o;
}

function looksLikeReaders(o: object): o is AutoDeriveReaders {
  const r = o as AutoDeriveReaders;
  return typeof r.fs === 'function'
    || typeof r.api === 'function'
    || typeof r.db === 'function'
    || typeof r.registry === 'function';
}

export function normalizeAutoDerive(raw: unknown): AutoDeriveConfig | null {
  if (raw === true) return { readers: { fs: defaultFsReader } };
  if (!raw || raw === false || typeof raw !== 'object') return null;
  const o = raw as AutoDeriveConfig & { readers?: unknown };
  const cfg: AutoDeriveConfig = {};
  if (o.resolveConfig && typeof o.resolveConfig === 'object') cfg.resolveConfig = o.resolveConfig;
  if (o.readers && typeof o.readers === 'object') {
    if (looksLikeReaders(o.readers)) {
      cfg.readers = { ...o.readers };
    } else if (looksLikeResolveConfig(o.readers)) {
      cfg.resolveConfig = o.readers as ResolveConfig;
    }
  }
  if (!cfg.readers) cfg.readers = {};
  if (typeof cfg.readers.fs !== 'function') cfg.readers.fs = defaultFsReader;
  return cfg;
}

function rawRecord(args: unknown): Record<string, unknown> | null {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return null;
  return args as Record<string, unknown>;
}

function hostSuppliedArtifacts(args: unknown): boolean {
  const a = rawRecord(args);
  return !!(a && Array.isArray(a.artifacts));
}

function targetFromArgs(a: Record<string, unknown>): AutoDeriveTarget | null {
  if (typeof a.path === 'string' && a.path.length > 0) return { kind: 'fs', key: a.path };
  if (typeof a.url === 'string' && a.url.length > 0) return { kind: 'api', key: a.url };
  if (typeof a.endpoint === 'string' && a.endpoint.length > 0) return { kind: 'api', key: a.endpoint };
  if (typeof a.table === 'string' && a.table.length > 0) {
    const id = a.id != null ? String(a.id) : '';
    return { kind: 'db', key: id ? `${a.table}/${id}` : a.table };
  }
  if (typeof a.key === 'string' && a.key.length > 0) return { kind: 'registry', key: a.key };
  return null;
}

function intendedAfter(a: Record<string, unknown>, before: string | null): string | null {
  for (const k of ['contents', 'content', 'new_content', 'new_contents'] as const) {
    if (typeof a[k] === 'string') return a[k] as string;
  }
  const oldS = typeof a.old_string === 'string' ? a.old_string : null;
  const newS = typeof a.new_string === 'string' ? a.new_string : null;
  if (newS == null) return null;
  if (typeof before === 'string' && oldS && oldS.length > 0 && before.includes(oldS)) {
    return before.replace(oldS, newS);
  }
  if (newS.length > 0) return newS;
  return null;
}

function typeForTarget(
  target: AutoDeriveTarget,
  a: Record<string, unknown>,
  resolveConfig?: ResolveConfig,
): ArtifactType | null {
  if (typeof a.type === 'string' && a.type) {
    const t = a.type as ArtifactType;
    if (t === 'openapi' || t === 'graphql' || t === 'grpc' || t === 'asyncapi' || t === 'mcp_manifest') {
      return t;
    }
  }
  if (target.kind === 'fs') {
    const hinted = resolveConfig && resolveConfig.pathTypeHints
      ? resolveConfig.pathTypeHints[target.key]
      : undefined;
    if (hinted) return hinted;
    return classifyByName(target.key);
  }
  return null;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          const e = new Error(`autoDerive reader timed out after ${ms}ms`);
          (e as { name: string }).name = 'TimeoutError';
          reject(e);
        }, Math.max(1, ms));
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function readCurrent(
  readers: AutoDeriveReaders,
  target: AutoDeriveTarget,
): Promise<string | null> {
  const fn = readers[target.kind];
  if (typeof fn !== 'function') {
    const err = new Error(`autoDerive: no ${target.kind} reader`);
    (err as { code?: string }).code = 'NO_READER';
    throw err;
  }
  return withTimeout(Promise.resolve(fn(target.key)), AUTO_DERIVE_READ_TIMEOUT_MS);
}

export type AutoDeriveResult = {
  call: ToolCallDescriptor;
  derivation: NonNullable<AutoDeriveObservation['derivation']>;
  failed?: { cause: string };
};

/**
 * Derive a before/after pair onto the call descriptor when the host did not supply artifacts.
 * Never throws out — reader failures return the bound call with fragment_only + failed.cause.
 */
export async function runAutoDerive(args: {
  bound: ToolCallDescriptor;
  rawArgs: unknown;
  cfg: AutoDeriveConfig;
  config: GuardConfig;
}): Promise<AutoDeriveResult> {
  const bound = args.bound;
  if (hostSuppliedArtifacts(args.rawArgs)) {
    return {
      call: bound,
      derivation: { mode: 'host_supplied', targets: [] },
    };
  }

  const a = rawRecord(args.rawArgs) || rawRecord(bound.arguments);
  if (!a) {
    return { call: bound, derivation: { mode: 'fragment_only', targets: [] } };
  }

  const target = targetFromArgs(a);
  if (!target) {
    return { call: bound, derivation: { mode: 'fragment_only', targets: [] } };
  }

  const type = typeForTarget(target, a, args.cfg.resolveConfig);
  if (!type) {
    return {
      call: bound,
      derivation: {
        mode: 'fragment_only',
        targets: [target],
        notes: [{ target: target.key, note: 'not_contract_path' }],
      },
    };
  }

  const readers = args.cfg.readers || { fs: defaultFsReader };
  let before: string | null;
  try {
    before = await readCurrent(readers, target);
  } catch (err: unknown) {
    const name = err && typeof err === 'object' && 'name' in err
      ? String((err as { name?: string }).name)
      : '';
    const cause = name === 'TimeoutError' ? 'reader_timeout' : 'reader_threw';
    emit(args.config, { type: 'derive_failed', at: iso(), cause });
    return {
      call: bound,
      derivation: {
        mode: 'fragment_only',
        targets: [target],
        notes: [{
          target: target.key,
          note: cause === 'reader_timeout' ? 'reader_timeout' : 'reader_threw',
        }],
      },
      failed: { cause },
    };
  }

  const after = intendedAfter(a, before);
  if (after == null) {
    return {
      call: bound,
      derivation: { mode: 'fragment_only', targets: [target] },
    };
  }

  const notes: AutoDeriveNote[] = [];
  if (before === null) {
    notes.push({ target: target.key, note: 'before_unavailable' });
    // Absence must not erase a binder-lifted fragment pair (old_string/new_string).
    if (Array.isArray(bound.artifacts) && bound.artifacts.length > 0) {
      return {
        call: bound,
        derivation: {
          mode: 'fragment_only',
          targets: [target],
          notes,
        },
      };
    }
  }

  const derived: DerivedArtifact = {
    id: `${type}:${target.key}`,
    type,
    before,
    after,
    source: AUTO_DERIVE_SOURCE,
  };

  const call: ToolCallDescriptor = {
    ...bound,
    artifacts: [derived as unknown as Artifact],
  };
  return {
    call,
    derivation: {
      mode: 'auto_derived',
      targets: [target],
      ...(notes.length ? { notes } : {}),
    },
  };
}

export function attachDerivation<T>(
  outcome: T,
  derivation: NonNullable<AutoDeriveObservation['derivation']> | null | undefined,
): T {
  if (!derivation) return outcome;
  return { ...(outcome as object), derivation } as T;
}
