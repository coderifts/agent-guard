/**
 * Host wiring example: git → blobs / resolvePriorContent → agent-guard pure APIs.
 *
 * NOT shipped in the npm package (see examples/README.md). NOT a second
 * contract-gate. Production PR artifact derivation:
 *   https://github.com/coderifts/contract-gate  →  src/artifacts.js
 *
 * Run offline (no repo, no network):
 *   node examples/host-git-resolve.mjs
 *   node --test test/host-git-resolve-example.test.js
 *
 * ---------------------------------------------------------------------------
 * TOCTOU (unclosed — do not read this file as a solved problem)
 * ---------------------------------------------------------------------------
 * Resolving current content proves what was true AT MEASUREMENT TIME only.
 * A host that then writes unconditionally still has the race between resolve
 * and write. Closing that gap needs a version token from the resolve and an
 * expectation carried into the write. Neither this example nor
 * @coderifts/agent-guard provides that token or that conditional write.
 * Freshness assessFreshness can compare bytes you re-measure; it does not
 * make your write atomic with respect to the tree.
 * ---------------------------------------------------------------------------
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const distCjs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cjs');

// Prefer built package surface (same modules hosts import after npm install + build).
const ar = require(path.join(distCjs, 'artifact-resolver.js'));
const { blobMapKey } = ar;
// Compiled name is `resolve`; index re-exports it as resolveArtifacts.
const resolveArtifacts = ar.resolveArtifacts || ar.resolve;
if (typeof resolveArtifacts !== 'function') {
  throw new Error('examples/host-git-resolve: build dist first (npm run build)');
}

// ── 1. Blob key format (the piece hosts cannot guess) ─────────────────────────
//
// ResolveInput.blobs is keyed exactly as blobMapKey(ref, path) — currently
// `${ref}:${path}`, matching `git show <ref>:<path>`. Always call blobMapKey;
// never hard-code a second scheme.

// ── 2. Injectable git seam (contract-gate uses the same discipline) ───────────
//
// Production: execFileSync('git', args, { cwd, encoding: 'utf8' })
// Tests / this demo: pass a fake that never touches a repo.

/**
 * @typedef {(args: string[], cwd?: string) => string} GitImpl
 */

/**
 * Default real git runner — HOST ONLY. Not imported by package src/.
 * Shown here so the seam is visible; the demo main() uses a fake.
 * @type {GitImpl}
 */
export function defaultGit(args, cwd = process.cwd()) {
  const { execFileSync } = require('node:child_process');
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/**
 * Read one blob. Honest absence vs error:
 *   - missing at ref → null  (resolver treats as empty side / possible added|deleted)
 *   - other failure  → { error: 'unreadable_blob', detail }
 *
 * Do NOT invent an empty string on failure and pretend it was measured content.
 * (contract-gate's blobAt collapses miss to '' for preflight empty-side convention;
 *  agent-guard's snapshot prefers null | { error } so anti-fabrication stays visible.
 *  Empty string in the map is still "present empty text", not "unresolved".)
 *
 * @param {string} ref
 * @param {string} filePath
 * @param {string} [cwd]
 * @param {GitImpl} [gitImpl]
 * @returns {string | null | { error: string, detail?: string }}
 */
export function readBlobAt(ref, filePath, cwd = process.cwd(), gitImpl = defaultGit) {
  try {
    return gitImpl(['show', `${ref}:${filePath}`], cwd);
  } catch (err) {
    const msg = err && err.message ? String(err.message) : String(err);
    // git show typically says "does not exist" / "exists on disk, but not in" for absent paths
    if (/does not exist|exists on disk, but not in|bad object|pathspec/i.test(msg)) {
      return null;
    }
    return { error: 'unreadable_blob', detail: msg.slice(0, 200) };
  }
}

/**
 * List paths changed on head since merge-base with base (three-dot), same as contract-gate.
 * @param {string} baseRef
 * @param {string} headRef
 * @param {string} [cwd]
 * @param {GitImpl} [gitImpl]
 * @returns {string[]}
 */
export function listChangedFiles(baseRef, headRef, cwd = process.cwd(), gitImpl = defaultGit) {
  const out = gitImpl(['diff', '--name-only', `${baseRef}...${headRef}`], cwd);
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

/**
 * Build the pure snapshot the resolver consumes.
 *
 * Both sides:
 *   prior  (baseRef)  → blobs[blobMapKey(baseRef, path)]
 *   current (headRef) → blobs[blobMapKey(headRef, path)]
 *
 * Production hosts should prefer contract-gate deriveArtifactsFromDiff for the
 * PR artifact list; this builder is the explicit map shape for resolveArtifacts.
 *
 * @param {object} o
 * @param {string} o.baseRef
 * @param {string} o.headRef
 * @param {string[]} o.changedFiles
 * @param {string} [o.cwd]
 * @param {GitImpl} [o.gitImpl]
 */
export function buildBlobsSnapshot({ baseRef, headRef, changedFiles, cwd = process.cwd(), gitImpl = defaultGit }) {
  /** @type {Record<string, string | null | { error: string, detail?: string }>} */
  const blobs = {};
  for (const filePath of changedFiles) {
    blobs[blobMapKey(baseRef, filePath)] = readBlobAt(baseRef, filePath, cwd, gitImpl);
    blobs[blobMapKey(headRef, filePath)] = readBlobAt(headRef, filePath, cwd, gitImpl);
  }
  return blobs;
}

/**
 * Example resolvePriorContent for guardToolCall / withCodeRifts.
 *
 * Freshness runner calls this with { artifactId, path?, toolName } and expects
 * current prior content (what is on disk / at HEAD *now*), or null if unmeasurable.
 *
 * This is MEASUREMENT-TIME only — see TOCTOU block at top of file.
 *
 * @param {object} o
 * @param {string} [o.headRef]  ref to treat as "now" (e.g. HEAD or PR head SHA)
 * @param {string} [o.cwd]
 * @param {GitImpl} [o.gitImpl]
 * @returns {(req: { artifactId: string, path?: string, toolName: string }) => string | null}
 */
export function makeResolvePriorContentFromGit({
  headRef = 'HEAD',
  cwd = process.cwd(),
  gitImpl = defaultGit,
} = {}) {
  return function resolvePriorContent(req) {
    // Artifact ids from the default binder often look like "openapi:path/to/file".
    // Prefer explicit path; else take the path tail after the first "type:" prefix.
    let filePath = typeof req.path === 'string' && req.path.length > 0 ? req.path : '';
    if (!filePath && typeof req.artifactId === 'string') {
      const id = req.artifactId;
      const colon = id.indexOf(':');
      filePath = colon >= 0 ? id.slice(colon + 1).replace(/#\d+$/, '') : id;
    }
    if (!filePath) return null;

    const blob = readBlobAt(headRef, filePath, cwd, gitImpl);
    if (blob === null) return null; // honest: not measurable
    if (blob && typeof blob === 'object' && blob.error) return null; // do not invent ""
    return typeof blob === 'string' ? blob : null;
  };
}

// ── Demo (fake git — offline) ─────────────────────────────────────────────────

/** @type {GitImpl} */
function fakeGit(args) {
  const joined = args.join(' ');
  if (args[0] === 'diff' && args[1] === '--name-only') {
    return 'openapi.yaml\nREADME.md\n';
  }
  if (args[0] === 'show' && args[1] === 'base:openapi.yaml') {
    return 'openapi: "3.0.0"\ninfo: { title: T, version: "1" }\npaths: {}\n';
  }
  if (args[0] === 'show' && args[1] === 'head:openapi.yaml') {
    return 'openapi: "3.0.0"\ninfo: { title: T, version: "2" }\npaths: { /x: { get: {} } }\n';
  }
  if (args[0] === 'show' && args[1] === 'base:README.md') {
    return '# old\n';
  }
  if (args[0] === 'show' && args[1] === 'head:README.md') {
    return '# hi\n';
  }
  if (args[0] === 'show' && String(args[1]).includes('missing.yaml')) {
    const err = new Error(`path 'missing.yaml' does not exist in 'head'`);
    throw err;
  }
  if (args[0] === 'show' && String(args[1]).includes('locked.bin')) {
    throw new Error('fatal: not a valid object name (permission denied)');
  }
  throw new Error(`fakeGit: unexpected ${joined}`);
}

function main() {
  const baseRef = 'base';
  const headRef = 'head';
  const changedFiles = listChangedFiles(baseRef, headRef, '/tmp/fake', fakeGit);
  const blobs = buildBlobsSnapshot({
    baseRef,
    headRef,
    changedFiles,
    cwd: '/tmp/fake',
    gitImpl: fakeGit,
  });

  // Unresolvable path: honest null / error — not "".
  blobs[blobMapKey(headRef, 'missing.yaml')] = readBlobAt(headRef, 'missing.yaml', '/tmp/fake', fakeGit);
  blobs[blobMapKey(baseRef, 'missing.yaml')] = null;
  blobs[blobMapKey(headRef, 'locked.bin')] = readBlobAt(headRef, 'locked.bin', '/tmp/fake', fakeGit);

  console.log('blob keys (must match blobMapKey):');
  for (const k of Object.keys(blobs).sort()) {
    const v = blobs[k];
    const shown = v === null ? 'null' : (typeof v === 'object' ? JSON.stringify(v) : `string(${v.length})`);
    console.log(`  ${k} → ${shown}`);
  }

  const result = resolveArtifacts(
    { baseRef, headRef, changedFiles: [...changedFiles, 'missing.yaml'], blobs },
    {},
  );
  console.log('\nresolveArtifacts coverage:', result.coverage);
  console.log('artifacts:', result.artifacts.map((a) => a.id));
  console.log('unresolved (honest, not invented empty):', result.unresolved);

  const resolvePrior = makeResolvePriorContentFromGit({ headRef, cwd: '/tmp/fake', gitImpl: fakeGit });
  const prior = resolvePrior({ artifactId: 'openapi:openapi.yaml', toolName: 'Edit' });
  console.log('\nresolvePriorContent(openapi.yaml) length:', prior && prior.length);

  console.log(`
---
Production: use coderifts/contract-gate src/artifacts.js (deriveArtifactsFromDiff)
for PR head diffs. This file only shows the agent-guard blob key + resolver seam.

TOCTOU: measurement-time only. No version token. No conditional write. Unclosed.
---`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
