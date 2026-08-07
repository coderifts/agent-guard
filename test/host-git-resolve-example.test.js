'use strict';

/**
 * Pins the host example to the real blobMapKey constant (not a hand-typed literal)
 * and runs the example offline with an injected fake (no git, no repo).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const { blobMapKey, resolve: resolveArtifacts } = require('../dist/cjs/artifact-resolver.js');

const EXAMPLE_URL = pathToFileURL(
  path.join(__dirname, '..', 'examples', 'host-git-resolve.mjs'),
).href;

describe('examples/host-git-resolve — key format + offline fake', () => {
  it('blobMapKey is the single scheme the resolver reads (assert against export, not a copy)', () => {
    // Real constant / function from the package — if the scheme drifts, this fails.
    assert.equal(typeof blobMapKey, 'function');
    assert.equal(blobMapKey('abc123', 'openapi.yaml'), 'abc123:openapi.yaml');
    assert.equal(blobMapKey('base', 'a/b.yaml'), 'base:a/b.yaml');
    // Documented identity with git show <ref>:<path>
    const ref = 'origin/main';
    const p = 'specs/openapi.yaml';
    assert.equal(blobMapKey(ref, p), `${ref}:${p}`);
  });

  it('resolver only finds blobs under blobMapKey — wrong scheme is absent (null path)', () => {
    const baseRef = 'base';
    const headRef = 'head';
    const p = 'openapi.yaml';
    const bodyB = 'openapi: "3.0.0"\ninfo: { title: T, version: "1" }\npaths: {}\n';
    const bodyH = 'openapi: "3.0.0"\ninfo: { title: T, version: "2" }\npaths: {}\n';
    const wrongKey = `${baseRef}/${p}`; // slash scheme — NOT what the resolver uses
    const rWrong = resolveArtifacts({
      baseRef,
      headRef,
      changedFiles: [p],
      blobs: {
        [wrongKey]: bodyB,
        [`${headRef}/${p}`]: bodyH,
      },
    }, {});
    // Keys not under blobMapKey → both sides missing → unresolved, not a fabricated artifact.
    assert.equal(rWrong.artifacts.length, 0);
    assert.ok(rWrong.unresolved.length >= 1);

    const rOk = resolveArtifacts({
      baseRef,
      headRef,
      changedFiles: [p],
      blobs: {
        [blobMapKey(baseRef, p)]: bodyB,
        [blobMapKey(headRef, p)]: bodyH,
      },
    }, {});
    assert.equal(rOk.artifacts.length, 1);
    // id is type:path (classifyByName → openapi:openapi.yaml), not bare path alone.
    assert.equal(rOk.artifacts[0].id, `openapi:${p}`);
    assert.equal(rOk.artifacts[0].before, bodyB);
    assert.equal(rOk.artifacts[0].after, bodyH);
  });

  it('example module: buildBlobsSnapshot + resolvePrior use blobMapKey and honest nulls (fake git)', async () => {
    const ex = await import(EXAMPLE_URL);
    assert.equal(typeof ex.buildBlobsSnapshot, 'function');
    assert.equal(typeof ex.makeResolvePriorContentFromGit, 'function');
    assert.equal(typeof ex.readBlobAt, 'function');

    /** @type {(args: string[]) => string} */
    function fakeGit(args) {
      if (args[0] === 'diff' && args[1] === '--name-only') return 'openapi.yaml\n';
      if (args[0] === 'show' && args[1] === 'base:openapi.yaml') return 'BEFORE\n';
      if (args[0] === 'show' && args[1] === 'head:openapi.yaml') return 'AFTER\n';
      if (args[0] === 'show' && String(args[1]).includes('gone.yaml')) {
        throw new Error("path 'gone.yaml' does not exist in 'head'");
      }
      if (args[0] === 'show' && String(args[1]).includes('perm.bin')) {
        throw new Error('fatal: permission denied');
      }
      throw new Error(`unexpected ${args.join(' ')}`);
    }

    const blobs = ex.buildBlobsSnapshot({
      baseRef: 'base',
      headRef: 'head',
      changedFiles: ['openapi.yaml'],
      cwd: '/tmp/x',
      gitImpl: fakeGit,
    });

    // Keys must equal the package constant — not a literal duplicated in the test alone.
    assert.ok(Object.prototype.hasOwnProperty.call(blobs, blobMapKey('base', 'openapi.yaml')));
    assert.ok(Object.prototype.hasOwnProperty.call(blobs, blobMapKey('head', 'openapi.yaml')));
    assert.equal(blobs[blobMapKey('base', 'openapi.yaml')], 'BEFORE\n');
    assert.equal(blobs[blobMapKey('head', 'openapi.yaml')], 'AFTER\n');

    // Absent → null (honest), not "".
    assert.equal(ex.readBlobAt('head', 'gone.yaml', '/tmp/x', fakeGit), null);
    // Unreadable → error object, not invented empty string.
    const bad = ex.readBlobAt('head', 'perm.bin', '/tmp/x', fakeGit);
    assert.ok(bad && typeof bad === 'object' && bad.error === 'unreadable_blob');

    const resolvePrior = ex.makeResolvePriorContentFromGit({
      headRef: 'head',
      cwd: '/tmp/x',
      gitImpl: fakeGit,
    });
    assert.equal(resolvePrior({ artifactId: 'openapi:openapi.yaml', toolName: 'Edit' }), 'AFTER\n');
    assert.equal(resolvePrior({ artifactId: 'openapi:gone.yaml', toolName: 'Edit' }), null);
  });
});
