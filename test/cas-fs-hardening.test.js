'use strict';

/**
 * 1098 — filesystem defences. Each test names the escape it closes and was written only after
 * measuring that we did NOT already have it (lstat, realpath, O_NOFOLLOW, fd reads and ino/dev
 * were all absent from src/cas-adapters/ on 12.0.0).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  assertSafeCasPath, UnsafeCasPathError, fsObjectIdentity, identitiesEqual,
  createFsVersionToken, writeFileIfUnchanged, FS_ABSENT_TOKEN, measureFsAuthorization,
} = require('../dist/cjs/index.js');

function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'cas-hard-')); }

/**
 * Swap the object at `file` for a NEW inode carrying identical bytes and an identical mtime.
 * The mtime is pinned to a fixed whole-second value on both sides: relying on rename/utimes to
 * round-trip the original's sub-millisecond mtime made this flaky under suite load, and a flaky
 * precondition turns the test into a measurement of something else.
 */
function swapInodeKeepingToken(dir, file, bytes) {
  const FIXED = new Date(1600000000000);
  fs.writeFileSync(file, bytes);
  fs.utimesSync(file, FIXED, FIXED);
  const other = path.join(dir, `swap-${path.basename(file)}`);
  fs.writeFileSync(other, bytes);
  fs.utimesSync(other, FIXED, FIXED);
  fs.renameSync(other, file);
  fs.utimesSync(file, FIXED, FIXED);
}

describe('1098 — path defences', () => {
  it('refuses a literal ".." segment, judged BEFORE resolution', async () => {
    const d = tmpdir();
    try {
      fs.mkdirSync(path.join(d, 'sub'));
      const literal = `${d}/sub/../escaped.yaml`;
      await assert.rejects(() => assertSafeCasPath(literal), (e) => {
        assert.ok(e instanceof UnsafeCasPathError);
        assert.equal(e.reason, 'path_traversal');
        return true;
      });
      await assert.rejects(() => writeFileIfUnchanged({ path: literal, expected_token: FS_ABSENT_TOKEN, content: 'x' }));
      assert.equal(fs.existsSync(path.join(d, 'escaped.yaml')), false, 'nothing may be written');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });

  it('refuses a symlinked final component — check and write must name ONE object', async () => {
    const d = tmpdir();
    try {
      const outside = path.join(d, 'OUTSIDE.txt');
      fs.writeFileSync(outside, 'original\n');
      const link = path.join(d, 'openapi.yaml');
      fs.symlinkSync(outside, link);
      const tok = await createFsVersionToken(link);
      await assert.rejects(
        () => writeFileIfUnchanged({ path: link, expected_token: tok, content: 'VIA SYMLINK\n' }),
        (e) => { assert.equal(e.reason, 'symlink_target'); return true; },
      );
      assert.equal(fs.lstatSync(link).isSymbolicLink(), true, 'the link must survive');
      assert.equal(fs.readFileSync(outside, 'utf8'), 'original\n', 'the target must be untouched');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });

  it('a symlinked ANCESTOR is canonicalised, not refused (macOS /var is one)', async () => {
    const d = tmpdir();
    try {
      const real = path.join(d, 'real'); fs.mkdirSync(real);
      const linkDir = path.join(d, 'link'); fs.symlinkSync(real, linkDir);
      const target = await assertSafeCasPath(path.join(linkDir, 'openapi.yaml'));
      assert.equal(target, path.join(fs.realpathSync(real), 'openapi.yaml'),
        'the parent resolves to its real location rather than being rejected');
      const r = await writeFileIfUnchanged({ path: path.join(linkDir, 'openapi.yaml'), expected_token: FS_ABSENT_TOKEN, content: 'ok\n' });
      assert.equal(r.status, 'committed');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });
});

describe('1098 — object identity', () => {
  it('fsObjectIdentity reads dev+ino through a file descriptor; null when absent', async () => {
    const d = tmpdir();
    try {
      const f = path.join(d, 'a.yaml'); fs.writeFileSync(f, 'a\n');
      const id = await fsObjectIdentity(f);
      assert.equal(typeof id.dev, 'number');
      assert.equal(typeof id.ino, 'number');
      assert.equal(await fsObjectIdentity(path.join(d, 'missing.yaml')), null);
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });

  it('identitiesEqual is false for null on either side (absence is never equality)', () => {
    assert.equal(identitiesEqual(null, null), false);
    assert.equal(identitiesEqual({ dev: 1, ino: 2 }, null), false);
    assert.equal(identitiesEqual({ dev: 1, ino: 2 }, { dev: 1, ino: 2 }), true);
    assert.equal(identitiesEqual({ dev: 1, ino: 2 }, { dev: 1, ino: 3 }), false);
  });

  it('the write evidence records which OBJECT was checked, not merely the path string', async () => {
    const d = tmpdir();
    try {
      const f = path.join(d, 'a.yaml'); fs.writeFileSync(f, 'a\n');
      const tok = await createFsVersionToken(f);
      const r = await writeFileIfUnchanged({ path: f, expected_token: tok, content: 'b\n' });
      assert.equal(r.status, 'committed');
      assert.equal(typeof r.result.checked_identity.ino, 'number');
      assert.equal(typeof r.result.checked_identity.dev, 'number');
      assert.ok(r.result.committed_identity, 'the post-write object is recorded too');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });

  it('an inode swap with IDENTICAL bytes is refused — content equality cannot see it', async () => {
    const d = tmpdir();
    try {
      const f = path.join(d, 'a.yaml');
      fs.writeFileSync(f, 'same\n');
      fs.utimesSync(f, new Date(1600000000000), new Date(1600000000000));
      const tok = await createFsVersionToken(f);
      const t1identity = await fsObjectIdentity(f);   // measured at T1, like the runner does
      swapInodeKeepingToken(d, f, 'same\n');
      const after = await fsObjectIdentity(f);
      assert.notEqual(t1identity.ino, after.ino, 'precondition: the inode really changed');
      assert.equal(await createFsVersionToken(f), tok, 'precondition: the TOKEN is unchanged');
      const r = await writeFileIfUnchanged({
        path: f, expected_token: tok, expected_identity: t1identity, content: 'new\n',
      });
      assert.equal(r.status, 'refused', 'identity must catch what the content token cannot');
      assert.equal(fs.readFileSync(f, 'utf8'), 'same\n', 'the write must not have landed');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });
});

describe('1098 — the identity claim is opt-in and never inferred', () => {
  it('omitting expected_identity makes NO identity claim (an inode swap then passes on token alone)', async () => {
    const d = tmpdir();
    try {
      const f = path.join(d, 'a.yaml');
      fs.writeFileSync(f, 'same\n');
      fs.utimesSync(f, new Date(1600000000000), new Date(1600000000000));
      const tok = await createFsVersionToken(f);
      swapInodeKeepingToken(d, f, 'same\n');
      assert.equal(await createFsVersionToken(f), tok, 'precondition: the TOKEN is unchanged');
      const r = await writeFileIfUnchanged({ path: f, expected_token: tok, content: 'new\n' });
      assert.equal(r.status, 'committed',
        'without a T1 identity we do not pretend to one — the weaker guarantee is reported, not faked');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });

  it('measureFsAuthorization returns token AND identity as one observation', async () => {
    const d = tmpdir();
    try {
      const f = path.join(d, 'a.yaml'); fs.writeFileSync(f, 'a\n');
      const m = await measureFsAuthorization({ path: f, contents: 'b\n' });
      assert.equal(typeof m.expected_token, 'string');
      assert.equal(typeof m.expected_identity.ino, 'number');
      assert.equal(await measureFsAuthorization({ path: f }), null, 'no contents → nothing to measure');
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  });
});
