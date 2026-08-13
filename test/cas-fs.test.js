'use strict';

/**
 * Filesystem CAS adapter — createFsVersionToken + writeFileIfUnchanged via executeIfUnchanged.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const {
  createFsVersionToken,
  readVersionedFile,
  writeFileIfUnchanged,
  executeIfUnchanged,
  tokensEqual,
  FS_ABSENT_TOKEN,
  FS_VERSION_TOKEN_PREFIX,
} = require('../dist/cjs/index.js');

let tmpRoot;

before(async () => {
  tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'coderifts-cas-'));
});

after(async () => {
  if (tmpRoot) {
    await fsp.rm(tmpRoot, { recursive: true, force: true });
  }
});

describe('createFsVersionToken', () => {
  it('returns FS_ABSENT_TOKEN for missing path', async () => {
    const t = await createFsVersionToken(path.join(tmpRoot, 'no-such-file.txt'));
    assert.equal(t, FS_ABSENT_TOKEN);
  });

  it('returns fs:v1:mtime:hash for an existing file', async () => {
    const p = path.join(tmpRoot, 'a.txt');
    await fsp.writeFile(p, 'hello', 'utf8');
    const t = await createFsVersionToken(p);
    assert.ok(t.startsWith(FS_VERSION_TOKEN_PREFIX));
    assert.notEqual(t, FS_ABSENT_TOKEN);
    const again = await createFsVersionToken(p);
    assert.equal(tokensEqual(t, again), true);
  });

  it('token changes when content changes', async () => {
    const p = path.join(tmpRoot, 'b.txt');
    await fsp.writeFile(p, 'v1', 'utf8');
    const t1 = await createFsVersionToken(p);
    await fsp.writeFile(p, 'v2', 'utf8');
    const t2 = await createFsVersionToken(p);
    assert.equal(tokensEqual(t1, t2), false);
  });
});

describe('writeFileIfUnchanged (via executeIfUnchanged)', () => {
  it('fresh token → write succeeds and content matches', async () => {
    const p = path.join(tmpRoot, 'fresh.txt');
    await fsp.writeFile(p, 'original', 'utf8');
    const token = await createFsVersionToken(p);
    const out = await writeFileIfUnchanged({
      path: p,
      expected_token: token,
      content: 'committed',
    });
    assert.equal(out.status, 'committed');
    assert.equal(out.version_token, token);
    assert.equal(await fsp.readFile(p, 'utf8'), 'committed');
    // No leftover temp files in dir
    const names = await fsp.readdir(tmpRoot);
    assert.ok(!names.some((n) => n.includes('.coderifts-cas-') && n.endsWith('.tmp')));
  });

  it('external mutation between token and commit → refused; original intact; no partial', async () => {
    const p = path.join(tmpRoot, 'race.txt');
    await fsp.writeFile(p, 'keep-me', 'utf8');
    const token = await createFsVersionToken(p);
    // External writer mutates after host measured the token
    await fsp.writeFile(p, 'external-win', 'utf8');
    const out = await writeFileIfUnchanged({
      path: p,
      expected_token: token,
      content: 'should-not-land',
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.reason, 'stale_version_token');
    assert.equal(out.expected_token, token);
    assert.ok(out.current_token && out.current_token !== token);
    assert.equal(await fsp.readFile(p, 'utf8'), 'external-win');
    const names = await fsp.readdir(tmpRoot);
    assert.ok(!names.some((n) => n.includes('.coderifts-cas-') && n.endsWith('.tmp')));
  });

  it('readVersionedFile pairs content + token', async () => {
    const p = path.join(tmpRoot, 'pair.txt');
    await fsp.writeFile(p, 'body', 'utf8');
    const v = await readVersionedFile(p);
    assert.equal(v.content, 'body');
    assert.equal(v.version_token, await createFsVersionToken(p));
  });
});

describe('executeIfUnchanged (generic helper)', () => {
  it('refuses when current_token mismatches without calling write', async () => {
    let wrote = false;
    const out = await executeIfUnchanged({
      expected_token: 'tok-a',
      current_token: () => 'tok-b',
      write: () => {
        wrote = true;
        return 'x';
      },
    });
    assert.equal(out.status, 'refused');
    assert.equal(out.reason, 'stale_version_token');
    assert.equal(wrote, false);
  });
});
