'use strict';

/**
 * The vendored core is receipt-verifier's, byte for byte — and all THREE copies agree.
 *
 * src/vendor is the source; scripts/copy-vendor.mjs mirrors it into dist/cjs and dist/esm at build
 * time. Three copies is three chances to drift, and a drifted copy is the shape of 1423: two
 * verifiers with the same name disagreeing about what "checked" means.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src', 'vendor');
const COPIES = [SRC, path.join(ROOT, 'dist', 'cjs', 'vendor'), path.join(ROOT, 'dist', 'esm', 'vendor')];
const SOURCE_REPO = path.join(process.env.HOME || '', 'receipt-verifier');

function pinned() {
  return fs.readFileSync(path.join(SRC, 'VENDOR.sha256'), 'utf8').split('\n')
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => { const [file, sha] = l.trim().split(/\s+/); return { file, sha }; });
}

describe('vendored receipt-verifier core', () => {
  it('the pin covers the whole closure, grant verifier included', () => {
    const files = pinned().map((r) => r.file);
    for (const need of ['verify.js', 'arity.js', 'verify-grant.js', 'verify-evidence.js',
      'verify-prove-transcript.js', 'keys/coderifts-keys.json']) {
      assert.ok(files.includes(need), `${need} is not pinned`);
    }
  });

  it('every vendored file matches its pinned digest', () => {
    for (const { file, sha } of pinned()) {
      const bytes = fs.readFileSync(path.join(SRC, file));
      assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), sha, file);
    }
  });

  it('all THREE copies are byte-identical (one source, copied by the build)', () => {
    for (const { file } of pinned()) {
      const [a, b, c] = COPIES.map((d) => fs.readFileSync(path.join(d, file)));
      assert.ok(a.equals(b), `${file}: src and dist/cjs differ — rebuild`);
      assert.ok(a.equals(c), `${file}: src and dist/esm differ — rebuild`);
    }
    // The pin travels with the copies, so a dist that shipped a stale pin is caught too.
    for (const d of COPIES) assert.ok(fs.existsSync(path.join(d, 'VENDOR.sha256')));
  });

  it('nothing in the vendored closure reaches outside it', () => {
    for (const { file } of pinned().filter((r) => r.file.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(SRC, file), 'utf8');
      for (const m of src.matchAll(/require\('(\.[^']*)'\)/g)) {
        assert.ok(!m[1].startsWith('../'), `${file} requires outside the vendor dir: ${m[1]}`);
      }
    }
  });

  it('the pin names a revision for every vendored file', () => {
    // MIXED ON PURPOSE. verify.js stays at 6048195 (the 1306 keyring-shape fix this guard was
    // tested against); the 1423 evidence core is at HEAD. A single source-commit line would be a
    // tidier lie, so provenance is per file and the next test verifies each against ITS OWN
    // revision — otherwise an honest mixed pin reads as drift and the check gets disabled.
    const header = fs.readFileSync(path.join(SRC, 'VENDOR.sha256'), 'utf8');
    for (const { file } of pinned()) {
      // WORKING-TREE is an allowed revision token for a file that is vendored before it lands
      // upstream. It is a NAMED state, not a gap: the next test compares those bytes against the
      // sibling working tree rather than skipping them, so "not committed yet" never means
      // "not checked".
      assert.match(header, new RegExp(`#\\s+${file.replace(/[./]/g, '\\$&')}\\s+([0-9a-f]{40}|WORKING-TREE)`),
        `${file} has no revision in the pin header`);
    }
  });

  it('each vendored file is byte-identical to its OWN pinned revision upstream', (t) => {
    if (!fs.existsSync(SOURCE_REPO)) {
      t.skip(`receipt-verifier is not checked out beside this repo (${SOURCE_REPO}) — `
        + 'the pin and the three-copy comparison ran; upstream parity did not');
      return;
    }
    const header = fs.readFileSync(path.join(SRC, 'VENDOR.sha256'), 'utf8');
    for (const { file } of pinned()) {
      const m = header.match(new RegExp(`#\\s+${file.replace(/[./]/g, '\\$&')}\\s+([0-9a-f]{40}|WORKING-TREE)`));
      assert.ok(m, `${file} has no revision in the pin header`);
      if (m[1] === 'WORKING-TREE') {
        const up = path.join(SOURCE_REPO, file);
        assert.ok(fs.existsSync(up), `${file} is pinned WORKING-TREE but is absent upstream`);
        assert.ok(fs.readFileSync(path.join(SRC, file)).equals(fs.readFileSync(up)),
          `${file} has drifted from receipt-verifier's working tree`);
        continue;
      }
      const r = spawnSync('git', ['-C', SOURCE_REPO, 'show', `${m[1]}:${file}`], { maxBuffer: 1 << 24 });
      assert.equal(r.status, 0, `${file}@${m[1]} is not in receipt-verifier's history`);
      assert.ok(fs.readFileSync(path.join(SRC, file)).equals(r.stdout),
        `${file} has drifted from receipt-verifier@${m[1].slice(0, 7)}`);
    }
  });
});
