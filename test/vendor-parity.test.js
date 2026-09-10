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
    // ── ONE TAG, NOT A MIXED PIN ───────────────────────────────────────────────────────────
    //
    // The provenance was per file — verify.js held at 6048195 because "recopying HEAD would change
    // a verifier nobody measured again". MEASURED before this changed: the 6048195 → v1.0.0 delta
    // on verify.js is ZERO non-comment lines (CLI usage docs). The reason for the mixed pin was
    // true when written and is not true of this delta, so the core is now one released tag.
    //
    // A tag is a provenance a stranger can resolve. WORKING-TREE was honest about where bytes came
    // from and unresolvable by anyone else: "the vendored bytes match upstream" meant "they match
    // whatever is on this machine right now".
    const header = fs.readFileSync(path.join(SRC, 'VENDOR.sha256'), 'utf8');
    assert.match(header, /source_commit: ac683b16c19662c9124c8cdab785223b28d2d0c6/,
      'the pin does not name the released commit');
    assert.match(header, /receipt-verifier \*\*v1\.0\.2\*\*/,
      'the pin does not name the release tag');
    // AND THE SIGNER, because that is what v1.0.1 added over v1.0.0. The tag itself is verified
    // below; this asserts the pin RECORDS which key must have signed it. Without the record, the
    // check below would accept any good signature by anyone, and "signed" would mean "somebody
    // signed something" rather than "this releaser signed this release".
    assert.match(header, /SHA256:7yRXTm9zKGicfFpzL\+7lpwFoPaoSwxAJlabB3jwxw2Y/,
      'the pin names a signed tag but records no signer fingerprint to check it against');
    // THE PIN ROW, not the word. A per-file `#   <file>  WORKING-TREE` row IS a pin nobody outside
    // this machine can resolve; prose recording that the pin USED to be one is history, and a
    // check that cannot tell them apart forces the history to be deleted to stay green.
    for (const line of header.split('\n')) {
      assert.doesNotMatch(line, /^#\s+\S+\.(?:js|json)\s+WORKING-TREE/,
        `a file is still pinned to a working tree: ${line.trim()}`);
    }
  });

  it('each vendored core file is byte-identical to the SIGNED receipt-verifier v1.0.2', (t) => {
    if (!fs.existsSync(SOURCE_REPO)) {
      t.skip(`receipt-verifier is not checked out beside this repo (${SOURCE_REPO}) — `
        + 'the pin and the three-copy comparison ran; upstream parity did NOT (not passed)');
      return;
    }
    const TAG = 'v1.0.2';
    // The sibling checkout is still where the bytes come from — nothing here reaches a network —
    // but the comparison is against the TAG, so a sibling parked on another branch, or carrying
    // uncommitted edits, can no longer make this pass.
    const peeled = spawnSync('git', ['-C', SOURCE_REPO, 'rev-parse', `${TAG}^{commit}`],
      { encoding: 'utf8' });
    assert.equal(peeled.status, 0,
      `receipt-verifier has no ${TAG} tag — the vendored core cannot be traced to a release`);
    assert.equal(peeled.stdout.trim(), 'ac683b16c19662c9124c8cdab785223b28d2d0c6',
      `${TAG} points somewhere other than the commit this pin names`);
    // ── THE TAG IS VERIFIED, NOT MERELY RESOLVED ────────────────────────────────────────────
    //
    // `rev-parse` proves the tag points where the pin says. It does not prove the tag is the one
    // the releaser cut: an unsigned tag is a name anyone with push access can move, and this check
    // would keep passing after it moved, as long as the bytes were moved with it.
    //
    // v1.0.1 is annotated and SSH-signed, so the pin now resolves to an IDENTITY. This asserts the
    // signature verifies AND that it verifies against the fingerprint recorded in VENDOR.sha256 —
    // "signed" alone would accept a signature by anyone at all, which is not what a pin is for.
    //
    // MEASURED: `git tag -v` exits 0 and writes the verdict to STDERR, not stdout. A gate that
    // read stdout would find nothing and could be written to pass on an unsigned tag without ever
    // noticing it was reading the wrong stream.
    const SIGNER_FPR = 'SHA256:7yRXTm9zKGicfFpzL+7lpwFoPaoSwxAJlabB3jwxw2Y';
    const v = spawnSync('git', ['-C', SOURCE_REPO, 'tag', '-v', TAG], { encoding: 'utf8' });
    const verdict = `${v.stdout || ''}${v.stderr || ''}`;
    assert.equal(v.status, 0, `${TAG} does not verify as a signed tag:\n${verdict}`);
    assert.match(verdict, /Good .*signature/,
      `${TAG} carries no good signature — the vendored core cannot be traced to a signed release`);
    assert.ok(verdict.includes(SIGNER_FPR),
      `${TAG} is signed, but NOT by the key this pin records (${SIGNER_FPR}):\n${verdict}`);

    let compared = 0;
    for (const { file } of pinned()) {
      const r = spawnSync('git', ['-C', SOURCE_REPO, 'show', `${TAG}:${file}`], { maxBuffer: 1 << 24 });
      // Not every vendored file comes from the core — the header says which. A file absent at the
      // tag is skipped here and still covered by its own digest row above.
      if (r.status !== 0) continue;
      compared += 1;
      assert.ok(fs.readFileSync(path.join(SRC, file)).equals(r.stdout),
        `${file} has drifted from receipt-verifier@${TAG}`);
    }
    assert.ok(compared >= 3,
      `only ${compared} file(s) were compared against ${TAG} — a parity check over almost nothing`);
  });
});
