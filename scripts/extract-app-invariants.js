#!/usr/bin/env node
'use strict';

/**
 * 1394 (revised) — regenerate the EXTRACTED-INVARIANT snapshots.
 *
 * ── WHY EXTRACTED AND NOT WHOLE ─────────────────────────────────────────────────────────────
 *
 * The first version of this snapshot vendored `src/change-set.js` (74 kB) and
 * `packages/cli/src/provider/github-enforcement.js` (60 kB) verbatim into this PUBLIC repository.
 * They are not thin generated types like the SDK's: one is the governance engine, the other the
 * provider adapter carrying the permission detail behind the 1405 provider-identity caution.
 * Publishing them is over-exposure, and it cannot be taken back while the open-core position is
 * still open. So only what the parity tests ACTUALLY assert is recorded.
 *
 * The other four artifacts stay WHOLE because they are thin and are already public-shaped:
 *   crbundle-v1-parity.frozen.json     699 B   a frozen test vector
 *   v2-grant-canonical-request.json   3.5 kB   a request-shape fixture
 *   policy.txt                        4.8 kB   the rule text we ship to agents
 *   required-check-contract.js        4.1 kB   a contract constant; 15368 is GitHub's own app id
 *
 * Usage: node scripts/extract-app-invariants.js   (requires a coderifts-app checkout)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const GUARD = path.join(__dirname, '..');
const SNAP = path.join(GUARD, 'fixtures', 'recorded', 'app-sync');
const APP = process.env.CODERIFTS_APP_DIR || process.env.CODERIFTS_APP_ROOT
  || path.join(process.env.HOME || os.homedir(), 'coderifts-app');

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

/** The seven cases test/exported-bundle-fingerprint-parity.test.js compares. Kept in step by that test. */
function fingerprintVectors() {
  const { CASES } = require(path.join(GUARD, 'test', 'lib', 'bundle-fingerprint-cases.js'));
  const { computeBundleFingerprint } = require(path.join(APP, 'src', 'change-set.js'));
  return {
    $comment:
      'GOLDEN OUTPUTS, not the producer. The parity test calls the app\'s computeBundleFingerprint '
      + 'on seven fixed inputs and compares byte-for-byte with the Guard\'s exported copy. In '
      + 'RECORDED mode the app side is these recorded outputs. WHAT IS LOST: a drift introduced in '
      + 'the app AFTER this recording is invisible until a LIVE run regenerates it — RECORDED '
      + 'proves the Guard still matches what the app produced at the pinned commit, never what it '
      + 'produces today. WHAT IS NOT LOST: every one of the seven cases still runs and still '
      + 'compares, including the ordering and null-side cases the engine is easiest to break on.',
    vectors: CASES.map((c) => ({
      name: c.name,
      fingerprint: computeBundleFingerprint(c.artifacts, c.context),
    })),
  };
}

const written = [];
function write(name, bytes, source, note) {
  fs.writeFileSync(path.join(SNAP, name), bytes);
  written.push({ path: name, source, sha256: sha256(bytes), bytes: bytes.length, ...(note ? { note } : {}) });
}

/**
 * Invariant #9's two textual properties, extracted. EVERY line matching the basis pattern is taken
 * (not only the positive one), so the negative assertion still sees every candidate.
 *
 * NO PROSE IN THE OUTPUT. An earlier draft put this explanation inside the .txt, and the sentence
 * describing the forbidden pattern MATCHED it — the snapshot failed the assertion it was recording.
 * What is scanned is exactly what is recorded; the prose lives in EXTRACTED-INVARIANTS.md.
 */
function enforcementInvariantLines() {
  const src = fs.readFileSync(path.join(APP, 'packages', 'cli', 'src', 'provider', 'github-enforcement.js'), 'utf8');
  const out = [];
  src.split(String.fromCharCode(10)).forEach((l, i) => {
    if (l.includes('all six layers VERIFIED') || /basis:/i.test(l)) out.push('L' + (i + 1) + ': ' + l.trim());
  });
  if (out.length === 0) throw new Error('extract found no invariant lines — the adapter moved; update this extractor');
  return Buffer.from(out.join(String.fromCharCode(10)) + String.fromCharCode(10), 'utf8');
}

const vec = Buffer.from(`${JSON.stringify(fingerprintVectors(), null, 2)}\n`, 'utf8');
write('change-set.fingerprints.json', vec, 'src/change-set.js computeBundleFingerprint() — EXTRACTED outputs',
  'extracted invariant: seven golden fingerprints, not the 74 kB engine');

write('github-enforcement.invariants.txt', enforcementInvariantLines(),
  'packages/cli/src/provider/github-enforcement.js — EXTRACTED lines',
  'extracted invariant: the lines invariant #9 asserts on, not the 60 kB adapter');

process.stdout.write(`extract-app-invariants: wrote ${written.length} file(s) to ${SNAP}\n`);
for (const w of written) process.stdout.write(`  ${w.path} ${w.sha256.slice(0, 12)} ${w.bytes} B\n`);
module.exports = { fingerprintVectors };
