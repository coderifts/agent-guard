/**
 * LIVE vs RECORDED app-sync (1380 / 1127 / 1374 pattern).
 *
 * LIVE  — coderifts-app checkout present: compare against live generator /
 *         getCanonicalRuleText / canonical fixture, AND fail if this recording is stale.
 * RECORDED — no checkout: compare against the vendored snapshot, labeled
 *         weaker than LIVE. Missing or corrupt snapshot exits 1 — no skip.
 *
 * LIVE resolution: CODERIFTS_APP_DIR || CODERIFTS_APP_ROOT || $HOME/coderifts-app.
 * No sibling-path shortcut — that would make a local checkout look like CI.
 *
 * @module @coderifts/agent-guard/lib/recorded-app-sync
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ROOT = process.env.CODERIFTS_GUARD_ROOT
  ? path.resolve(process.env.CODERIFTS_GUARD_ROOT)
  : path.resolve(__dirname, '..');
const SNAP_DIR = path.join(ROOT, 'fixtures', 'recorded', 'app-sync');
const PIN_PATH = path.join(SNAP_DIR, 'pin.json');

function sha256hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function appRoot() {
  const fromDir = process.env.CODERIFTS_APP_DIR && String(process.env.CODERIFTS_APP_DIR).trim();
  if (fromDir) return path.resolve(fromDir);
  const fromRoot = process.env.CODERIFTS_APP_ROOT && String(process.env.CODERIFTS_APP_ROOT).trim();
  if (fromRoot) return path.resolve(fromRoot);
  return path.join(process.env.HOME || os.homedir(), 'coderifts-app');
}

/**
 * The four app artifacts THIS suite compares against. Ported from the SDK's helper (1380); the
 * list differs because the Guard checks different things — crbundle parity, the exported
 * fingerprint, the two provider contracts behind INVARIANTS #5/#9, and the policy text.
 *
 * ALL must be present for LIVE. A partial checkout would run some gates live and others recorded
 * inside one run, and the banner could then only lie about one of them.
 */
const LIVE_ARTIFACTS = Object.freeze([
  ['test', 'fixtures', 'crbundle-v1-parity.frozen.json'],
  ['src', 'change-set.js'],
  ['src', 'agent-host-rule.js'],
  ['packages', 'cli', 'src', 'provider', 'required-check-contract.js'],
  ['packages', 'cli', 'src', 'provider', 'github-enforcement.js'],
]);

function generatorsPresent() {
  const root = appRoot();
  return LIVE_ARTIFACTS.every((seg) => fs.existsSync(path.join(root, ...seg)));
}

/** Absolute path to an app artifact, for the LIVE branch. */
function livePath(...seg) {
  return path.join(appRoot(), ...seg);
}

function loadPin() {
  if (!fs.existsSync(PIN_PATH)) {
    const err = new Error(
      `RECORDED snapshot missing at ${PIN_PATH}. `
      + 'Reporting a comparison that did not happen is worse than failing. '
      + 'Restore fixtures/recorded/app-sync/.',
    );
    err.code = 'NO_RECORDED';
    throw err;
  }
  const pin = JSON.parse(fs.readFileSync(PIN_PATH, 'utf8'));
  if (!Array.isArray(pin.artifacts) || pin.artifacts.length === 0) {
    const err = new Error('RECORDED pin has no artifacts — refusing to skip');
    err.code = 'NO_RECORDED';
    throw err;
  }
  for (const a of pin.artifacts) {
    const p = path.join(SNAP_DIR, a.path);
    if (!fs.existsSync(p)) {
      const err = new Error(
        `RECORDED snapshot missing ${a.path} at ${p}. `
        + 'Reporting a comparison that did not happen is worse than failing.',
      );
      err.code = 'NO_RECORDED';
      throw err;
    }
    const got = sha256hex(fs.readFileSync(p));
    if (got !== a.sha256) {
      const err = new Error(
        `RECORDED snapshot corrupt ${a.path}: pin ${a.sha256} bytes ${got}`,
      );
      err.code = 'STALE_RECORDED';
      throw err;
    }
  }
  return pin;
}

/**
 * Every read is checked against the pin. MEASURED 2026-09-06: deleting pin.json left the suite
 * GREEN, because the converted tests read the snapshot files and never loaded the pin — so the
 * one thing making the recording tamper-evident was optional. A snapshot nobody verifies is not a
 * recording, it is a second unversioned source of truth.
 *
 * Throws (never returns a fallback) on: missing pin, unlisted artifact, missing file, sha mismatch.
 * Reporting a comparison against bytes we cannot vouch for is worse than failing.
 */
function verifiedSnapshot(rel) {
  const pin = loadPin();
  const entry = (pin.artifacts || []).find((a) => a.path === rel);
  if (!entry) {
    throw new Error(`RECORDED snapshot ${rel} is not listed in ${PIN_PATH} — `
      + 'an unpinned file is not a recording. Regenerate the snapshot.');
  }
  const abs = path.join(SNAP_DIR, rel);
  if (!fs.existsSync(abs)) {
    throw new Error(`RECORDED snapshot missing at ${abs} (pinned as ${entry.sha256.slice(0, 12)}).`);
  }
  const bytes = fs.readFileSync(abs);
  const got = sha256hex(bytes);
  if (got !== entry.sha256) {
    throw new Error(`RECORDED snapshot ${rel} does not match its pin: ${got.slice(0, 12)} != `
      + `${entry.sha256.slice(0, 12)}. Either the file was edited by hand or the pin is stale; `
      + 'regenerate both together.');
  }
  return bytes;
}

function snapshotPath(rel) {
  verifiedSnapshot(rel);   // path handed out only after the bytes check out
  return path.join(SNAP_DIR, rel);
}

function snapshotBytes(rel) {
  return verifiedSnapshot(rel);
}

function snapshotText(rel) {
  return verifiedSnapshot(rel).toString('utf8');
}

function modeBanner(mode) {
  return mode === 'LIVE' ? '[LIVE]' : '[RECORDED — weaker than LIVE]';
}

function liveCanonicalPath() {
  return path.join(appRoot(), 'test', 'fixtures', 'v2-grant-canonical-request.json');
}

function liveGeneratorPath() {
  return path.join(appRoot(), 'scripts', 'generate-grant-request-types.js');
}

function liveRulePath() {
  return path.join(appRoot(), 'src', 'agent-host-rule.js');
}

module.exports = {
  verifiedSnapshot,
  livePath,
  LIVE_ARTIFACTS,
  ROOT,
  SNAP_DIR,
  PIN_PATH,
  sha256hex,
  appRoot,
  generatorsPresent,
  loadPin,
  snapshotPath,
  snapshotBytes,
  snapshotText,
  modeBanner,
  liveCanonicalPath,
  liveGeneratorPath,
  liveRulePath,
};
