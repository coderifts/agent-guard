'use strict';

/**
 * Round 3 (2026-10-25): the vendored receipt-verifier core is the signed v1.1.5, and its keyring is
 * the live registry (sha256 0981898b…28dd, the bytes of GET
 * https://app.coderifts.com/.well-known/coderifts-keys.json). Before: v1.0.3 core, keyring bfe0c898…
 *
 * The pattern of receipt-verifier 1.1.5 test/key-algorithm-keyring-1.1.5.test.js, through the
 * vendored copy (src/vendor/verify.js):
 *   - the real public 07-k1 receipt (ts 2026-08-26, before retired_at) → RETIRED_KEY_VALID_AT_ISSUE;
 *   - a 07-k1 receipt with ts ≥ retired_at → KEY_RETIRED_AFTER_SIGNING (valid:false), as 1.1.5 says it.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const VENDOR = path.join(__dirname, '..', 'src', 'vendor');
const PIN = path.join(VENDOR, 'keys', 'coderifts-keys.json');
const LIVE_SHA256 = '0981898b8bd3fc5745be183f1cd021f355b1bbd8f37fc30b493e225a763928dd';
const FIXTURE_07_K1 = 'eyJ2IjoyLCJraWQiOiIyMDI2LTA3LWsxIiwiZnAiOiJzaGEyNTY6NjhhYzM4MTNjZjUzYjNiZDMyMDgwMjhmYTYwOWExMWI5YTE3MDEyYjRmNTk5NGFhZmFjZGM3YTc5MzAzOTUyZCIsInByZXYiOiJudWxsIiwiY2FsbGVyIjoiYW5vbiIsInRzIjoiMjAyNi0wOC0yNlQyMToyMTo1OS4yMTJaIiwicmVnIjoiNGY1M2NkYTE4YzJiYWEwYzAzNTRiYjVmOWEzZWNiZTVlZDEyYWI0ZDhlMTFiYTg3M2MyZjExMTYxMjAyYjk0NSJ9.V1HOj8SKzT_KBLwlYaEYCziHsaZo390kuHReZg5yByvavNTNOxT1qhANIRc5Av0tJd6PVQvMDahGj8C4nCH8Bg';
const { verifyReceipt, keyringFromDocument, reconstructSignedInput } = require(path.join(VENDOR, 'verify.js'));

describe('round 3 · the vendored keyring is the live registry', () => {
  const doc = JSON.parse(fs.readFileSync(PIN, 'utf8'));
  it('the pin is the live bytes, and VENDOR.sha256 records the same hash', () => {
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(PIN)).digest('hex'), LIVE_SHA256);
    assert.match(fs.readFileSync(path.join(VENDOR, 'VENDOR.sha256'), 'utf8'), new RegExp(`keys/coderifts-keys\\.json\\s+${LIVE_SHA256}`));
  });
  it('2026-10-k1 active, 2026-07-k1 retired at 2026-10-21', () => {
    assert.deepEqual(doc.keys.map((k) => [k.kid, k.status, k.valid_from, k.retired_at]), [
      ['2026-10-k1', 'active', null, null],
      ['2026-07-k1', 'retired', null, '2026-10-21T00:00:00.000Z'],
    ]);
  });
  it('the real 07-k1 receipt (ts before retired_at) → RETIRED_KEY_VALID_AT_ISSUE', () => {
    const r = verifyReceipt(FIXTURE_07_K1, { keyring: keyringFromDocument(doc, 'pin'), expectedKid: null });
    assert.equal(r.valid, true);
    assert.equal(r.status, 'RETIRED_KEY_VALID_AT_ISSUE');
  });
  it('a 07-k1 receipt at or after retired_at → KEY_RETIRED_AFTER_SIGNING (test key under the live entry)', () => {
    const kp = crypto.generateKeyPairSync('ed25519');
    const reg = { keys: [doc.keys[0], { ...doc.keys[1], public_key_pem: kp.publicKey.export({ type: 'spki', format: 'pem' }) }] };
    const keyring = keyringFromDocument(reg, 'test');
    const sign = (ts) => {
      const p = { v: 2, kid: '2026-07-k1', fp: `sha256:${'1'.repeat(64)}`, prev: 'null', caller: 'anon', ts, reg: '' };
      return `${Buffer.from(JSON.stringify(p)).toString('base64url')}.${crypto.sign(null, Buffer.from(reconstructSignedInput(p), 'utf8'), kp.privateKey).toString('base64url')}`;
    };
    assert.equal(verifyReceipt(sign('2026-10-20T23:59:59.000Z'), { keyring, expectedKid: null }).status, 'RETIRED_KEY_VALID_AT_ISSUE');
    const after = verifyReceipt(sign('2026-10-21T00:00:00.000Z'), { keyring, expectedKid: null });
    assert.equal(after.valid, false);
    assert.equal(after.status, 'KEY_RETIRED_AFTER_SIGNING');
  });
});
