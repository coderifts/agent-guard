'use strict';

/**
 * 1307 — the guard can verify offline, and can fail closed on a missing receipt.
 *
 * THE ASYMMETRY, measured across the four enforcement points before this:
 *
 *   contract-gate      offline, pinned keyring
 *   k8s-admission      offline, pinned keyring
 *   gateway-verifier   offline, pinned keyring
 *   agent-guard        OVER THE NETWORK, and not fail-closed on a MISSING receipt
 *
 * Two different gaps in one place, and the tests below are split the same way.
 *
 * WHAT THE WORST CASE LOOKS LIKE HERE. For the network half: the issuer is unreachable, or is
 * watching which receipts get checked. For the missing-receipt half: a proxy strips the receipt and
 * edits `execution_action` — with no receipt there is nothing to detect the edit, and the old code
 * proceeded on the reconciled envelope.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { offlineReceiptVerifier, missingReceiptDecision } = require('../dist/cjs/index.js');

// ── the missing-receipt posture ──────────────────────────────────────────────────────────────

describe('missing receipt — proceed stays the default', () => {
  it('an envelope WITH a receipt is never affected by this policy', () => {
    // The present-and-invalid case is guard.ts:812's job and is untouched.
    for (const policy of [undefined, 'proceed', 'fail-closed']) {
      assert.equal(missingReceiptDecision(policy, true).stop, false, `policy ${policy}`);
    }
  });

  it('no policy configured → proceeds, exactly as before', () => {
    // Every existing host. If this ever flipped, upgrading the guard would start refusing the
    // analyze path, which carries no receipt by design.
    assert.equal(missingReceiptDecision(undefined, false).stop, false);
    assert.equal(missingReceiptDecision('proceed', false).stop, false);
  });

  it('fail-closed → stops, and says WHY in terms of what is at risk', () => {
    const d = missingReceiptDecision('fail-closed', false);
    assert.equal(d.stop, true);
    assert.equal(d.cause, 'RECEIPT_MISSING');
    assert.match(d.detail, /not tamper-evident/);
    assert.match(d.detail, /execution_action/,
      'the reason should name what an attacker would change');
  });

  it('WORST CASE: an unrecognised policy string does not silently enable fail-closed', () => {
    // Nor silently disable it. A typo must land on the documented default, not on a third
    // behaviour nobody chose.
    assert.equal(missingReceiptDecision('failclosed', false).stop, false);
    assert.equal(missingReceiptDecision('FAIL-CLOSED', false).stop, false);
  });

  it('the guard actually CALLS this — it is not an exported ornament', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'guard.ts'), 'utf8');
    assert.match(src, /missingReceiptDecision\(config\.requireReceipt/,
      'nothing in the guard consults the missing-receipt policy');
    // And after the present-and-invalid branch: a receipt that IS present must still be judged on
    // its signature first.
    assert.ok(
      src.indexOf('envelope.receipt?.token) {') < src.indexOf('missingReceiptDecision('),
      'the missing-receipt check runs before the invalid-receipt check',
    );
  });
});

// ── offline verification ─────────────────────────────────────────────────────────────────────

describe('offline verification against a pinned keyring', () => {
  it('an empty or unreadable keyring fails LOUDLY at construction', async () => {
    // Not at the first verification. An empty ring makes every receipt UNKNOWN_KEY, which reads as
    // "the receipts are bad" when the truth is "we were given no keys".
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-ring-'));
    const empty = path.join(tmp, 'empty.json');
    fs.writeFileSync(empty, JSON.stringify({ keys: [] }));
    // MEASURED: the VENDORED loadKeyring already refuses this first, with `no keys[] in registry
    // <path>` — a better message than ours because it names the file. Our guard covers the case it
    // does not (a loader that returns an empty ring without throwing). Either way the requirement
    // is the same and it is what this asserts: LOUD at construction, never quiet until first use.
    await assert.rejects(
      () => offlineReceiptVerifier(empty),
      (err) => /no keys\[\] in registry|pinned keyring is empty or unreadable/.test(String(err.message)),
      'an empty keyring was accepted, and would refuse every receipt for the wrong reason',
    );
  });

  it('a real keyring produces a verifier with the SAME shape as the network one', async () => {
    // The two must be interchangeable, or the offline path would be a second, differently-behaving
    // verifier and the guard's call site would have to know which one it holds.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-ring-'));
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const ring = path.join(tmp, 'keys.json');
    fs.writeFileSync(ring, JSON.stringify({
      keys: [{
        kid: 'k1',
        public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
        status: 'active',
      }],
    }));
    const verify = await offlineReceiptVerifier(ring);
    assert.equal(typeof verify, 'function');
    const out = await verify('not-a-real-token');
    assert.equal(typeof out.valid, 'boolean');
    assert.equal(typeof out.status, 'string');
    assert.equal(out.valid, false, 'garbage must not verify');
  });

  it('WORST CASE: it never reaches the network — no fetch in the offline path', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'offline-verify.ts'), 'utf8');
    assert.doesNotMatch(src, /fetch\(|https?\.request\(|axios|new URL\(.*http/,
      'the offline verifier acquired a network call');
    // And the keyring itself is never fetched — a fetchable ring would let whoever answers the
    // fetch choose the keys, which makes "offline" a configuration detail rather than a property.
    assert.match(src, /NEVER FETCHED/);
  });

  it('the vendored core is pinned, and matches its pin', () => {
    const dir = path.join(__dirname, '..', 'src', 'vendor');
    const pin = fs.readFileSync(path.join(dir, 'VENDOR.sha256'), 'utf8');
    for (const f of ['verify.js', 'arity.js']) {
      const digest = crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, f))).digest('hex');
      assert.ok(pin.includes(digest), `${f} drifted from its pin — recopy from receipt-verifier`);
    }
  });

  it('the pin names the upstream revision, so a reader can reproduce the copy', () => {
    const pin = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'vendor', 'VENDOR.sha256'), 'utf8',
    );
    assert.match(pin, /receipt-verifier [0-9a-f]{40}/, 'the pin does not name a source revision');
  });
});

// ── the claim this item exists to make true ──────────────────────────────────────────────────

describe('the four-point sentence', () => {
  it('this point CAN now verify offline — the capability exists and is exported', () => {
    const pkg = require('../dist/cjs/index.js');
    assert.equal(typeof pkg.offlineReceiptVerifier, 'function');
    assert.equal(typeof pkg.missingReceiptDecision, 'function');
  });

  it('but it is OPT-IN, and this test says so rather than letting the claim drift', () => {
    // The honest form of the sentence: all four points CAN verify offline; this one does so when a
    // keyring is configured, and uses the network otherwise. Claiming "all four do, always" would
    // be false for every host that has not set receiptKeyring.
    const types = fs.readFileSync(path.join(__dirname, '..', 'src', 'types.ts'), 'utf8');
    assert.match(types, /receiptKeyring\?:/, 'the keyring option is not optional in the type');
    assert.match(types, /requireReceipt\?:/, 'the missing-receipt policy is not optional');
  });
});
