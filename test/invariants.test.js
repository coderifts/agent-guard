'use strict';

/**
 * INVARIANTS.md — the enforcing tests.
 *
 * An invariant with no test is a convention, and a convention is what produced three majors in one
 * day. These tests reference INVARIANTS.md by number so a rule and its enforcement cannot drift
 * apart silently: if an entry claims `ENFORCED BY: test/invariants.test.js`, a test here must
 * carry that number.
 *
 * TWO OF THESE PIN A VIOLATION RATHER THAN A GUARANTEE (#4 and #8). That is deliberate. A rule we
 * do not hold is worth pinning precisely so a future fix has to delete the test on purpose,
 * instead of the rule quietly becoming true-by-forgetting.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const INVARIANTS = fs.readFileSync(path.join(ROOT, 'INVARIANTS.md'), 'utf8');

const readSrc = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');
/** Source with comments stripped — a rule must hold in CODE, not in prose about code. */
const codeOnly = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('the file and its tests cannot drift apart', () => {
  it('every invariant that claims a test here is actually numbered here', () => {
    const claimed = [...INVARIANTS.matchAll(/^## (\d+)\.[\s\S]*?\*\*ENFORCED BY:\*\* ([^\n]+)/gm)]
      .filter((m) => m[2].includes('test/invariants.test.js'))
      .map((m) => Number(m[1]));
    assert.ok(claimed.length >= 5, `expected several enforced invariants, saw ${claimed.length}`);
    const src = fs.readFileSync(__filename, 'utf8');
    for (const n of claimed) {
      assert.ok(new RegExp(`#${n}\\b`).test(src),
        `INVARIANTS.md #${n} claims this file enforces it, but no test here references #${n}`);
    }
  });

  it('an invariant with no test SAYS SO — no blanks, no implied enforcement', () => {
    const entries = [...INVARIANTS.matchAll(/^## \d+\.[^\n]*\n([\s\S]*?)(?=^## |\Z)/gm)];
    assert.equal(entries.length, 10, 'there are ten prohibitions');
    for (const [, body] of entries) {
      assert.match(body, /\*\*ENFORCED BY:\*\*/, 'every entry must state its enforcement or its absence');
      assert.match(body, /\*\*MEASURED[.:]?/, 'every entry must record what was measured');
      assert.match(body, /\*\*DEFECT CLASS\.\*\*/, 'a rule without its defect class is a preference');
    }
  });
});

describe('#1 no guard callback signature accepts a provider credential', () => {
  it('no callback type in the public input carries a token or credential parameter', () => {
    const wc = codeOnly(readSrc('with-coderifts.ts'));
    // Callback-typed fields on the public input surface.
    const callbacks = [...wc.matchAll(/^\s*(\w+)\??:\s*\(([^)]*)\)\s*=>/gm)];
    assert.ok(callbacks.length > 0, 'expected callback signatures to inspect');
    for (const [, name, params] of callbacks) {
      assert.equal(/token|credential|apiKey|api_key|secret|password/i.test(params), false,
        `callback ${name} takes a credential-looking parameter: (${params})`);
    }
  });

  it('the guard never reads a provider token from the environment', () => {
    for (const f of fs.readdirSync(SRC).filter((x) => x.endsWith('.ts'))) {
      const code = codeOnly(readSrc(f));
      assert.equal(/process\.env\.(GITHUB_TOKEN|GH_TOKEN|CODERIFTS_API_KEY)/.test(code), false,
        `${f} reads a provider credential from the environment`);
    }
  });
});

describe('#2 CAS adapters contain no shell or network capability', () => {
  it('no adapter imports child_process or performs a network call', () => {
    const dir = path.join(SRC, 'cas-adapters');
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.ts'));
    assert.ok(files.length > 0, 'expected CAS adapters to inspect');
    for (const f of files) {
      const code = codeOnly(fs.readFileSync(path.join(dir, f), 'utf8'));
      for (const banned of ['child_process', 'spawn(', 'execSync', 'fetch(', 'https.request', 'http.request']) {
        assert.equal(code.includes(banned), false,
          `cas-adapters/${f} contains ${banned} — an executor that can do this is a better attack surface than what it guards`);
      }
    }
  });
});

describe('#4 the atomic profile — PARTLY fixed by _V1, and the remainder pinned', () => {
  // UPDATED 2026-08-27 when ENFORCING_STRICT_V1 shipped. These tests used to pin the ORIGINAL
  // violation (an unversioned name). That half is fixed and the record says so. What they pin now
  // is the REMAINDER, because a shipped improvement must not quietly flip a record it did not
  // fully earn — the entry in INVARIANTS.md still reads as violated, for two stated reasons.

  it('REMAINDER 1: the unsuffixed alias is still an accepted UNVERSIONED public spelling', () => {
    const wc = readSrc('with-coderifts.ts');
    assert.match(wc, /export type WithCodeRiftsProfile = 'ENFORCING_STRICT' \| 'ENFORCING_STRICT_V1'/,
      'both spellings are accepted; the unsuffixed one names a contract without naming its version');
    // Nothing structural stops a maintainer re-pointing the alias at a future _V2 — only a comment
    // and a test. Removing the alias in a major is what would close this.
    assert.match(INVARIANTS, /## 4\.[\s\S]*?STILL VIOLATED, BUT NARROWLY/,
      'INVARIANTS.md must keep #4 as violated while the alias exists');
  });

  it('REMAINDER 2: the contract is procedural checks, not a versioned table', () => {
    const wc = codeOnly(readSrc('with-coderifts.ts'));
    // _V1 is nine conditions across three code paths, frozen by a test that READS THE SOURCE.
    // That is drift protection, not a declaration. A real contract would be data both _V1 and a
    // future _V2 point at.
    assert.ok(wc.includes('enforcingStrictWeakenFlags'), 'still a flag-scanning function');
    assert.ok(wc.includes('enforcingStrictExecutionChainProblems'), 'still a separate chain check');
    assert.equal(/PROFILE_CONTRACTS\s*[:=]|const PROFILES\s*[:=]/.test(wc), false,
      'if a versioned contract TABLE ships, #4 and this test must be revisited together');
  });

  it('WHAT WAS FIXED is recorded, not merely dropped', () => {
    // The rule this entry came from — meaning changing under its own name — cannot recur for _V1.
    assert.match(INVARIANTS, /## 4\.[\s\S]*?UPDATED 2026-08-27 WHEN `_V1` SHIPPED/);
    assert.match(INVARIANTS, /## 4\.[\s\S]*?the expensive half is closed, the definitional half is not/);
  });
});

describe('#5 the shared-issuer residual is stated where the app id is defined', () => {
  // Cross-repo read: the constant lives in the CLI. Skipping when the sibling is absent would let
  // the check disappear silently, so a missing checkout is reported rather than skipped.
  const cliConstant = path.join(
    os.homedir(), 'coderifts-app', 'packages', 'cli', 'src', 'provider', 'required-check-contract.js',
  );

  it('app_id 15368 is documented as GitHub Actions, shared, and never as ours', () => {
    if (!fs.existsSync(cliConstant)) {
      assert.fail(`sibling CLI checkout missing at ${cliConstant} — cannot verify #5, and a silent skip is how this rule would rot`);
    }
    const s = fs.readFileSync(cliConstant, 'utf8');
    assert.match(s, /15368/);
    assert.match(s, /shared by every GitHub Actions workflow/i,
      'the residual must be stated at the definition, not only in a design doc');
    assert.equal(/CodeRifts[- ]specific|our own app id|identifies CodeRifts/i.test(s), false,
      'nothing may describe the shared Actions issuer as a CodeRifts identity');
  });
});

describe('#7 an indeterminate outcome is never retried automatically', () => {
  it('no indeterminate branch sits next to retry or loop logic', () => {
    for (const f of fs.readdirSync(SRC).filter((x) => x.endsWith('.ts'))) {
      const code = codeOnly(readSrc(f));
      if (!/indeterminate/i.test(code)) continue;
      const lines = code.split('\n');
      lines.forEach((line, i) => {
        if (!/indeterminate/i.test(line)) return;
        const window = lines.slice(Math.max(0, i - 3), i + 4).join('\n');
        assert.equal(/\bretry\b|\bretries\b|for\s*\(|while\s*\(/i.test(window), false,
          `${f}:${i + 1} — an indeterminate write may have landed; retrying it is a second write`);
      });
    }
  });
});

describe('#8 the commit label', () => {
  it('the STRICT profile refuses a host-claimed commit', () => {
    const cas = codeOnly(readSrc('cas-attestation.ts'));
    assert.match(cas, /evidence\.class === 'executor_attested'/,
      'strictCommitObservation must demand an executor attestation');
    assert.match(cas, /bindingIntendedSupplied/,
      'and a kernel binding, so the attestation cross-checks THIS outcome');
  });

  it('DEFAULT PROFILE: a host-claimed commit still earns the name — the violation, pinned', () => {
    // Measured: authorized_and_committed = receipt_verified && cas.status === 'committed', where
    // cas.status comes from the host-supplied outcome. The strict AND is applied only when the
    // profile is set. Deleting this test is how the fix announces itself.
    const cas = codeOnly(readSrc('cas-attestation.ts'));
    assert.match(cas, /let authorized_and_committed = receipt_verified && cas\.status === 'committed'/);
    assert.match(cas, /if \(opts\.profile === 'ENFORCING_STRICT'\)/);
    assert.match(INVARIANTS, /## 8\.[\s\S]*?WE DO NOT HOLD THIS AS STATED/,
      'INVARIANTS.md must record #8 as holding only under strict');
  });
});

describe('#9 the inescapable claim', () => {
  it('the basis names LAYERS and never claims unreachability', () => {
    const cli = path.join(
      os.homedir(), 'coderifts-app', 'packages', 'cli', 'src', 'provider', 'github-enforcement.js',
    );
    if (!fs.existsSync(cli)) {
      assert.fail(`sibling CLI checkout missing at ${cli} — cannot verify #9`);
    }
    const s = fs.readFileSync(cli, 'utf8');
    assert.match(s, /all six layers VERIFIED/, 'the true-branch basis must enumerate what was verified');
    // The basis must not assert a negative it cannot observe.
    assert.equal(/basis:[^\n]*(nobody can|cannot be bypassed|no way around|unreachable)/i.test(s), false,
      'the basis must not claim unreachability, which no configuration read can establish');
  });

  it('the finding is recorded word-by-word, with a narrowing that is NOT shipped', () => {
    assert.match(INVARIANTS, /## 9\.[\s\S]*?WE VIOLATE THIS/);
    assert.match(INVARIANTS, /provider_configured_to_block/, 'the proposed name must be written down');
    assert.match(INVARIANTS, /NOT shipped, because the wording is adopter-facing/);
  });
});

describe('what needs an executor is named, not silently omitted', () => {
  it('#3, #6 and #10 are listed as out of scope with their reason', () => {
    const tail = INVARIANTS.slice(INVARIANTS.indexOf('## What needs an executor'));
    for (const n of ['#3', '#6', '#10']) {
      assert.ok(tail.includes(n), `${n} must be named in the out-of-scope section`);
    }
    assert.match(tail, /asserting a property of code that is\s*\n?not in this repository/,
      'the reason must be stated: a test here would be vacuous');
  });
});
