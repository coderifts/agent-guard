'use strict';

/**
 * 1375 — the raw-shell boundary.
 *
 * ── WHAT WAS MEASURED, 2026-09-05, BEFORE THE FIX ───────────────────────────────────────────
 *
 * guard 16.0.0 fail-closes on an unguarded mutation, and everyone (me included) assumed that
 * covered a raw shell. It did not. Through guardToolRegistry, with the client unreachable:
 *
 *   Bash { command: 'kubectl apply -f prod.yaml' }   SKIPPED → executed:true
 *   Bash { command: 'terraform apply -auto-approve' } SKIPPED → executed:true
 *   Bash { command: 'gh pr merge 42 --merge' }        SKIPPED → executed:true
 *   Bash { command: 'rm -rf /var/lib/data' }          SKIPPED → executed:true
 *
 * And it kept slipping WITH an explicit `mutationClass: 'mutating_shell'` on the tool, which is
 * the part that makes this a hole rather than a limitation: the host said the word, and the word
 * did not travel. The registry had already resolved Bash to mutating_shell and marked it
 * guarded:true — correct all along — but ToolCallDescriptor carried no field for it, so the
 * fail-closed decision never saw it.
 *
 * ── THE FIX IS NOT A COMMAND CLASSIFIER ─────────────────────────────────────────────────────
 *
 * Nothing added here reads a command string, and nothing should. `sh -c`, an alias, a wrapper
 * script, base64 — a string test loses that race and, worse, LOOKS like it is winning. The claim
 * made instead is one the guard can hold: a capability the host declares as mutating does not run
 * unguarded. That is capability-narrowing, and the incentive it creates is the point — if raw
 * shell blocks on every call, the fix is to take raw shell off the guarded host.
 *
 * `ls -la` blocking is therefore CORRECT, not collateral damage. A raw shell is undecidable by
 * construction; grading a read as safe would mean guessing, and the guess is what an attacker
 * writes their command to satisfy.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { guardToolRegistry, isDeclaredMutatingClass } = require('../dist/cjs/index.js');

/** Unreachable on purpose: nothing below may depend on a preflight succeeding. */
const UNREACHABLE = {
  async preflightChangeSet() { throw new Error('network'); },
  async authorizeChangeSet() { throw new Error('network'); },
  async verifyReceipt() { throw new Error('network'); },
};

function reg(tool) {
  return guardToolRegistry([{ execute: async () => 'RAN', ...tool }],
    { guard: { client: UNREACHABLE, operation: 'deploy' } });
}

const MUTATING_COMMANDS = [
  'kubectl apply -f prod.yaml',
  'terraform apply -auto-approve',
  'gh pr merge 42 --merge',
  'curl -X POST https://deploy.example/hook',
  'helm upgrade prod ./chart',
  'rm -rf /var/lib/data',
];

describe('1375 — a raw shell does not execute unguarded', () => {
  for (const command of MUTATING_COMMANDS) {
    it(`Bash { command: ${JSON.stringify(command)} } → BLOCKED`, async () => {
      const outcome = await reg({ name: 'Bash' }).tools[0].execute({ command });
      assert.equal(outcome.verdict.cause, 'UNGUARDED_MUTATION');
      assert.equal(outcome.executed, false);
      assert.equal(outcome.executionAttempted, false, 'the raw executor must never be reached');
    });
  }

  it('a read-looking command blocks too — undecidable is not safe', async () => {
    // If this ever passes, someone taught the guard to read command strings. That is the failure
    // this test exists to catch, not a feature: the next command would be `ls -la; kubectl apply`.
    const outcome = await reg({ name: 'Bash' }).tools[0].execute({ command: 'ls -la' });
    assert.equal(outcome.executed, false);
  });

  it('an explicitly declared mutating_shell blocks — the declaration now travels', async () => {
    const outcome = await reg({ name: 'Bash', mutationClass: 'mutating_shell' })
      .tools[0].execute({ command: 'kubectl apply -f prod.yaml' });
    assert.equal(outcome.executed, false);
  });
});

describe('1375 — capability-narrowing, and what it does NOT touch', () => {
  it('a readonly tool is unaffected and still runs', async () => {
    // The registry leaves readonly tools unguarded, so the raw result comes back as-is.
    const out = await reg({ name: 'Read' }).tools[0].execute({ path: 'README.md' });
    assert.equal(out, 'RAN');
  });

  it('NO COMMAND STRING IS READ — the source proves it', () => {
    // The strongest form of "this is not a classifier": assert the absence of the classifier.
    const fs = require('node:fs');
    const path = require('node:path');
    const strip = (f) => fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const f of ['unguarded-mutation.ts', 'guard.ts']) {
      const src = strip(f);
      for (const needle of ['kubectl', 'terraform', 'helm', 'arguments.command', 'args.command']) {
        assert.equal(src.includes(needle), false, `${f} must not inspect commands (${needle})`);
      }
    }
  });

  it('the class test is a prefix, so a future mutating_* is covered on the day it is added', () => {
    for (const c of ['mutating', 'mutating_shell', 'mutating_deploy', 'mutating_something_new']) {
      assert.equal(isDeclaredMutatingClass(c), true, c);
    }
    for (const c of ['readonly', undefined, null, '', 'read', 42, {}]) {
      assert.equal(isDeclaredMutatingClass(c), false, JSON.stringify(c));
    }
  });

  it('the named opt-out still works, loudly', async () => {
    // Capability-narrowing without an escape is a footgun: a host that genuinely must keep raw
    // shell needs a way through that is deliberate and audible.
    process.env.CODERIFTS_ADVISORY = '1';
    const warnings = [];
    const original = console.warn;
    console.warn = (m) => warnings.push(String(m));
    try {
      const outcome = await reg({ name: 'Bash' }).tools[0].execute({ command: 'kubectl apply -f x' });
      assert.equal(outcome.executed, true);
      assert.equal(warnings.length, 1, 'an advisory raw-shell execution must never be silent');
      assert.match(warnings[0], /ADVISORY/);
    } finally {
      console.warn = original;
      delete process.env.CODERIFTS_ADVISORY;
    }
  });
});
