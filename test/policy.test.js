'use strict';

/**
 * Layer 1 + 2 + 3 helpers: withPolicy inject, CODERIFTS_POLICY constant, tri-state presence.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  CODERIFTS_POLICY,
  POLICY_MARKER,
  POLICY_ABSENT_WARN,
  withPolicy,
  policyPresenceOf,
  detectPolicyPresence,
  observePolicyPresence,
  resetPolicyWarnForTests,
} = require('../dist/cjs/index.js');

describe('README shows the one-import interpolation', () => {
  it('documents withPolicy + CODERIFTS_POLICY interpolation and the honest line', () => {
    const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
    assert.match(readme, /\$\{yourPrompt\}\\n\\n\$\{CODERIFTS_POLICY\}/);
    assert.match(readme, /withPolicy/);
    assert.match(readme, /proves the \*\*text is present\*\*/i);
    assert.match(readme, /result-shapers/i);
  });
});

describe('CODERIFTS_POLICY / POLICY_MARKER', () => {
  it('constant contains the ONE-operation marker', () => {
    assert.equal(typeof CODERIFTS_POLICY, 'string');
    assert.ok(CODERIFTS_POLICY.includes(POLICY_MARKER));
    assert.equal(
      POLICY_MARKER,
      'A receipt authorizes ONE operation: a merge receipt does not authorize a deploy.',
    );
  });
});

describe('withPolicy — string', () => {
  it('appends the policy to a host prompt', () => {
    const out = withPolicy('You are a coding agent.');
    assert.ok(out.startsWith('You are a coding agent.'));
    assert.ok(out.includes(POLICY_MARKER));
    assert.ok(out.includes(CODERIFTS_POLICY));
  });

  it('is idempotent — second call does not append twice', () => {
    const once = withPolicy('You are a coding agent.');
    const twice = withPolicy(once);
    assert.equal(twice, once);
    assert.equal(twice.split(POLICY_MARKER).length, 2);
  });

  it('injectPolicy:false returns the original string', () => {
    const src = 'You are a coding agent.';
    assert.equal(withPolicy(src, { injectPolicy: false }), src);
    assert.equal(src.includes(POLICY_MARKER), false);
  });

  it('empty string becomes the policy body', () => {
    assert.equal(withPolicy(''), CODERIFTS_POLICY);
    assert.equal(withPolicy('   '), CODERIFTS_POLICY);
  });
});

describe('withPolicy — messages (no in-place mutation)', () => {
  it('prepends a system message when none exists', () => {
    const original = [{ role: 'user', content: 'hi' }];
    const frozen = original.slice();
    const out = withPolicy(original);
    assert.equal(out[0].role, 'system');
    assert.equal(out[0].content, CODERIFTS_POLICY);
    assert.equal(out[1].content, 'hi');
    assert.deepEqual(original, frozen, 'caller array not mutated');
    assert.equal(original[0].role, 'user');
  });

  it('appends into an existing string system message', () => {
    const original = [
      { role: 'system', content: 'You are helpful.', extra: 1 },
      { role: 'user', content: 'hi' },
    ];
    const out = withPolicy(original);
    assert.ok(out[0].content.startsWith('You are helpful.'));
    assert.ok(out[0].content.includes(POLICY_MARKER));
    assert.equal(out[0].extra, 1, 'extra fields preserved');
    assert.equal(original[0].content, 'You are helpful.', 'caller object not mutated');
  });

  it('is idempotent on messages', () => {
    const once = withPolicy([{ role: 'system', content: 'hi' }]);
    const twice = withPolicy(once);
    assert.equal(twice[0].content, once[0].content);
    assert.equal(String(twice[0].content).split(POLICY_MARKER).length, 2);
  });

  it('injectPolicy:false returns a copy without appending', () => {
    const original = [{ role: 'user', content: 'hi' }];
    const out = withPolicy(original, { injectPolicy: false });
    assert.equal(out.length, 1);
    assert.equal(out[0].content, 'hi');
    assert.notEqual(out, original);
    assert.equal(original.length, 1);
  });
});

describe('policyPresenceOf / detectPolicyPresence', () => {
  it('unknown when nothing supplied', () => {
    assert.equal(policyPresenceOf(undefined), 'unknown');
    assert.equal(policyPresenceOf(null), 'unknown');
    assert.equal(detectPolicyPresence(undefined), 'unknown');
  });

  it('detected when the marker is present', () => {
    assert.equal(policyPresenceOf(CODERIFTS_POLICY), 'detected');
    assert.equal(policyPresenceOf(`prefix\n${POLICY_MARKER}\nsuffix`), 'detected');
  });

  it('absent when text is supplied without the marker', () => {
    assert.equal(policyPresenceOf('just tools, no policy'), 'absent');
    assert.equal(policyPresenceOf(''), 'absent');
  });
});

describe('observePolicyPresence once-per-process warn', () => {
  beforeEach(() => resetPolicyWarnForTests());

  it('unknown does not warn', () => {
    const hits = [];
    const orig = console.warn;
    console.warn = (m) => { hits.push(String(m)); };
    try {
      assert.equal(observePolicyPresence(undefined), 'unknown');
      assert.equal(observePolicyPresence(null), 'unknown');
    } finally {
      console.warn = orig;
    }
    assert.equal(hits.length, 0);
  });

  it('detected is silent', () => {
    const hits = [];
    const orig = console.warn;
    console.warn = (m) => { hits.push(String(m)); };
    try {
      assert.equal(observePolicyPresence(CODERIFTS_POLICY), 'detected');
    } finally {
      console.warn = orig;
    }
    assert.equal(hits.length, 0);
  });

  it('absent warns once; second absent is silent', () => {
    const hits = [];
    const orig = console.warn;
    console.warn = (m) => { hits.push(String(m)); };
    try {
      assert.equal(observePolicyPresence('no marker here'), 'absent');
      assert.equal(observePolicyPresence('still no marker'), 'absent');
    } finally {
      console.warn = orig;
    }
    assert.deepEqual(hits, [POLICY_ABSENT_WARN]);
  });
});
