'use strict';

/**
 * 1577/1587 — a committed outcome says whether post-commit detection actually compared anything.
 *
 * `detect_stale_during_commit` can be true and still do nothing. cas-adapters/api.ts documents it:
 * when the host returns no new_etag on success there is no intended post-state, so
 * expected_after_commit falls back to a live re-read and tokensEqual is tautologically true. That
 * lived in a comment; the outcome said `committed` either way, so a caller could not tell a
 * detection that ran from one that was a no-op.
 *
 * The field is ABSENT when detection was not requested — cas-fs.test.js pins that the no-detect
 * path keeps a byte-identical committed shape, and that guarantee is older than this field.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { executeIfUnchanged } = require('../dist/cjs/conditional-write.js');

const base = { expected_token: 'tok-a', current_token: async () => 'tok-a' };

test('detection is ABSENT when it was not requested', async () => {
  const out = await executeIfUnchanged({ ...base, write: async () => 'payload' });
  assert.equal(out.status, 'committed');
  assert.equal(Object.prototype.hasOwnProperty.call(out, 'detection'), false,
    'the no-detect path must keep the shape it had before this field existed');
});

test("detection is 'ran' when an intended post-state was compared", async () => {
  const out = await executeIfUnchanged({
    ...base,
    write: async () => 'payload',
    detect_stale_during_commit: true,
    expected_after_commit: async () => 'tok-a',
    intended_post_state_known: () => true,
  });
  assert.equal(out.status, 'committed');
  assert.equal(out.detection, 'ran');
});

test("detection is 'no_op_no_intended_token' when the host gave no intended post-state", async () => {
  // THE CASE THE FIELD EXISTS FOR. expected_after_commit returns the live re-read, so the
  // comparison passes tautologically and the status is still committed — indistinguishable from
  // the test above without this field.
  const out = await executeIfUnchanged({
    ...base,
    write: async () => 'payload',
    detect_stale_during_commit: true,
    expected_after_commit: async () => 'tok-a',
    intended_post_state_known: () => false,
  });
  assert.equal(out.status, 'committed', 'verdict-neutral: the status must not move');
  assert.equal(out.detection, 'no_op_no_intended_token');
});

test('the field changes no verdict — same inputs, same status either way', async () => {
  // The bite against a future edit that lets `detection` feed the comparison.
  const mk = (known) => executeIfUnchanged({
    ...base,
    write: async () => 'payload',
    detect_stale_during_commit: true,
    expected_after_commit: async () => 'tok-a',
    intended_post_state_known: () => known,
  });
  const a = await mk(true);
  const b = await mk(false);
  assert.equal(a.status, b.status);
  assert.equal(a.version_token, b.version_token);
  assert.notEqual(a.detection, b.detection, 'the only difference must be the reported state');
});

test('a real post-state mismatch still detects, and reports that it ran', async () => {
  // Detection still works: reporting is added beside the verdict, not instead of it.
  const out = await executeIfUnchanged({
    ...base,
    write: async () => 'payload',
    detect_stale_during_commit: true,
    expected_after_commit: async () => 'tok-DIFFERENT',
    intended_post_state_known: () => true,
  });
  assert.equal(out.status, 'committed_stale_detected');
  assert.equal(out.reason, 'stale_during_commit');
});
