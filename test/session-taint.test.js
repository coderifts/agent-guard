'use strict';

/**
 * Session-taint detector acceptance — replays the 32 validated detector-trace fixtures.
 * Normative algorithm: flag ⇔ ssot_sink_events ≠ ∅ ∧ tainted. This is a SEPARATE surface; the frozen
 * single-call detect() is untouched (asserted below). Independent ground truth — we reproduce
 * session_state_after + flag_at_this_step + trip_step, we do not re-label.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  SessionTaintTracker, SESSION_TAINT_VERSION, DETECTOR_VERSION,
  updateSession, evaluate, emptySessionState, projectState,
} = require('../dist/cjs/index.js');
const fx = require('./session-taint-fixtures.json');
const fixtures = Array.isArray(fx) ? fx : (fx.fixtures || fx.traces || []);

test('PART 0 — corpus: 32 fixtures, 20 should_flag / 12 not', () => {
  assert.equal(fixtures.length, 32);
  assert.equal(fixtures.filter((f) => f.should_flag === true).length, 20);
  assert.equal(fixtures.filter((f) => f.should_flag === false).length, 12);
});

test('ACCEPTANCE: replay all 32 traces — flag_at_this_step, full state projection, trip_step', () => {
  const flagMiss = []; const stateMiss = []; const tripMiss = [];
  for (const f of fixtures) {
    const tracker = new SessionTaintTracker();
    let firstFlagStep = -1;
    f.trace.forEach((step, i) => {
      const obs = tracker.observe(step.call);
      const sn = step.step != null ? step.step : i + 1;
      if (obs.flag !== step.flag_at_this_step) flagMiss.push(`${f.vector_id} step ${sn}: flag expected ${step.flag_at_this_step}, got ${obs.flag}`);
      if (obs.flag && firstFlagStep < 0) firstFlagStep = sn;
      // Full projected-state equality (SPEC §7.1 — includes tainted + the two observability bits,
      // which stay under-set via the fixture-faithful NON_SINK order, so they still match exactly).
      try { assert.deepEqual(obs.state, step.session_state_after); }
      catch (_) { stateMiss.push(`${f.vector_id} step ${sn}: state projection mismatch`); }
    });
    const expectedTrip = f.should_flag ? f.trip_step : -1;
    if (firstFlagStep !== expectedTrip) tripMiss.push(`${f.vector_id}: trip_step expected ${f.should_flag ? f.trip_step : 'none'}, got ${firstFlagStep < 0 ? 'none' : firstFlagStep}`);
  }
  assert.deepEqual(flagMiss, [], `flag mismatches:\n${flagMiss.join('\n')}`);
  assert.deepEqual(stateMiss, [], `state mismatches:\n${stateMiss.join('\n')}`);
  assert.deepEqual(tripMiss, [], `trip_step mismatches:\n${tripMiss.join('\n')}`);
});

test('predicate isolation (SPEC §7.2): empty / taint-only / sink-only / both / overflow', () => {
  // empty -> false
  assert.equal(evaluate(emptySessionState()).flag, false);
  // taint only (no sink) -> false
  const taintOnly = updateSession(emptySessionState(), { toolName: 'Write', arguments: { path: 'build/frags/x.b64', contents: 'YWJjZGVmZ2g=' } });
  assert.equal(taintOnly.tainted, true);
  assert.equal(evaluate(taintOnly).flag, false);
  // sink only (no taint) -> false
  const sinkOnly = updateSession(emptySessionState(), { toolName: 'Bash', arguments: { command: 'node scripts/promote-spec.js' } });
  assert.equal(sinkOnly.ssot_sink_events.length > 0, true);
  assert.equal(sinkOnly.tainted, false);
  assert.equal(evaluate(sinkOnly).flag, false);
  // both -> true
  const both = updateSession(taintOnly, { toolName: 'Bash', arguments: { command: 'node scripts/promote-spec.js' } });
  assert.equal(evaluate(both).flag, true);
  // overflow forces taint: a sink with no taint but overflow=true -> flag true
  assert.equal(evaluate(sinkOnly, false, { overflow: true }).flag, true);
});

test('reverse-edge (ST-031) stays silent: snapshot never adds an ssot_sink_event', () => {
  const st031 = fixtures.find((f) => f.vector_id === 'ST-031');
  assert.ok(st031 && st031.should_flag === false, 'ST-031 is a no-flag reverse-edge fixture');
  const tracker = new SessionTaintTracker();
  for (const step of st031.trace) assert.equal(tracker.observe(step.call).flag, false);
});

test('FROZEN: SESSION_TAINT_VERSION separate; builtin detector version unchanged', () => {
  assert.equal(SESSION_TAINT_VERSION, 'session-taint/1.0.0');
  assert.equal(DETECTOR_VERSION, 'builtin/1.1.0'); // DG-1 version, NOT bumped by session-taint
  assert.notEqual(SESSION_TAINT_VERSION, DETECTOR_VERSION);
});
