'use strict';

/**
 * DG-1 detector hardening — deep-argument-scan corpus (52 vectors: 36 evasions + 16 precision-guard
 * FPs) + the 120-vector acceptance matrix (68 original + 52 DG-1). Independent ground truth; the
 * scan is additive + monotonic toward caution — it must close the 36 evasions WITHOUT flipping any
 * of the 16 FPs or the 22 original no-trigger vectors.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { builtinDetector, DETECTOR_VERSION } = require('../dist/cjs/index.js');
const dg1 = require('./dg1-vectors.json');
const orig = require('./trigger-vectors.json');

test('DG-1 corpus shape: 52 vectors, 36 trigger / 16 no-trigger, well-formed', () => {
  assert.equal(dg1.length, 52);
  assert.equal(dg1.filter((v) => v.expected.trigger === true).length, 36);
  assert.equal(dg1.filter((v) => v.expected.trigger === false).length, 16);
  for (const v of dg1) {
    assert.ok(v.description && v.input && v.input.toolName, 'shape: description + input.toolName');
    assert.equal(typeof v.expected.trigger, 'boolean');
    assert.ok(v.expected.keySignal, 'each vector carries a keySignal');
  }
});

test('DETECTOR_VERSION bumped to builtin/1.1.0 (behavior changed)', () => {
  assert.equal(DETECTOR_VERSION, 'builtin/1.1.0');
});

test('all 36 DG-1 evasions now trigger:true (the hole is closed)', () => {
  const missed = [];
  for (const v of dg1.filter((x) => x.expected.trigger === true)) {
    const r = builtinDetector.detect(v.input);
    if (r.trigger !== true) missed.push(v.expected.keySignal);
  }
  assert.deepEqual(missed, [], `evasions that still skip:\n${missed.join('\n')}`);
});

test('all 16 DG-1 precision-guard FPs still trigger:false (via their named suppressor)', () => {
  const flipped = [];
  for (const v of dg1.filter((x) => x.expected.trigger === false)) {
    const r = builtinDetector.detect(v.input);
    if (r.trigger !== false) flipped.push(`${v.expected.keySignal} (signals: ${r.signals.join(',')})`);
  }
  assert.deepEqual(flipped, [], `FPs the scan over-reached on:\n${flipped.join('\n')}`);
});

test('REGRESSION GATE: all 68 original vectors unchanged (46 trigger, 22 no-trigger)', () => {
  const changed = [];
  for (let i = 0; i < orig.length; i++) {
    const r = builtinDetector.detect(orig[i].input);
    if (r.trigger !== orig[i].expected.trigger) changed.push(`#${i} ${orig[i].expected.keySignal}: expected ${orig[i].expected.trigger}, got ${r.trigger}`);
  }
  assert.deepEqual(changed, [], `original-vector regressions:\n${changed.join('\n')}`);
  assert.equal(orig.length, 68);
});

test('deep scan is MONOTONIC toward caution: never removes a trigger, only lowers confidence', () => {
  // The read-only short-circuit precedes the deep scan: a read-only tool with a contract payload stays SKIP.
  const ro = builtinDetector.detect({ toolName: 'Read', arguments: { path: 'x', spec: 'openapi: 3.0.3\npaths:\n  /x:\n    get: {}' } });
  assert.equal(ro.trigger, false);
  assert.equal(ro.confident, true);
  // A deep-found contract triggers with confident:false (heuristic), never confident:true.
  const deep = builtinDetector.detect({ toolName: 'Write', arguments: { body: 'openapi: 3.0.3\npaths:\n  /x:\n    get: {}' } });
  assert.equal(deep.trigger, true);
  assert.equal(deep.confident, false);
});
