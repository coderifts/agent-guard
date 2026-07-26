'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { builtinDetector, DETECTOR_VERSION } = require('../dist/cjs/index.js');
const corpus = require('./trigger-vectors.json');

test('corpus shape: 68 vectors, 46 trigger, 22 no-trigger', () => {
  assert.equal(corpus.length, 68);
  assert.equal(corpus.filter((v) => v.expected.trigger === true).length, 46);
  assert.equal(corpus.filter((v) => v.expected.trigger === false).length, 22);
});

test('builtinDetector passes ALL 68 Grok corpus vectors (mandatory fixture)', () => {
  const fails = [];
  for (let i = 0; i < corpus.length; i++) {
    const v = corpus[i];
    const r = builtinDetector.detect(v.input);
    if (r.trigger !== v.expected.trigger) fails.push(`#${i} ${v.expected.keySignal}: expected ${v.expected.trigger}, got ${r.trigger}`);
  }
  assert.deepEqual(fails, [], `detector must pass all 68 vectors:\n${fails.join('\n')}`);
});

test('detector output shape + version on every vector', () => {
  for (const v of corpus) {
    const r = builtinDetector.detect(v.input);
    assert.equal(typeof r.trigger, 'boolean');
    assert.equal(typeof r.confident, 'boolean');
    assert.ok(Array.isArray(r.artifacts));
    assert.ok(Array.isArray(r.signals));
  }
  assert.equal(builtinDetector.version, DETECTOR_VERSION);
});

test('fail-safe: an explicit-artifacts call always triggers with confidence', () => {
  const r = builtinDetector.detect({ toolName: 'Edit', arguments: {}, artifacts: [{ id: 'a', type: 'openapi', before: 'x', after: 'y' }] });
  assert.equal(r.trigger, true);
  assert.equal(r.confident, true);
  assert.equal(r.artifacts.length, 1);
});

test('read-only tool is never a contract call', () => {
  const r = builtinDetector.detect({ toolName: 'Read', arguments: { path: 'openapi.yaml' } });
  assert.equal(r.trigger, false);
  assert.equal(r.confident, true);
});
