'use strict';

/**
 * The seven fingerprint-parity cases, extracted so the TEST and the snapshot GENERATOR read one
 * list. Two copies of a golden-vector input set is how a recording starts describing inputs the
 * test no longer runs.
 */

const OPENAPI_BEFORE = JSON.stringify({
  openapi: '3.0.0', info: { title: 't', version: '1.0.0' },
  paths: { '/u': { get: { responses: { 200: { description: 'ok' } } } } },
});
const OPENAPI_AFTER = JSON.stringify({
  openapi: '3.0.0', info: { title: 't', version: '1.0.0' }, paths: {},
});

/** Cases chosen so every element of the preimage is exercised at least once. */
const CASES = Object.freeze([
  { name: 'operation only (the live authorize shape)',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: { operation: 'merge' } },
  { name: 'no context at all',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: undefined },
  { name: 'empty context object',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: {} },
  { name: 'every context field populated',
    artifacts: [{ id: 'openapi.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER }],
    context: {
      operation: 'merge', environment: 'production', repository: 'acme/api',
      branch: 'main', pull_request: 42, policy_profile: 'strict',
    } },
  { name: 'multiple artifacts, submitted out of order',
    artifacts: [
      { id: 'b.yaml', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER },
      { id: 'a.yaml', type: 'openapi', before: OPENAPI_AFTER, after: OPENAPI_BEFORE },
    ],
    context: { operation: 'deploy' } },
  { name: 'mixed artifact types',
    artifacts: [
      { id: 'x', type: 'graphql', before: 'type Q { a: Int }', after: 'type Q { }' },
      { id: 'x', type: 'openapi', before: OPENAPI_BEFORE, after: OPENAPI_AFTER },
    ],
    context: { operation: 'merge', repository: 'acme/api' } },
  { name: 'null and empty artifact sides',
    artifacts: [{ id: 'n', type: 'openapi', before: null, after: '' }],
    context: { operation: 'merge' } },
]);

module.exports = { CASES, OPENAPI_BEFORE, OPENAPI_AFTER };
