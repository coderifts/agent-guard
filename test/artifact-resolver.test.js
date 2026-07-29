'use strict';

/**
 * artifactResolver acceptance — automatic base/head contract artifacts from a pure git snapshot
 * (artifact-resolver-matrix v1.0, 15 rows / 16 config variants). The matrix is VENDORED into this
 * test dir and loaded by a RELATIVE path (the ENOENT lesson — never read from ~/grok-coderifts at
 * test time). Ported assertions: coverage, artifact ids + empty sides, unresolved reasons/paths,
 * ignored_non_contract, ssot_selections, artifacts_ready_for_preflight, produces_verdict.
 *
 * Imports the compiled resolver submodule directly (not the index barrel) so the suite is robust to
 * the barrel's export set.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { resolve } = require('../dist/cjs/artifact-resolver.js');
const { matchGlob } = require('../dist/cjs/resolver-glob.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'artifact-resolver-matrix.json'), 'utf8'));
const ROWS = MATRIX.rows;

function input(row) {
  return { baseRef: row.input.baseRef, headRef: row.input.headRef, changedFiles: row.input.changedFiles, blobs: row.input.blobs || {} };
}
function variantsOf(row) {
  const out = [];
  if (row.expected) out.push({ label: 'expected', config: row.input.config || {}, exp: row.expected });
  if (row.expected_strict) out.push({ label: 'strict', config: row.input.config || {}, exp: row.expected_strict });
  if (row.expected_default_lenient) {
    const c = { ...(row.input.config || {}) };
    delete c.requireSsotIfConfigured;
    out.push({ label: 'lenient', config: c, exp: row.expected_default_lenient });
  }
  return out;
}

function checkVariant(row, v) {
  const r = resolve(input(row), v.config);
  const { exp } = v;
  const tag = `${row.id}/${v.label}`;

  assert.equal(r.coverage, exp.coverage, `${tag} coverage`);

  // artifact ids (sorted ASC) + declared empty sides
  const expArts = (exp.artifacts || []).filter((a) => a.id);
  if (expArts.length > 0) {
    assert.deepEqual(r.artifacts.map((a) => a.id), expArts.map((a) => a.id).slice().sort(), `${tag} artifact ids`);
    for (const ea of expArts) {
      const got = r.artifacts.find((a) => a.id === ea.id);
      assert.ok(got, `${tag} artifact ${ea.id} present`);
      if (ea.before === '') assert.equal(got.before, '', `${tag} ${ea.id} before empty (added)`);
      if (ea.after === '') assert.equal(got.after, '', `${tag} ${ea.id} after empty (deleted)`);
    }
  } else if (exp.artifacts) {
    assert.equal(r.artifacts.length, 0, `${tag} no artifacts`);
  }

  // unresolved reasons + paths
  if (exp.unresolved) {
    const got = r.unresolved.map((u) => `${u.reason}@${u.path}`).slice().sort();
    const want = exp.unresolved.map((u) => `${u.reason}@${u.path}`).slice().sort();
    assert.deepEqual(got, want, `${tag} unresolved`);
  }
  if (exp.ignored_non_contract) {
    assert.deepEqual(r.report.ignored_non_contract.slice().sort(), exp.ignored_non_contract.slice().sort(), `${tag} ignored_non_contract`);
  }
  if (exp.artifacts_ready_for_preflight !== undefined) {
    assert.equal(r.report.claim.artifacts_ready_for_preflight, exp.artifacts_ready_for_preflight, `${tag} ready`);
  }
  if (exp.ssot_selections) {
    for (const sel of exp.ssot_selections) {
      const got = r.report.ssot_selections.find((s) => s.chosen === sel.chosen);
      assert.ok(got, `${tag} ssot chose ${sel.chosen}`);
      assert.equal(got.reason, sel.reason, `${tag} ssot reason for ${sel.chosen}`);
      if (sel.deferred) assert.deepEqual(got.deferred.slice().sort(), sel.deferred.slice().sort(), `${tag} ssot deferred`);
    }
  }

  // invariant A7: never claims a verdict
  assert.equal(r.report.claim.produces_verdict, false, `${tag} produces_verdict false`);
  // A5: COMPLETE ⇒ unresolved empty
  if (r.coverage === 'COMPLETE') assert.equal(r.unresolved.length, 0, `${tag} COMPLETE ⇒ no unresolved`);
  return r;
}

// ── all 15 rows / 16 variants ─────────────────────────────────────────────────────────────────────
describe('artifactResolver — matrix acceptance', () => {
  assert.equal(ROWS.length, 15, 'all 15 rows present');
  for (const row of ROWS) {
    for (const v of variantsOf(row)) {
      it(`${row.id}/${v.label}: ${row.title.slice(0, 66)}`, () => { checkVariant(row, v); });
    }
  }
});

// ── named checklist (task PART 7) ─────────────────────────────────────────────────────────────────
describe('artifactResolver — named checklist', () => {
  const row = (id) => ROWS.find((r) => r.id === id);

  it('AR-002: multi-file $ref → ONE bundled root; component change visible; deps deferred not duplicated', () => {
    const r = resolve(input(row('AR-002')), row('AR-002').input.config);
    assert.equal(r.artifacts.length, 1, 'one artifact for the surface (not two)');
    const a = r.artifacts[0];
    assert.equal(a.id, 'openapi:spec/openapi.yaml');
    assert.notEqual(a.before, a.after, 'component-only change is visible in the assembled bundle');
    assert.match(a.before, /#\/components\//, 'external $ref rewritten to an internal component ref');
    assert.ok(a.before.includes('name') && !a.after.includes('name'), 'base Pet has name, head Pet dropped it');
    const sel = r.report.ssot_selections.find((s) => s.chosen === 'spec/openapi.yaml');
    assert.deepEqual(sel.deferred, ['spec/components.yaml'], 'component is a deferred dependency');
    assert.ok(!r.report.ignored_non_contract.includes('spec/components.yaml'), 'dependency is not "ignored noise"');
  });

  it('AR-006: missing $ref target → UNRESOLVED, NOT fabricated (no stub component, no artifact)', () => {
    const r = resolve(input(row('AR-006')), row('AR-006').input.config);
    assert.equal(r.coverage, 'UNRESOLVED');
    assert.equal(r.artifacts.length, 0, 'no artifact produced');
    assert.equal(r.unresolved[0].reason, 'missing_ref_target');
    assert.deepEqual(r.unresolved[0].related_paths, ['missing-components.yaml']);
  });

  it('AR-007: generated + source both changed → SSOT picks the source (generated_deprioritized)', () => {
    const r = resolve(input(row('AR-007')), row('AR-007').input.config);
    assert.deepEqual(r.artifacts.map((a) => a.id), ['openapi:openapi/openapi.yaml'], 'only the source artifact');
    const sel = r.report.ssot_selections[0];
    assert.equal(sel.chosen, 'openapi/openapi.yaml');
    assert.equal(sel.reason, 'generated_deprioritized');
    assert.deepEqual(sel.deferred, ['generated/openapi.json']);
  });

  it('AR-010: one good + one missing-$ref → PARTIAL (artifact for the good, unresolved for the bad)', () => {
    const r = resolve(input(row('AR-010')), row('AR-010').input.config);
    assert.equal(r.coverage, 'PARTIAL');
    assert.deepEqual(r.artifacts.map((a) => a.id), ['openapi:good/openapi.yaml']);
    assert.equal(r.unresolved[0].reason, 'missing_ref_target');
    assert.equal(r.report.claim.artifacts_ready_for_preflight, false, 'PARTIAL is not ready');
  });

  it('AR-012: external http $ref forbidden by default → UNRESOLVED (external_ref_forbidden)', () => {
    const r = resolve(input(row('AR-012')), row('AR-012').input.config);
    assert.equal(r.coverage, 'UNRESOLVED');
    assert.equal(r.artifacts.length, 0);
    assert.equal(r.unresolved[0].reason, 'external_ref_forbidden');
  });

  it('AR-013: multi-protocol (mcp + graphql) → two artifacts sorted by id; README ignored', () => {
    const r = resolve(input(row('AR-013')), {});
    assert.deepEqual(r.artifacts.map((a) => a.id), ['graphql:schema.graphql', 'mcp_manifest:mcp.json']);
    assert.deepEqual(r.report.ignored_non_contract, ['README.md']);
  });

  it('AR-014: ssotPrefer→missing — strict fails (config_ssot_missing), lenient falls back to generated', () => {
    const strict = resolve(input(row('AR-014')), row('AR-014').input.config);
    assert.equal(strict.coverage, 'UNRESOLVED');
    assert.equal(strict.unresolved[0].reason, 'config_ssot_missing');
    assert.equal(strict.artifacts.length, 0);
    const lenientCfg = { ...row('AR-014').input.config };
    delete lenientCfg.requireSsotIfConfigured;
    const lenient = resolve(input(row('AR-014')), lenientCfg);
    assert.equal(lenient.coverage, 'COMPLETE');
    assert.deepEqual(lenient.artifacts.map((a) => a.id), ['openapi:generated/openapi.yaml']);
  });
});

// ── determinism (§0.3 / A6) + anti-fabrication (A1/A2) ──────────────────────────────────────────────
describe('artifactResolver — determinism + anti-fabrication', () => {
  const row = (id) => ROWS.find((r) => r.id === id);

  it('same snapshot + config → byte-identical result (assembled bundle included)', () => {
    for (const id of ['AR-002', 'AR-008b', 'AR-013']) {
      const a = JSON.stringify(resolve(input(row(id)), row(id).input.config || {}));
      const b = JSON.stringify(resolve(input(row(id)), row(id).input.config || {}));
      assert.equal(a, b, `${id} deterministic`);
    }
  });

  it('A1/A2: a missing $ref NEVER yields a stub artifact; assembled bytes come only from real blobs', () => {
    const r = resolve(input(row('AR-006')), row('AR-006').input.config);
    assert.equal(r.artifacts.length, 0, 'no fabricated artifact for a missing target');
    // AR-002 assembled content is composed only of blob content (the real Pet fields, no invented keys)
    const ok = resolve(input(row('AR-002')), row('AR-002').input.config).artifacts[0];
    assert.ok(ok.before.includes('integer') && ok.before.includes('string'), 'assembled before = real base component fields');
    assert.ok(ok.after.includes('integer') && !ok.after.includes('string'), 'assembled after = real head component fields (name removed)');
  });

  it('produces_verdict is false on every row (the resolver never decides)', () => {
    for (const r of ROWS) {
      assert.equal(resolve(input(r), r.input.config || {}).report.claim.produces_verdict, false, `${r.id}`);
    }
  });
});

// ── glob matcher: correct double-star spanning (the SSOT core) ──────────────────────────────────────
describe('artifactResolver — glob ** matching', () => {
  it('double-star spans zero-or-more path segments', () => {
    assert.equal(matchGlob('**/generated/**', 'generated/openapi.json'), true, 'leading segment optional');
    assert.equal(matchGlob('**/generated/**', 'a/b/generated/c/d.yaml'), true, 'deeply nested');
    assert.equal(matchGlob('**/generated/**', 'src/openapi.yaml'), false, 'no generated segment → no match');
    assert.equal(matchGlob('generated/**', 'generated/x.json'), true);
    assert.equal(matchGlob('*.graphql', 'schema.graphql'), true);
    assert.equal(matchGlob('*.graphql', 'a/schema.graphql'), false, 'single-star does not cross /');
  });
});
