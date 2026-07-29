'use strict';

/**
 * guardToolRegistry acceptance — the agent-runtime inescapability layer (guard-tool-registry-matrix
 * v1.0, 16 fixtures). Every BR/GTR row is ported from the VENDORED matrix (loaded via a RELATIVE
 * path — the ENOENT lesson: the fixture lives in the repo, never read from ~/grok-coderifts at test
 * time). Asserts startup ok/fail + fail_code, coverage verdict, guarded_mutators, readonly_passthrough,
 * inescapable_runtime, inescapable_merge, per-tool class + binder operation.
 *
 * Two runtime objects the JSON matrix cannot serialize are injected here (the SPEC requires them, the
 * fixtures abstract them away): every raw tool gets a stub `execute` unless the fixture explicitly
 * sets it (GTR-014 sets execute:null → INVALID_TOOL); and a valid stub GuardConfig.client is provided
 * unless the fixture explicitly sets `guard` (GTR-015 sets guard:{} → GUARD_CONFIG_INVALID).
 *
 * PLUS the security core: a non-leakage test proving raw.execute is unreachable from a ProtectedTool.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { guardToolRegistry, RegistryConstructionError } = require('../dist/cjs/index.js');

const MATRIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'guard-tool-registry-matrix.json'), 'utf8'));
const ROWS = MATRIX.rows;

const STUB_CLIENT = { preflight: async () => ({}) };            // stand-in CodeRifts client
const STUB_EXECUTE = async () => 'raw-result';

/** Materialize a fixture's rawTools: inject a stub execute unless the fixture set one explicitly. */
function materializeTools(rawTools) {
  return (rawTools || []).map((t) => {
    const out = { ...t };
    if (!('execute' in out)) out.execute = STUB_EXECUTE;         // JSON can't carry functions
    return out;
  });
}

/** Materialize a fixture's config: inject a valid guard client unless the fixture set `guard`. */
function materializeConfig(config) {
  const cfg = { ...(config || {}) };
  if (!('guard' in cfg)) cfg.guard = { client: STUB_CLIENT };
  return cfg;
}

function run(row) {
  return guardToolRegistry(materializeTools(row.input.rawTools), materializeConfig(row.input.config));
}

// ── all 16 fixtures ─────────────────────────────────────────────────────────────────────────────
describe('guardToolRegistry — 16-fixture acceptance matrix', () => {
  assert.equal(ROWS.length, 16, 'all 16 fixtures present');

  for (const row of ROWS) {
    it(`${row.id}: ${row.title}`, () => {
      const exp = row.expected;

      if (exp.startup === 'fail') {
        let err = null;
        try { run(row); } catch (e) { err = e; }
        assert.ok(err instanceof RegistryConstructionError, `${row.id} threw RegistryConstructionError`);
        assert.equal(err.code, exp.fail_code, `${row.id} fail_code`);
        return;
      }

      // startup ok
      const result = run(row);
      assert.ok(result && Array.isArray(result.tools), `${row.id} returns tools`);

      if (exp.protected_names !== undefined) {
        assert.deepEqual(result.report.protected_tools, exp.protected_names, `${row.id} protected_names (sorted ASC)`);
      }
      if (exp.guarded_mutators !== undefined) {
        assert.deepEqual(result.report.guarded_mutators.slice().sort(), exp.guarded_mutators.slice().sort(), `${row.id} guarded_mutators`);
      }
      if (exp.readonly_passthrough !== undefined) {
        assert.deepEqual(result.report.readonly_passthrough.slice().sort(), exp.readonly_passthrough.slice().sort(), `${row.id} readonly_passthrough`);
      }
      if (exp.unguarded_mutators !== undefined) {
        assert.deepEqual(result.report.unguarded_mutators, exp.unguarded_mutators, `${row.id} unguarded_mutators`);
      }
      if (exp.coverage !== undefined && exp.coverage !== null) {
        assert.equal(result.coverage, exp.coverage, `${row.id} coverage`);
        assert.equal(result.report.coverage, exp.coverage, `${row.id} report.coverage`);
      }
      if (exp.inescapable_runtime !== undefined) {
        assert.equal(result.report.claim.inescapable_runtime, exp.inescapable_runtime, `${row.id} inescapable_runtime`);
      }
      // inescapable_merge is ALWAYS false (normative); assert it on every ok row
      assert.equal(result.report.claim.inescapable_merge, false, `${row.id} inescapable_merge always false`);
      if (exp.inescapable_deploy !== undefined) {
        assert.equal(result.report.claim.inescapable_deploy, exp.inescapable_deploy, `${row.id} inescapable_deploy`);
      }
      // deploy claim is always false here regardless
      assert.equal(result.report.claim.inescapable_deploy, false, `${row.id} inescapable_deploy always false`);

      // per-tool class assertions
      if (exp.mutationClass) {
        for (const [name, cls] of Object.entries(exp.mutationClass)) {
          const t = result.tools.find((x) => x.name === name);
          assert.ok(t, `${row.id} tool ${name} present`);
          assert.equal(t._coderifts.mutationClass, cls, `${row.id} ${name} mutationClass`);
        }
      }
      if (exp.each_tool) {
        for (const [name, want] of Object.entries(exp.each_tool)) {
          const t = result.tools.find((x) => x.name === name);
          assert.ok(t, `${row.id} tool ${name} present`);
          assert.equal(t._coderifts.guarded, want.guarded, `${row.id} ${name} guarded`);
          assert.equal(t._coderifts.mutationClass, want.mutationClass, `${row.id} ${name} class`);
        }
      }
      // §4 operation binding
      if (exp.binder_operation) {
        for (const [name, op] of Object.entries(exp.binder_operation)) {
          const t = result.tools.find((x) => x.name === name);
          assert.ok(t, `${row.id} tool ${name} present`);
          assert.equal(t._coderifts.operation, op, `${row.id} ${name} bound operation`);
        }
      }
      if (exp.warnings_include) {
        for (const w of exp.warnings_include) {
          assert.ok(result.report.warnings.includes(w), `${row.id} warnings include ${w}`);
        }
      }
    });
  }
});

// ── named checklist (task PART 6) ─────────────────────────────────────────────────────────────────
describe('guardToolRegistry — named checklist', () => {
  const row = (id) => ROWS.find((r) => r.id === id);

  it('GTR-001 empty set → COMPLETE, inescapable_runtime true, guarded/readonly empty', () => {
    const r = run(row('GTR-001'));
    assert.equal(r.coverage, 'COMPLETE');
    assert.equal(r.report.claim.inescapable_runtime, true);
    assert.deepEqual(r.report.guarded_mutators, []);
    assert.deepEqual(r.report.readonly_passthrough, []);
  });

  it('GTR-002 readonly-only → COMPLETE, guarded_mutators empty, names sorted ASC', () => {
    const r = run(row('GTR-002'));
    assert.equal(r.coverage, 'COMPLETE');
    assert.deepEqual(r.report.guarded_mutators, []);
    assert.deepEqual(r.report.protected_tools, ['Glob', 'Grep', 'Read']);
  });

  it('GTR-005 unknown name → treated as guarded mutator (fail-closed default)', () => {
    const r = run(row('GTR-005'));
    assert.equal(r.report.unknown_treated_as, 'mutating');
    assert.deepEqual(r.report.guarded_mutators, ['weird_custom_tool_xyz']);
    assert.equal(r.tools[0]._coderifts.mutationClass, 'mutating');
    assert.equal(r.tools[0]._coderifts.guarded, true);
    assert.equal(r.coverage, 'COMPLETE');
  });

  it('GTR-006 unknown + reject → UNKNOWN_TOOL', () => {
    assert.throws(() => run(row('GTR-006')), (e) => e instanceof RegistryConstructionError && e.code === 'UNKNOWN_TOOL');
  });

  it('GTR-009 forceReadonly on mutator + default failHard → FORCE_READONLY_MUTATOR', () => {
    assert.throws(() => run(row('GTR-009')), (e) => e instanceof RegistryConstructionError && e.code === 'FORCE_READONLY_MUTATOR');
  });

  it('GTR-010 forceReadonly + failHard=false → BYPASSED (never COMPLETE), inescapable_runtime false', () => {
    const r = run(row('GTR-010'));
    assert.equal(r.coverage, 'BYPASSED');
    assert.equal(r.report.claim.inescapable_runtime, false);
    assert.ok(r.report.warnings.includes('force_readonly_on_mutator_heuristic:Write'));
    const write = r.tools.find((t) => t.name === 'Write');
    assert.equal(write._coderifts.guarded, false);
    assert.equal(write._coderifts.mutationClass, 'readonly');
  });

  it('GTR-011 classify shell→readonly + failHard=false → BYPASSED; default failHard would throw', () => {
    const r = run(row('GTR-011'));
    assert.equal(r.coverage, 'BYPASSED');
    assert.equal(r.report.claim.inescapable_runtime, false);
    // the expected_if_failHard_default variant: default failHard ⇒ FORCE_READONLY_MUTATOR
    assert.throws(
      () => guardToolRegistry(materializeTools(row('GTR-011').input.rawTools), { classify: { Bash: 'readonly' }, guard: { client: STUB_CLIENT } }),
      (e) => e instanceof RegistryConstructionError && e.code === 'FORCE_READONLY_MUTATOR',
    );
  });

  it('GTR-012 deploy-class → operation=deploy bound, COMPLETE, but inescapable_deploy false', () => {
    const r = run(row('GTR-012'));
    const deploy = r.tools.find((t) => t.name === 'deploy_prod');
    assert.equal(deploy._coderifts.mutationClass, 'mutating_deploy');
    assert.equal(deploy._coderifts.operation, 'deploy');       // §106 T7: deploy operation, not merge
    assert.equal(r.coverage, 'COMPLETE');
    assert.equal(r.report.claim.inescapable_runtime, true);
    assert.equal(r.report.claim.inescapable_deploy, false);
  });

  it('GTR-016 WriteSearch → mutating wins over the readonly substring', () => {
    const r = run(row('GTR-016'));
    assert.equal(r.tools[0]._coderifts.mutationClass, 'mutating');
    assert.deepEqual(r.report.guarded_mutators, ['WriteSearch']);
    assert.equal(r.coverage, 'COMPLETE');
  });
});

// ── non-leakage (PART 2 security core) ────────────────────────────────────────────────────────────
describe('guardToolRegistry — non-leakage: raw.execute unreachable from a ProtectedTool', () => {
  it('the wrapped mutator does NOT expose raw.execute, is frozen, and cannot be re-pointed to raw', () => {
    const rawExecute = async () => 'RAW_SIDE_EFFECT';
    const raw = [{ name: 'Write', mutationClass: 'mutating', execute: rawExecute }];
    const result = guardToolRegistry(raw, { guard: { client: STUB_CLIENT } });
    const tool = result.tools[0];

    // 1. exposed execute is a NEW closure, not the raw function
    assert.notEqual(tool.execute, rawExecute, 'exposed execute is not === raw.execute');
    // 2. no own property of the protected tool holds the raw executor
    for (const key of Reflect.ownKeys(tool)) {
      assert.notEqual(tool[key], rawExecute, `property ${String(key)} must not be the raw executor`);
    }
    assert.equal(tool.raw, undefined, 'no `raw` property');
    assert.equal(tool.rawTool, undefined, 'no `rawTool` property');
    // 3. deep scan of _coderifts too
    for (const v of Object.values(tool._coderifts)) assert.notEqual(v, rawExecute);

    // 4. frozen array + frozen tool + non-configurable execute
    assert.ok(Object.isFrozen(result.tools), 'tools array frozen');
    assert.ok(Object.isFrozen(tool), 'ProtectedTool frozen');
    const desc = Object.getOwnPropertyDescriptor(tool, 'execute');
    assert.equal(desc.configurable, false, 'execute non-configurable');
    assert.equal(desc.writable, false, 'execute non-writable');

    // 5. a host cannot reassign tool.execute = raw (frozen → throws in strict mode)
    assert.throws(() => { tool.execute = rawExecute; }, TypeError);
    assert.notEqual(tool.execute, rawExecute, 'still not the raw executor after attempted reassign');
  });

  it('RegistryResult exposes only tools/coverage/report — never rawTools or a raw-executor map', () => {
    const raw = [{ name: 'Read', mutationClass: 'readonly', execute: async () => 'r' }];
    const result = guardToolRegistry(raw, { guard: { client: STUB_CLIENT } });
    assert.deepEqual(Object.keys(result).sort(), ['coverage', 'report', 'tools']);
    // readonly passthrough is also a fresh closure (not the raw function)
    const t = result.tools[0];
    assert.equal(typeof t.execute, 'function');
    for (const key of Reflect.ownKeys(t)) assert.notEqual(t[key], raw[0].execute, `${String(key)} not raw`);
  });
});

// ── determinism (§7 D1) ───────────────────────────────────────────────────────────────────────────
describe('guardToolRegistry — determinism', () => {
  it('same tools + config → same coverage, guarded set, protected order', () => {
    const mk = () => guardToolRegistry(
      [{ name: 'Write', mutationClass: 'mutating', execute: async () => 1 },
        { name: 'Read', mutationClass: 'readonly', execute: async () => 2 },
        { name: 'Bash', execute: async () => 3 }],
      { guard: { client: STUB_CLIENT } },
    );
    const a = mk();
    const b = mk();
    assert.equal(a.coverage, b.coverage);
    assert.deepEqual(a.report.protected_tools, b.report.protected_tools);
    assert.deepEqual(a.report.guarded_mutators, b.report.guarded_mutators);
  });
});
