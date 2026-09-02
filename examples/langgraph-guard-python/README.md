# CodeRifts LangGraph Guard

A minimal [LangGraph](https://github.com/langchain-ai/langgraph) guard node that wires the
CodeRifts verdict directly into the agent loop.

Before the agent acts on a tool whose API contract may have drifted, the guard node diffs
the tool's old vs new spec against the zero-auth CodeRifts endpoint
(`POST https://app.coderifts.com/api/v1/demo`). On `BLOCK` the graph routes to `abort` and
the unsafe call never runs; on a safe verdict it proceeds to `execute`. No API key required.

## Run

```
pip install langgraph
python coderifts_langgraph_guard.py
```

On Python 3.9, pin the compatible release: `pip install "langgraph==0.6.11"`.

## Expected output

```
[guard] get_order_status: execution_action='STOP' reason=STOP ... patterns=[FIELD_REMOVAL]
[abort] CodeRifts STOP -> get_order_status not called, agent halted
final: aborted get_order_status (CodeRifts STOP)
```

## What it shows

The sample before/after pair renames the response field `order_status` to `status`.
CodeRifts flags `FIELD_REMOVAL` (HIGH) and the `TOOL_RESULT_SHAPE_DRIFT` reflex escalates the
decision to `BLOCK` even though the raw risk score is low, so the agent halts before calling
the tool against the now-incompatible contract.

Swap `OLD_SPEC` / `NEW_SPEC` for your own before/after pair to watch the verdict shift.

## Other framework examples

The same `@coderifts_guard` decorator works on any framework's tools. Two
siblings live alongside the LangGraph node, both invoking the tool directly with
no LLM so the trace is deterministic:

- `coderifts_langchain_guard.py` a LangChain tool. `pip install langchain-core` then `python coderifts_langchain_guard.py`.
- `coderifts_autogen_guard.py` an AutoGen tool registered for execution. `pip install "pyautogen<0.3"` then `python coderifts_autogen_guard.py`.

On the breaking change the tool body never runs (the guard raises before it); on
the safe additive change it does.

## How the guard node reads the verdict

Control flow follows `/.well-known/coderifts.json` → `recommended_usage`:
**branch on `execution_action`**, not `decision` / `omega_decision` / `safe_for_agent`.
The LangGraph node and `@coderifts_guard` share `evaluate_verdict` in
`coderifts_decorator.py` so they cannot diverge.

## Control-flow semantics (`execution_action`)

| `execution_action` | Guard |
|---|---|
| `CONTINUE` | Proceed |
| `CONTINUE_WITH_MONITORING` | Proceed only if `monitoring_sink_wired=True` |
| `REQUEST_APPROVAL` | Halt (approval is not optional) |
| `STOP` | Halt |
| anything else, **present** | Halt as unrecognised — never fall back to `decision` |
| **absent** | Legacy `decision`→action map, then the same rules |

`strict=` is deprecated and has no remaining job: under the published floor
`REQUEST_APPROVAL` already always halts.

```python
@coderifts_guard(old_spec, new_spec)
def call_tool(...): ...

# MONITOR action only proceeds when the host asserts a sink is wired:
@coderifts_guard(old_spec, new_spec, monitoring_sink_wired=True)
def call_tool(...): ...
```

On a halt the guard raises `CodeRiftsBlocked`. Inspect `err.execution_action`,
`err.reason`, and `err.verdict`. `err.decision` is diagnostic only.

Offline checks (no network, stdlib only):

```
python3 test_execution_action.py
```

## The full atomic chain (requires an API key)

Everything above stops at the **decision**: ask the zero-auth endpoint whether a
contract change is safe, branch on `execution_action`, act. That is the whole of
`coderifts_langgraph_guard.py`, and it needs no key.

**A decision is not a grant.** A decision says "this looks safe". An execution
grant says *this exact change, by this executor, against this target, once* — it
binds the bytes, and an executor consumes it a single time. An executor can
refuse to act without a grant. It has nothing to refuse on a decision.

`coderifts_langgraph_atomic.py` is that second path, as a second node. It asks
the **keyed** endpoint for a decision *and* a grant, and carries the grant to
whatever performs the mutation. The server mints it; this module requests and
carries it, and signs nothing itself.

```python
from coderifts_langgraph_atomic import build_app          # 1. atomic graph
app = build_app(); app.invoke({..., "target_uri": "https://api.example.com/orders"})
```

```
export CODERIFTS_API_KEY=cr_live_...
python coderifts_langgraph_atomic.py
```

Without `CODERIFTS_API_KEY` it raises a named error and stops. It does **not**
fall back to the zero-auth endpoint: that endpoint cannot mint a grant, so a
fallback would hand you a verdict while your code believed it held a grant.

The decision-only path is untouched by any of this — a separate file, a separate
graph, and `test_atomic_wire_fields.py` asserts the two share nothing but the
`evaluate_verdict` helper.

Check the wire shape with no key, no network and no `langgraph` installed:

```
python3 -m unittest test_atomic_wire_fields
```

It asserts the request field set against the generated canonical fixture in
`coderifts-app`, and skips with a named reason when that sibling checkout is
absent rather than passing quietly.

### Seeing the rest of the chain actually run

This example ends where the grant is handed over. Two places show what happens
after, and neither needs an API key:

- **[capability-demo `examples/atomic-v2`](https://github.com/coderifts/capability-demo/tree/main/examples/atomic-v2)**
  — `node examples/atomic-v2/run.js`. No network, no key, no database, about a
  second. Four hops asserted end to end: the authorize request shape, grant
  issuance, one-use consumption, and seal verification — plus a control that a
  forged signature over identical bytes is refused.
- **`node bin/prove-all.js`** in the same repository — boots a throwaway
  Postgres, runs the six panel proofs and the ten chain points in one process,
  and writes `transcript.json` and `TRANSCRIPT.md`. The tenth point re-verifies
  that transcript with the network trapped, so the artifact's own offline claim
  is demonstrated rather than asserted.
