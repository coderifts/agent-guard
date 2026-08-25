"""
CodeRifts guard node for LangGraph
==================================

Wires the CodeRifts verdict directly into the agent loop. Before the agent
acts on a tool whose API contract may have drifted, a guard node diffs the
tool's old vs new spec against the zero-auth CodeRifts endpoint. Control flow
follows execution_action (shared evaluate_verdict from coderifts_decorator —
same rules as @coderifts_guard). On halt the graph routes to `abort` and the
unsafe call never runs; on CONTINUE (or MONITOR with a wired sink) it proceeds
to `execute`.

Endpoint: POST https://app.coderifts.com/api/v1/demo  (zero-auth, synchronous)
Run:      pip install langgraph  &&  python coderifts_langgraph_guard.py
"""

import json
import urllib.request
from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from coderifts_decorator import evaluate_verdict

CODERIFTS_DEMO_URL = "https://app.coderifts.com/api/v1/demo"


def call_coderifts(old_spec: dict, new_spec: dict) -> dict:
    """POST the before/after specs to the zero-auth diff endpoint, return the verdict."""
    payload = json.dumps({"old_spec": old_spec, "new_spec": new_spec}).encode()
    req = urllib.request.Request(
        CODERIFTS_DEMO_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"CodeRifts returned HTTP {e.code}: {body}") from None


class AgentState(TypedDict, total=False):
    tool_name: str          # the tool the agent is about to call
    old_spec: dict          # contract the agent was built against
    new_spec: dict          # contract currently served by the API
    verdict: dict           # full CodeRifts verdict
    blocked: bool           # guard decision (halt)
    halt_reason: str        # evaluate_verdict reason
    execution_action: str   # closed or raw unrecognised action
    result: str             # outcome of the run


# ---- nodes -----------------------------------------------------------------

def guard(state: AgentState) -> AgentState:
    """Self-check: ask CodeRifts whether the contract drift is safe to act on."""
    verdict = call_coderifts(state["old_spec"], state["new_spec"])
    # Same control flow as @coderifts_guard — branch_on execution_action.
    ev = evaluate_verdict(verdict, monitoring_sink_wired=False)
    patterns = ", ".join(
        p.get("name") or p.get("type", "") for p in verdict.get("detected_patterns", [])
    ) or "none"
    print(
        f"[guard] {state['tool_name']}: execution_action={ev['execution_action']!r} "
        f"reason={ev['reason']} source={ev['action_source']} "
        f"decision={ev['decision']!r}(diagnostic) patterns=[{patterns}]"
    )
    return {
        "verdict": verdict,
        "blocked": bool(ev["halt"]),
        "halt_reason": ev["reason"],
        "execution_action": ev["execution_action"] or "",
    }


def route(state: AgentState) -> str:
    return "abort" if state["blocked"] else "execute"


def execute(state: AgentState) -> AgentState:
    """The real tool call. Only reached when CodeRifts cleared the change."""
    print(f"[execute] contract safe -> calling {state['tool_name']}")
    return {"result": f"called {state['tool_name']}"}


def abort(state: AgentState) -> AgentState:
    """Reached on halt: the agent stops before the unsafe call."""
    reason = state.get("halt_reason") or "halt"
    print(
        f"[abort] CodeRifts {reason} -> {state['tool_name']} not called, agent halted"
    )
    return {"result": f"aborted {state['tool_name']} (CodeRifts {reason})"}


# ---- graph -----------------------------------------------------------------

def build_app():
    g = StateGraph(AgentState)
    g.add_node("guard", guard)
    g.add_node("execute", execute)
    g.add_node("abort", abort)
    g.add_edge(START, "guard")
    g.add_conditional_edges("guard", route, {"execute": "execute", "abort": "abort"})
    g.add_edge("execute", END)
    g.add_edge("abort", END)
    return g.compile()


# A breaking change: the response field `order_status` is renamed to `status`.
OLD_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0.0"},
    "paths": {"/orders/{id}": {"get": {"responses": {"200": {"description": "ok",
        "content": {"application/json": {"schema": {"type": "object",
            "properties": {"order_status": {"type": "string"}}}}}}}}}},
}
NEW_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0.0"},
    "paths": {"/orders/{id}": {"get": {"responses": {"200": {"description": "ok",
        "content": {"application/json": {"schema": {"type": "object",
            "properties": {"status": {"type": "string"}}}}}}}}}},
}


if __name__ == "__main__":
    app = build_app()
    final = app.invoke({
        "tool_name": "get_order_status",
        "old_spec": OLD_SPEC,
        "new_spec": NEW_SPEC,
    })
    print("\nfinal:", final["result"])
