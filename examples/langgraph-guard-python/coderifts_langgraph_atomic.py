"""
CodeRifts atomic guard node for LangGraph — the half after the decision
======================================================================

`coderifts_langgraph_guard.py` asks the zero-auth endpoint whether a contract
change is safe and branches on `execution_action`. That is a DECISION. This
module is the other half: it asks the KEYED endpoint for a decision **and an
execution grant**, and carries that grant to whatever performs the mutation.

A decision says "this looks safe". A grant says "this exact change, by this
executor, against this target, once". They are different objects and only the
second one an executor can refuse to act without.

ADDITIVE BY CONSTRUCTION. Nothing here imports from, patches, or re-runs
`coderifts_langgraph_guard.py`. The zero-auth path is byte-identical with this
file present or deleted; running that file does not execute a line of this one.

FAIL-CLOSED ON THE KEY. Without `CODERIFTS_API_KEY` this raises a named error.
It does NOT fall back to the demo endpoint: the demo endpoint cannot mint a
grant, so a silent fallback would hand the caller a decision while the code
around it believed it had a grant — the exact substitution this module exists
to make impossible.

Endpoint: POST https://app.coderifts.com/api/v1/preflight   (API key required)
Run:      export CODERIFTS_API_KEY=cr_live_...
          pip install langgraph && python coderifts_langgraph_atomic.py
"""

import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from typing import Optional, TypedDict

from coderifts_decorator import evaluate_verdict

CODERIFTS_PREFLIGHT_URL = os.environ.get(
    "CODERIFTS_PREFLIGHT_URL", "https://app.coderifts.com/api/v1/preflight"
)

GRANT_VERSION_V2 = "cr.exec.v2"

# ── the v2 wire contract ─────────────────────────────────────────────────────
#
# MEASURED, not guessed, from two sources that already agree:
#
#   coderifts-app/test/fixtures/v2-grant-canonical-request.json — the generated
#   parity fixture. Its own $comment: "a speaker is at parity when it serialises
#   `request` byte-equivalently and agrees with `reading` about what those bytes
#   mean." Its `request` carries twelve keys.
#
#   coderifts-python-sdk EXECUTION_GRANT_V2_REQUEST_FIELDS — the sibling speaker
#   that already sends these. Six identity fields, and it is the shorter list on
#   purpose.
#
# WHY `audience` IS NOT SENT, quoting the SDK's own measurement rather than
# re-deciding it here: preflight-change-set.js:144 builds
# `{ ...body, audience: decisionAudienceFor(req) }` — the server value is spread
# LAST, so a client-supplied audience is overwritten unconditionally. It appears
# in the canonical fixture because that fixture records the request the SERVER
# assembled, not what a client may send. Sending it would give a caller an
# argument that travels, is discarded, and reads like a binding that took effect.
#
# test_atomic_wire_fields.py holds this set against the fixture, and names
# `audience` as the one deliberate exclusion rather than letting the two drift.
WIRE_FIELDS = (
    "preflight_mode",
    "include_execution_grant",
    "grant_version",
    "tenant_id",
    "executor_id",
    "adapter_id",
    "target_uri",
    "state_nonce",
    "expected_state_token",
    "policy_hash",
    "context",
)

#: The fixture key this client deliberately does not send. Named, not omitted.
NOT_SENT = ("audience",)


class MissingApiKey(RuntimeError):
    """Raised when the atomic path is used without a key. Never a fallback."""


def _api_key() -> str:
    key = (os.environ.get("CODERIFTS_API_KEY") or "").strip()
    if not key:
        raise MissingApiKey(
            "CODERIFTS_API_KEY is not set. The atomic path requests an execution "
            "grant, and only the keyed endpoint mints one — the zero-auth demo "
            "endpoint returns a decision and no grant. This module will not fall "
            "back to it: you would get a verdict while the code around you "
            "believed it held a grant. Set CODERIFTS_API_KEY, or use "
            "coderifts_langgraph_guard.py, which is the decision-only path and "
            "needs no key."
        )
    return key


def state_nonce() -> str:
    """A fresh challenge per authorize call. Never reused across requests."""
    return secrets.token_hex(16)


def policy_hash(policy_text: str) -> str:
    """sha256 of the policy the caller is acting under, in the server's prefix form."""
    return "sha256:" + hashlib.sha256(policy_text.encode("utf-8")).hexdigest()


def build_authorize_request(
    *,
    old_spec: dict,
    new_spec: dict,
    operation: str,
    executor_id: str,
    adapter_id: str,
    target_uri: str,
    tenant_id: str,
    expected_state_token: str,
    policy: str,
    nonce: Optional[str] = None,
) -> dict:
    """
    The v2 authorize body, built and returned WITHOUT being sent.

    Separated from the call on purpose: it is what test_atomic_wire_fields.py
    asserts against the canonical fixture, so the shape is checked without a
    live request, an API key, or a network.

    THE SERVER MINTS THE GRANT. Every field here is an input to that minting —
    an identity, a target, a challenge. Nothing in this file signs anything, and
    a client that constructed something grant-shaped locally would be making a
    claim rather than requesting one.
    """
    return {
        "preflight_mode": "authorize",
        "include_execution_grant": True,
        "grant_version": GRANT_VERSION_V2,
        "tenant_id": tenant_id,
        "executor_id": executor_id,
        "adapter_id": adapter_id,
        "target_uri": target_uri,
        "state_nonce": nonce or state_nonce(),
        "expected_state_token": expected_state_token,
        "policy_hash": policy_hash(policy),
        # `context.operation` is what makes this the operation-bound path. Without
        # it the request is an analysis, and an analysis does not mint a grant.
        "context": {
            "operation": operation,
            "old_spec": old_spec,
            "new_spec": new_spec,
        },
    }


def call_coderifts_authorize(body: dict) -> dict:
    """POST the authorize request to the keyed endpoint and return the response."""
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        CODERIFTS_PREFLIGHT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_key()}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"CodeRifts returned HTTP {e.code}: {detail}") from None


class AtomicState(TypedDict, total=False):
    tool_name: str
    old_spec: dict
    new_spec: dict
    operation: str
    executor_id: str
    adapter_id: str
    target_uri: str
    tenant_id: str
    expected_state_token: str
    policy: str
    verdict: dict
    grant: str              # the compact grant token, when one was minted
    grant_absent_reason: str
    blocked: bool
    halt_reason: str
    execution_action: str
    result: str


# ---- nodes -----------------------------------------------------------------


def authorize(state: AtomicState) -> AtomicState:
    """Ask for a decision AND a grant. Fail-closed if no key is configured."""
    body = build_authorize_request(
        old_spec=state["old_spec"],
        new_spec=state["new_spec"],
        operation=state.get("operation", "tool_call"),
        executor_id=state.get("executor_id", "local"),
        adapter_id=state.get("adapter_id", "http"),
        target_uri=state["target_uri"],
        tenant_id=state.get("tenant_id", "default"),
        expected_state_token=state.get("expected_state_token", ""),
        policy=state.get("policy", ""),
    )
    verdict = call_coderifts_authorize(body)

    ev = evaluate_verdict(verdict, monitoring_sink_wired=False)

    # READ THE GRANT, DO NOT SYNTHESISE ONE. An allow-class decision with no
    # grant in the response is not an error here, but it is also not a grant:
    # the reason is recorded and `execute` refuses on it.
    grant = ""
    reason = ""
    envelope = verdict.get("execution_grant") or {}
    if isinstance(envelope, dict):
        grant = envelope.get("token") or ""
    elif isinstance(envelope, str):
        grant = envelope
    if not grant:
        reason = (
            "the authorize response carried no execution_grant. A decision was "
            "returned; a grant was not."
        )

    print(
        f"[authorize] {state['tool_name']}: execution_action={ev['execution_action']!r} "
        f"reason={ev['reason']} grant={'present' if grant else 'ABSENT'}"
    )
    return {
        "verdict": verdict,
        "grant": grant,
        "grant_absent_reason": reason,
        "blocked": bool(ev["halt"]),
        "halt_reason": ev["reason"],
        "execution_action": ev["execution_action"] or "",
    }


def route(state: AtomicState) -> str:
    # Two independent reasons to refuse, and they are not the same reason.
    # A halt is CodeRifts saying no; a missing grant is CodeRifts not having
    # said yes in the form an executor can check.
    if state.get("blocked"):
        return "abort"
    return "execute" if state.get("grant") else "abort"


def execute(state: AtomicState) -> AtomicState:
    """
    The mutating call, carrying the grant.

    THE EXECUTOR CONSUMES IT ONCE — that is the executor's job, not this node's.
    This node carries the token to it. What makes the chain atomic is the
    executor refusing a second presentation of the same grant, which is a
    property of the executor and its ledger; see the README's links to the
    local proof and to the full artifact.
    """
    print(
        f"[execute] grant carried -> calling {state['tool_name']} "
        f"(grant {state['grant'][:24]}…)"
    )
    return {"result": f"called {state['tool_name']} with grant"}


def abort(state: AtomicState) -> AtomicState:
    reason = state.get("halt_reason") or state.get("grant_absent_reason") or "halt"
    print(f"[abort] {state['tool_name']} not called: {reason}")
    return {"result": f"aborted {state['tool_name']} ({reason})"}


# ---- graph -----------------------------------------------------------------


def build_app():
    # Imported HERE, not at module scope. `build_authorize_request` and the wire
    # contract around it are checkable with no langgraph installed and no API key
    # — which is what lets test_atomic_wire_fields.py run offline. Only building
    # the actual graph needs the dependency, so only that pays for it.
    from langgraph.graph import StateGraph, START, END

    g = StateGraph(AtomicState)
    g.add_node("authorize", authorize)
    g.add_node("execute", execute)
    g.add_node("abort", abort)
    g.add_edge(START, "authorize")
    g.add_conditional_edges("authorize", route, {"execute": "execute", "abort": "abort"})
    g.add_edge("execute", END)
    g.add_edge("abort", END)
    return g.compile()


# The same breaking change the decision-only example uses: `order_status` -> `status`.
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
        "operation": "tool_call",
        "executor_id": "langgraph-example",
        "adapter_id": "http",
        "target_uri": "https://api.example.com/orders",
        "tenant_id": "default",
        "expected_state_token": "",
        "policy": "example-policy-v1",
    })
    print("\nfinal:", final["result"])
