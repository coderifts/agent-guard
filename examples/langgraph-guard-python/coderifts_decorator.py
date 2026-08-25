"""
CodeRifts guard decorator
==========================

Collapses the agent-loop guard into one line. Decorate any tool function (or
LangGraph / AutoGen / LangChain node) with @coderifts_guard(old_spec, new_spec).
Before the wrapped function runs, the decorator diffs the old vs new API contract
against the zero-auth CodeRifts endpoint and halts the agent before an unsafe call.
The verdict is cached per spec pair (the contract does not change between calls),
so the endpoint is hit once, not on every invocation.

Control-flow semantics (/.well-known/coderifts.json recommended_usage)
----------------------------------------------------------------------
Branch on ``execution_action`` — not ``decision``, not ``safe_for_agent``.

Closed set (only these four values are recognised):

    CONTINUE                   Proceed.
    CONTINUE_WITH_MONITORING   Proceed only if monitoring_sink_wired=True
                               (host asserts a monitoring sink is wired).
    REQUEST_APPROVAL           Halt. Approval is not optional.
    STOP                       Halt.

    anything else, PRESENT     Halt as unrecognised. Never fall back to
                               decision (a present unknown is not a missing
                               action — same hole class as treating unknown
                               as absent and reinventing permission).
    ABSENT                     Legacy decision→action map may apply
                               (ALLOW→CONTINUE, WARN→CONTINUE_WITH_MONITORING,
                               REQUIRE_APPROVAL→REQUEST_APPROVAL, BLOCK→STOP).
                               Then the same closed-set rules above apply.
                               This path is for older responses that omit the
                               field; prefer responses that carry
                               execution_action.

Derived from app.coderifts.com/.well-known/coderifts.json:
  branch_on = execution_action
  execution_action = [CONTINUE, CONTINUE_WITH_MONITORING, REQUEST_APPROVAL, STOP]
  unrecognised_execution_action = not_permission_fail_closed
  continue_with_monitoring_requires = monitoringSinkWired

strict= is accepted for call-site compatibility but has no remaining job: under
the published floor REQUEST_APPROVAL already always halts. Passing strict=True
does not change outcomes and emits a DeprecationWarning.

Zero extra dependencies (standard library only). No API key required.

    python coderifts_decorator.py
"""

import functools
import json
import urllib.request
import urllib.error
import warnings

CODERIFTS_DEMO_URL = "https://app.coderifts.com/api/v1/demo"

# Closed set — must match /.well-known/coderifts.json recommended_usage.execution_action
CLOSED_EXECUTION_ACTIONS = frozenset({
    "CONTINUE",
    "CONTINUE_WITH_MONITORING",
    "REQUEST_APPROVAL",
    "STOP",
})

# Legacy map when execution_action is ABSENT only (not when present-but-unknown).
# Mirrors the server's deriveExecutionAction / missing-action path.
_DECISION_TO_ACTION = {
    "ALLOW": "CONTINUE",
    "WARN": "CONTINUE_WITH_MONITORING",
    "REQUIRE_APPROVAL": "REQUEST_APPROVAL",
    "BLOCK": "STOP",
}

_VERDICT_CACHE = {}


class CodeRiftsBlocked(Exception):
    """Raised by @coderifts_guard to halt the agent before an unsafe call.

    Raised on STOP and REQUEST_APPROVAL, on CONTINUE_WITH_MONITORING without a
    wired monitoring sink, and on a present but unrecognised execution_action.
    Inspect .execution_action, .reason, .verdict; .decision is diagnostic only
    (not the control-flow field).
    """

    def __init__(self, verdict, execution_action=None, reason=None):
        self.verdict = verdict
        self.decision = _decision(verdict)  # diagnostic; do not branch on this
        self.execution_action = execution_action
        self.reason = reason
        patterns = _pattern_names(verdict)
        label = reason or execution_action or self.decision
        super().__init__(
            f"CodeRifts halt ({label}) execution_action={execution_action!r} "
            f"patterns=[{patterns}]"
        )


def _decision(verdict):
    """Diagnostic only — not for control flow (branch_on is execution_action)."""
    if not isinstance(verdict, dict):
        return "UNKNOWN"
    env = verdict.get("decision_result")
    if isinstance(env, dict) and isinstance(env.get("decision"), str):
        return env["decision"]
    return verdict.get("omega_decision") or verdict.get("decision") or "UNKNOWN"


def _pattern_names(verdict):
    if not isinstance(verdict, dict):
        return "none"
    return ", ".join(
        p.get("name") or p.get("type", "") for p in verdict.get("detected_patterns", [])
    ) or "none"


def _raw_execution_action(verdict):
    """
    Locate execution_action if PRESENT.

    Returns (value, source) where value is the raw field (may be unknown),
    or (None, 'missing') when the field is absent/empty.
    Present-but-unrecognised is NOT the same as missing.
    """
    if not isinstance(verdict, dict):
        return None, "missing"

    env = verdict.get("decision_result")
    if isinstance(env, dict) and "execution_action" in env:
        v = env.get("execution_action")
        if v is not None and v != "":
            return v, "envelope"

    if "execution_action" in verdict:
        v = verdict.get("execution_action")
        if v is not None and v != "":
            return v, "top_level"

    return None, "missing"


def evaluate_verdict(verdict, monitoring_sink_wired=False):
    """
    Pure control-flow evaluation for a CodeRifts verdict dict.

    Returns a dict:
      halt: bool
      reason: str          # CONTINUE | REQUEST_APPROVAL | STOP | MONITORING_UNWIRED |
                           # EXECUTION_ACTION_UNRECOGNISED | UNREADABLE_DECISION | ...
      execution_action: str | None
      decision: str        # diagnostic only
      action_source: str   # envelope | top_level | legacy_decision_map | missing

    Does not call the network. Safe for offline tests and for framework nodes
    that already hold a verdict.
    """
    decision = _decision(verdict)
    raw, source = _raw_execution_action(verdict)

    if raw is not None:
        # PRESENT — closed set or unrecognised. Never fall through to decision.
        if not isinstance(raw, str) or raw not in CLOSED_EXECUTION_ACTIONS:
            return {
                "halt": True,
                "reason": "EXECUTION_ACTION_UNRECOGNISED",
                "execution_action": raw if isinstance(raw, str) else None,
                "decision": decision,
                "action_source": source,
            }
        action = raw
        action_source = source
    else:
        # ABSENT — legacy decision→action map, then apply the same closed rules.
        action = _DECISION_TO_ACTION.get(decision)
        action_source = "legacy_decision_map"
        if action is None:
            return {
                "halt": True,
                "reason": "UNREADABLE_DECISION",
                "execution_action": None,
                "decision": decision,
                "action_source": "missing",
            }

    if action == "STOP":
        return {
            "halt": True,
            "reason": "STOP",
            "execution_action": action,
            "decision": decision,
            "action_source": action_source,
        }
    if action == "REQUEST_APPROVAL":
        return {
            "halt": True,
            "reason": "REQUEST_APPROVAL",
            "execution_action": action,
            "decision": decision,
            "action_source": action_source,
        }
    if action == "CONTINUE_WITH_MONITORING":
        if monitoring_sink_wired:
            return {
                "halt": False,
                "reason": "CONTINUE_WITH_MONITORING",
                "execution_action": action,
                "decision": decision,
                "action_source": action_source,
            }
        return {
            "halt": True,
            "reason": "MONITORING_UNWIRED",
            "execution_action": action,
            "decision": decision,
            "action_source": action_source,
        }
    # CONTINUE
    return {
        "halt": False,
        "reason": "CONTINUE",
        "execution_action": action,
        "decision": decision,
        "action_source": action_source,
    }


def _call_coderifts(old_spec, new_spec):
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


def _verdict(old_spec, new_spec):
    key = json.dumps([old_spec, new_spec], sort_keys=True)
    if key not in _VERDICT_CACHE:
        _VERDICT_CACHE[key] = _call_coderifts(old_spec, new_spec)
    return _VERDICT_CACHE[key]


def coderifts_guard(old_spec, new_spec, strict=False, monitoring_sink_wired=False):
    """Decorator. Diff old vs new spec via CodeRifts before running the wrapped
    function, and halt the agent before an unsafe call.

    Control flow follows execution_action (see module docstring / well-known).

    monitoring_sink_wired: host assertion that a monitoring sink is wired.
        Required for CONTINUE_WITH_MONITORING to proceed (default False =
        fail closed on that action). Matches well-known
        continue_with_monitoring_requires: monitoringSinkWired.

    strict: deprecated, no remaining job. REQUEST_APPROVAL always halts under
        the published floor. Accepted for call-site compatibility; when True a
        DeprecationWarning is emitted and behaviour is unchanged.

    See the module docstring for the full control-flow semantics.
    """
    if strict:
        warnings.warn(
            "coderifts_guard(strict=True) is deprecated and has no effect: "
            "REQUEST_APPROVAL always halts under branch_on execution_action. "
            "Remove strict= or use monitoring_sink_wired for MONITOR only.",
            DeprecationWarning,
            stacklevel=2,
        )

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            verdict = _verdict(old_spec, new_spec)
            result = evaluate_verdict(
                verdict, monitoring_sink_wired=monitoring_sink_wired
            )
            print(
                f"[coderifts_guard] {fn.__name__}: "
                f"execution_action={result['execution_action']!r} "
                f"source={result['action_source']} "
                f"reason={result['reason']} "
                f"decision={result['decision']!r}(diagnostic) "
                f"patterns=[{_pattern_names(verdict)}]"
            )
            if result["halt"]:
                print(
                    f"[coderifts_guard] {result['reason']} -> "
                    f"{fn.__name__} not called, agent halted"
                )
                raise CodeRiftsBlocked(
                    verdict,
                    execution_action=result["execution_action"],
                    reason=result["reason"],
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --- Demo 1: a breaking change. The response field `order_status` -> `status`.
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


@coderifts_guard(OLD_SPEC, NEW_SPEC)
def get_order_status(order_id):
    # The real tool call. Only runs when CodeRifts clears the contract change.
    return f"status for {order_id}"


# --- Demo 2: a safe, additive change (new optional field). Proceeds when the
# server returns CONTINUE; halts if it returns REQUEST_APPROVAL or STOP.
SAFE_OLD = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0.0"},
    "paths": {"/orders": {"get": {"responses": {"200": {"description": "ok",
        "content": {"application/json": {"schema": {"type": "object",
            "properties": {"id": {"type": "string"}}}}}}}}}},
}
SAFE_NEW = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0.0"},
    "paths": {"/orders": {"get": {"responses": {"200": {"description": "ok",
        "content": {"application/json": {"schema": {"type": "object",
            "properties": {"id": {"type": "string"},
                           "note": {"type": "string"}}}}}}}}}},
}


@coderifts_guard(SAFE_OLD, SAFE_NEW)
def list_orders():
    return "orders list"


if __name__ == "__main__":
    print("Demo 1 - breaking change (expect STOP / halt):")
    try:
        print("result:", get_order_status("order-123"))
    except CodeRiftsBlocked as e:
        print("aborted:", e)

    print("\nDemo 2 - safe additive change (expect CONTINUE / proceed when server allows):")
    try:
        print("result:", list_orders())
    except CodeRiftsBlocked as e:
        print("aborted:", e)
