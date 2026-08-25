#!/usr/bin/env python3
"""
Offline control-flow checks for evaluate_verdict / @coderifts_guard.

Standard library only. No network. No test framework.

    python3 test_execution_action.py
"""

from __future__ import print_function

import sys
import warnings

from coderifts_decorator import (
    CLOSED_EXECUTION_ACTIONS,
    CodeRiftsBlocked,
    coderifts_guard,
    evaluate_verdict,
)

# Prevent network if a decorator is misused in this file.
import coderifts_decorator as _mod

_mod._call_coderifts = lambda *a, **k: (_ for _ in ()).throw(
    RuntimeError("test_execution_action must not call the network")
)
_mod._VERDICT_CACHE.clear()


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_closed_set_matches_well_known():
    expected = {
        "CONTINUE",
        "CONTINUE_WITH_MONITORING",
        "REQUEST_APPROVAL",
        "STOP",
    }
    _assert(
        set(CLOSED_EXECUTION_ACTIONS) == expected,
        "closed set drifted from well-known: %r" % (CLOSED_EXECUTION_ACTIONS,),
    )


def test_continue_proceeds():
    r = evaluate_verdict({"execution_action": "CONTINUE", "decision": "ALLOW"})
    _assert(r["halt"] is False, r)
    _assert(r["reason"] == "CONTINUE", r)
    _assert(r["execution_action"] == "CONTINUE", r)


def test_stop_halts():
    r = evaluate_verdict({"execution_action": "STOP", "decision": "BLOCK"})
    _assert(r["halt"] is True, r)
    _assert(r["reason"] == "STOP", r)


def test_request_approval_halts_always():
    r = evaluate_verdict(
        {"execution_action": "REQUEST_APPROVAL", "decision": "REQUIRE_APPROVAL"}
    )
    _assert(r["halt"] is True, r)
    _assert(r["reason"] == "REQUEST_APPROVAL", r)
    # Decision-only legacy path must also halt (not opt-in strict).
    r2 = evaluate_verdict({"decision": "REQUIRE_APPROVAL"})
    _assert(r2["halt"] is True, r2)
    _assert(r2["execution_action"] == "REQUEST_APPROVAL", r2)
    _assert(r2["action_source"] == "legacy_decision_map", r2)


def test_monitor_requires_sink():
    r = evaluate_verdict(
        {"execution_action": "CONTINUE_WITH_MONITORING", "decision": "WARN"},
        monitoring_sink_wired=False,
    )
    _assert(r["halt"] is True, r)
    _assert(r["reason"] == "MONITORING_UNWIRED", r)

    r2 = evaluate_verdict(
        {"execution_action": "CONTINUE_WITH_MONITORING", "decision": "WARN"},
        monitoring_sink_wired=True,
    )
    _assert(r2["halt"] is False, r2)
    _assert(r2["reason"] == "CONTINUE_WITH_MONITORING", r2)


def test_unknown_present_halts_never_falls_to_decision():
    # PRESENT unknown + valid decision must NOT reinvent CONTINUE from ALLOW.
    r = evaluate_verdict(
        {"execution_action": "PROCEED_ANYWAY", "decision": "ALLOW"}
    )
    _assert(r["halt"] is True, r)
    _assert(r["reason"] == "EXECUTION_ACTION_UNRECOGNISED", r)
    _assert(r["execution_action"] == "PROCEED_ANYWAY", r)

    # Future restrictive action the client does not know — still halt.
    r2 = evaluate_verdict(
        {"execution_action": "QUARANTINE", "decision": "ALLOW"}
    )
    _assert(r2["halt"] is True, r2)
    _assert(r2["reason"] == "EXECUTION_ACTION_UNRECOGNISED", r2)


def test_absent_uses_legacy_decision_map():
    r = evaluate_verdict({"decision": "ALLOW"})
    _assert(r["halt"] is False, r)
    _assert(r["execution_action"] == "CONTINUE", r)
    _assert(r["action_source"] == "legacy_decision_map", r)

    r2 = evaluate_verdict({"decision": "BLOCK"})
    _assert(r2["halt"] is True, r2)
    _assert(r2["execution_action"] == "STOP", r2)


def test_envelope_execution_action_preferred():
    r = evaluate_verdict(
        {
            "decision": "ALLOW",
            "execution_action": "CONTINUE",  # would proceed if used
            "decision_result": {
                "decision": "BLOCK",
                "execution_action": "STOP",
            },
        }
    )
    _assert(r["halt"] is True, r)
    _assert(r["execution_action"] == "STOP", r)
    _assert(r["action_source"] == "envelope", r)


def test_decorator_offline_halt_and_proceed():
    _mod._VERDICT_CACHE.clear()
    # Inject a STOP verdict via the cache key path: monkeypatch _verdict.
    stop_v = {"execution_action": "STOP", "decision": "BLOCK", "detected_patterns": []}
    cont_v = {"execution_action": "CONTINUE", "decision": "ALLOW", "detected_patterns": []}

    def fake_verdict(old, new):
        return stop_v if old is stop_v else cont_v

    # Use direct evaluate via a tiny wrapper that skips network:
    calls = []

    def make_guarded(verdict):
        def guard(fn):
            def wrapper(*a, **k):
                r = evaluate_verdict(verdict)
                if r["halt"]:
                    raise CodeRiftsBlocked(
                        verdict,
                        execution_action=r["execution_action"],
                        reason=r["reason"],
                    )
                calls.append(fn.__name__)
                return fn(*a, **k)
            return wrapper
        return guard

    @make_guarded(stop_v)
    def blocked_tool():
        return "ran"

    @make_guarded(cont_v)
    def ok_tool():
        return "ran"

    try:
        blocked_tool()
        raise AssertionError("STOP must raise CodeRiftsBlocked")
    except CodeRiftsBlocked as e:
        _assert(e.reason == "STOP", e)
        _assert(e.execution_action == "STOP", e)

    _assert(ok_tool() == "ran", "CONTINUE must run body")
    _assert(calls == ["ok_tool"], calls)


def test_strict_deprecated_no_effect_on_continue():
    # strict=True must not invent a halt on CONTINUE; RA already always halts.
    r = evaluate_verdict({"execution_action": "CONTINUE", "decision": "ALLOW"})
    _assert(r["halt"] is False, r)

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        # Decorating with strict=True only warns; does not change evaluate_verdict.
        @coderifts_guard({"a": 1}, {"a": 2}, strict=True)
        def never_called():
            return 1

        _assert(any(issubclass(x.category, DeprecationWarning) for x in w), w)


def main():
    tests = [
        test_closed_set_matches_well_known,
        test_continue_proceeds,
        test_stop_halts,
        test_request_approval_halts_always,
        test_monitor_requires_sink,
        test_unknown_present_halts_never_falls_to_decision,
        test_absent_uses_legacy_decision_map,
        test_envelope_execution_action_preferred,
        test_decorator_offline_halt_and_proceed,
        test_strict_deprecated_no_effect_on_continue,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print("ok ", t.__name__)
        except Exception as e:
            failed += 1
            print("FAIL", t.__name__, ":", e)
    print()
    if failed:
        print("%d failed" % failed)
        return 1
    print("%d passed" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
