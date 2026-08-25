"""
CodeRifts guard on an AutoGen tool
==================================

The same framework-agnostic @coderifts_guard decorator, applied to an AutoGen
tool. Register the guarded function for execution on a ConversableAgent, then
invoke it through the agent. On BLOCK the guard raises CodeRiftsBlocked before
the tool body runs, so AutoGen reports the call as failed and the body never
executes. No LLM required (direct execute_function), so the trace is
deterministic.

Stacking: put @register_for_execution on top so AutoGen sees the guarded
callable, then @coderifts_guard underneath.

Requires coderifts_decorator.py (same repo) next to this file.

    pip3 install "pyautogen<0.3"
    python3 coderifts_autogen_guard.py
"""

import json

from autogen import ConversableAgent
from coderifts_decorator import coderifts_guard, CodeRiftsBlocked  # noqa: F401


# --- Breaking change: response field `order_status` -> `status` (the case Grok validated).
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

# --- Safe, additive change: a new optional response field.
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


def build_executor():
    # An executor agent that runs tools. No LLM: we invoke tools directly.
    executor = ConversableAgent("executor", llm_config=False, human_input_mode="NEVER")

    @executor.register_for_execution(name="get_order_status")
    @coderifts_guard(OLD_SPEC, NEW_SPEC)
    def get_order_status(order_id: str) -> str:
        """Get the status of an order by id."""
        return f"status for {order_id}"

    @executor.register_for_execution(name="list_orders")
    @coderifts_guard(SAFE_OLD, SAFE_NEW)
    def list_orders(limit: int = 10) -> str:
        """List recent orders."""
        return f"listed {limit} orders"

    return executor


def call(executor, name, arguments):
    return executor.execute_function({"name": name, "arguments": json.dumps(arguments)})


def main():
    executor = build_executor()

    print("AutoGen tool 1 - breaking contract change (expect BLOCK abort):")
    ok, res = call(executor, "get_order_status", {"order_id": "order-123"})
    print("executed=%s result=%r" % (ok, res.get("content")))
    if not ok:
        print("The AutoGen tool body never executed - CodeRifts halted it pre-call.\n")

    print("AutoGen tool 2 - safe additive change (expect tool runs):")
    ok, res = call(executor, "list_orders", {"limit": 5})
    print("executed=%s result=%r" % (ok, res.get("content")))


if __name__ == "__main__":
    main()
