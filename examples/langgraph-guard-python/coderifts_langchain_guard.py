"""
CodeRifts guard on a LangChain tool
===================================

The same framework-agnostic @coderifts_guard decorator, applied to a LangChain tool.
Stack it under @tool so the guard runs on every tool invocation: on BLOCK it raises
CodeRiftsBlocked and the tool body never executes. No LLM required (direct invocation),
so the trace is deterministic.

Requires coderifts_decorator.py (same repo) next to this file.

    pip3 install langchain-core
    python3 coderifts_langchain_guard.py
"""

from langchain_core.tools import tool
from coderifts_decorator import coderifts_guard, CodeRiftsBlocked


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


@tool
@coderifts_guard(OLD_SPEC, NEW_SPEC)
def get_order_status(order_id: str) -> str:
    """Get the status of an order by id."""
    return f"status for {order_id}"


@tool
@coderifts_guard(SAFE_OLD, SAFE_NEW)
def list_orders(limit: int = 10) -> str:
    """List recent orders."""
    return f"listed {limit} orders"


if __name__ == "__main__":
    print("LangChain tool 1 - breaking contract change (expect BLOCK abort):")
    try:
        print("result:", get_order_status.invoke({"order_id": "order-123"}))
    except CodeRiftsBlocked as e:
        print("aborted:", e)
        print("The LangChain tool body never executed - CodeRifts halted it pre-call.\n")

    print("LangChain tool 2 - safe additive change (expect tool runs):")
    try:
        print("result:", list_orders.invoke({"limit": 5}))
    except CodeRiftsBlocked as e:
        print("aborted:", e)
