"""
The atomic module's wire field set, held against the canonical v2 fixture.

NO LIVE CALL, NO API KEY, NO NETWORK. `build_authorize_request` returns the body
without sending it, which is what makes this checkable offline — and checkable at
all by someone who has no key.

WHY THIS TEST EXISTS. A request that is *nearly* right is the expensive failure:
it gets a 200, it looks like it worked, and the field the server never received
is the one that was supposed to bind the grant. The canonical fixture
(coderifts-app/test/fixtures/v2-grant-canonical-request.json) is generated from
the request schema and says of itself: "a speaker is at parity when it serialises
`request` byte-equivalently and agrees with `reading` about what those bytes
mean." This asserts the first half.

THE FIXTURE IS OPTIONAL AND ITS ABSENCE IS NAMED. It lives in a sibling checkout
that a user of this example will not have. When it is missing these tests SKIP
with a reason — they do not quietly pass. A parity test that greens when it
cannot see the thing it is checking parity against reports "no drift" for the one
case where it did not look.
"""

import json
import os
import unittest
from pathlib import Path

from coderifts_langgraph_atomic import (
    NOT_SENT,
    WIRE_FIELDS,
    build_authorize_request,
    policy_hash,
    state_nonce,
)

#: Sibling checkout, overridable. Not vendored: a copy here would be a second
#: fixture that could drift from the generated one without anything noticing.
FIXTURE = Path(
    os.environ.get(
        "CODERIFTS_V2_FIXTURE",
        Path.home() / "coderifts-app" / "test" / "fixtures" / "v2-grant-canonical-request.json",
    )
)

SKIP_REASON = (
    f"UNPROVEN here: the canonical fixture is not at {FIXTURE}. Clone coderifts-app "
    "as a sibling, or set CODERIFTS_V2_FIXTURE. Not proven-by-absence."
)


def sample_request(**over):
    args = dict(
        old_spec={"openapi": "3.0.0"},
        new_spec={"openapi": "3.0.0"},
        operation="tool_call",
        executor_id="langgraph-example",
        adapter_id="http",
        target_uri="https://api.example.com/orders",
        tenant_id="default",
        expected_state_token="",
        policy="example-policy-v1",
        nonce="a" * 32,
    )
    args.update(over)
    return build_authorize_request(**args)


class WireFieldSet(unittest.TestCase):
    def test_declared_set_matches_what_is_built(self):
        """WIRE_FIELDS is not a comment — it is the set the builder emits."""
        body = sample_request()
        self.assertEqual(
            sorted(body.keys()), sorted(WIRE_FIELDS),
            "the built body and the declared WIRE_FIELDS disagree",
        )

    @unittest.skipUnless(FIXTURE.is_file(), SKIP_REASON)
    def test_wire_set_equals_canonical_minus_the_named_exclusion(self):
        """
        The whole assertion, in one line: what we send is the canonical set, less
        exactly the fields we NAME as deliberately not sent.

        `audience` is that one field, and the reason is measured rather than
        decided here: the server spreads its own audience LAST over the request
        body, so a client-supplied value is overwritten unconditionally. The
        fixture carries it because the fixture records the request the SERVER
        assembled. Sending it would be an argument that travels and is discarded.
        """
        canonical = set(json.loads(FIXTURE.read_text())["request"].keys())
        sent = set(WIRE_FIELDS)

        self.assertEqual(
            sent, canonical - set(NOT_SENT),
            f"wire drift — sent-but-not-canonical: {sorted(sent - canonical)}; "
            f"canonical-but-unsent-and-unnamed: {sorted(canonical - sent - set(NOT_SENT))}",
        )

    @unittest.skipUnless(FIXTURE.is_file(), SKIP_REASON)
    def test_every_named_exclusion_is_really_in_the_canonical_set(self):
        """
        NOT_SENT must name real fields. A name that is not in the fixture is an
        exclusion for something that was never there — it would silently widen
        the test above and let a genuinely missing field hide behind it.
        """
        canonical = set(json.loads(FIXTURE.read_text())["request"].keys())
        for field in NOT_SENT:
            self.assertIn(
                field, canonical,
                f"NOT_SENT names {field!r}, which is not a canonical request field",
            )

    @unittest.skipUnless(FIXTURE.is_file(), SKIP_REASON)
    def test_context_carries_the_operation_the_fixture_declares(self):
        """`context.operation` is what makes this the operation-bound path."""
        canonical_context = json.loads(FIXTURE.read_text())["request"]["context"]
        self.assertIn("operation", canonical_context)
        self.assertIn("operation", sample_request()["context"])


class ValuesTheServerReads(unittest.TestCase):
    def test_authorize_mode_and_grant_request_are_set(self):
        body = sample_request()
        self.assertEqual(body["preflight_mode"], "authorize")
        self.assertIs(body["include_execution_grant"], True)
        self.assertEqual(body["grant_version"], "cr.exec.v2")

    def test_analyze_mode_is_not_what_this_module_sends(self):
        # A grant is minted on the operation-bound path only. If this ever built
        # an analyze request, every downstream "we have a grant" would be wrong.
        self.assertNotEqual(sample_request()["preflight_mode"], "analyze")

    def test_policy_hash_is_the_prefixed_sha256_form(self):
        h = policy_hash("example-policy-v1")
        self.assertTrue(h.startswith("sha256:"), h)
        self.assertEqual(len(h), len("sha256:") + 64)
        self.assertNotEqual(policy_hash("a"), policy_hash("b"))

    def test_state_nonce_is_fresh_per_call(self):
        # A reused challenge is not a challenge.
        self.assertNotEqual(state_nonce(), state_nonce())

    def test_the_nonce_that_was_passed_in_is_the_one_that_ships(self):
        body = sample_request(nonce="deadbeef" * 4)
        self.assertEqual(body["state_nonce"], "deadbeef" * 4)


class FailClosedWithoutAKey(unittest.TestCase):
    def test_a_missing_key_raises_a_NAMED_error_and_names_the_alternative(self):
        """
        The refusal that matters. A silent fallback to the zero-auth endpoint
        would return a decision while the caller believed it held a grant.
        """
        from coderifts_langgraph_atomic import MissingApiKey, _api_key

        saved = os.environ.pop("CODERIFTS_API_KEY", None)
        try:
            with self.assertRaises(MissingApiKey) as ctx:
                _api_key()
            message = str(ctx.exception)
            self.assertIn("CODERIFTS_API_KEY", message)
            self.assertIn("coderifts_langgraph_guard.py", message,
                          "the error does not point at the keyless path that still works")
        finally:
            if saved is not None:
                os.environ["CODERIFTS_API_KEY"] = saved

    def test_an_empty_key_is_treated_as_absent(self):
        from coderifts_langgraph_atomic import MissingApiKey, _api_key

        saved = os.environ.get("CODERIFTS_API_KEY")
        try:
            os.environ["CODERIFTS_API_KEY"] = "   "
            with self.assertRaises(MissingApiKey):
                _api_key()
        finally:
            if saved is None:
                os.environ.pop("CODERIFTS_API_KEY", None)
            else:
                os.environ["CODERIFTS_API_KEY"] = saved

    def test_building_a_request_needs_no_key_at_all(self):
        # Deliberate: the shape is checkable by someone who has no key, which is
        # what lets this whole file run offline.
        saved = os.environ.pop("CODERIFTS_API_KEY", None)
        try:
            self.assertEqual(sorted(sample_request().keys()), sorted(WIRE_FIELDS))
        finally:
            if saved is not None:
                os.environ["CODERIFTS_API_KEY"] = saved


class TheZeroAuthPathIsUntouched(unittest.TestCase):
    """
    The additive claim, asserted rather than promised.

    This module is a SECOND node beside the decision-only one. If it ever
    imported, patched or re-ran the original, "byte-identical zero-auth path"
    would stop being true and nothing else would say so.
    """

    def test_the_atomic_module_does_not_import_the_decision_module(self):
        source = Path(__file__).with_name("coderifts_langgraph_atomic.py").read_text()
        self.assertNotIn("coderifts_langgraph_guard", source.replace(
            "coderifts_langgraph_guard.py", ""),  # prose mentions in docstrings are fine
        )

    def test_both_modules_share_only_the_decorator_helper(self):
        atomic = Path(__file__).with_name("coderifts_langgraph_atomic.py").read_text()
        guard = Path(__file__).with_name("coderifts_langgraph_guard.py").read_text()
        for source in (atomic, guard):
            self.assertIn("from coderifts_decorator import evaluate_verdict", source)

    def test_the_atomic_module_does_not_use_the_zero_auth_endpoint(self):
        source = Path(__file__).with_name("coderifts_langgraph_atomic.py").read_text()
        self.assertNotIn("/api/v1/demo", source,
                         "the atomic path references the zero-auth endpoint it must never fall back to")


if __name__ == "__main__":
    unittest.main(verbosity=2)
