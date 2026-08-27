# Invariants

Ten prohibitions. **A task completes; an invariant can break at any time if nobody knows it
exists.** Today proved that three times over: a misnamed constant produced a wrong *published*
recipe, a legacy payload survived a version bump because a coupling test covered one branch, and a
revoked key passed four verifiers because a resolver normalised it away. Each would have been
caught by a written rule plus one test that references it.

**The form is what makes this work, not the content.** Every entry carries three things: the rule,
the DEFECT CLASS it came from, and the enforcing test — or an explicit statement that none exists.
**An unenforced rule that looks enforced is worse than an absent one**, which is precisely the
lesson from the revoked-status round, so `ENFORCED BY: none` is written out rather than left blank.

Each line was MEASURED for this file rather than asserted. Three of them turned out not to hold as
stated, and those say so.

---

## 1. No provider credential reaches a guard callback

**RULE.** A callback the host registers with the guard (`onEvent`, `resolvePriorContent`,
`resolveStateNonce`, `monitoringSink`) never receives a provider credential, and the guard never
asks for one.

**DEFECT CLASS.** Credential widening by convenience — a callback that "just needs the token" turns
every host integration into a place a token can leak, and nothing in the type system objects.

**MEASURED.** Holds. `onEvent?: (e: GuardEvent) => void` and `resolvePriorContent` take no
credential parameter, and no callback signature in `src/with-coderifts.ts` mentions a token.

**ENFORCED BY:** `test/invariants.test.js` → *no guard callback signature accepts a provider
credential*. Previously **unguarded** — the rule held by habit only.

---

## 2. The executor is not a general shell or HTTP proxy

**RULE.** A CAS adapter performs a bounded, named filesystem operation. It never shells out and
never makes a network call on the host's behalf.

**DEFECT CLASS.** Capability creep — a governance component that can run arbitrary commands is a
better attack surface than the thing it governs.

**MEASURED.** Holds. No `child_process`, `exec`, `spawn`, `fetch` or `http` in `src/cas-adapters/`.

**ENFORCED BY:** `test/invariants.test.js` → *CAS adapters contain no shell or network capability*.

---

## 3. A Redis nonce-claim plus a separate API call is NOT one transaction

**RULE.** Claiming a nonce in one store and then calling an API is two operations. Nothing may
describe that pair as atomic.

**DEFECT CLASS.** Atomicity by adjacency — two operations that usually succeed together get
described as one, and the failure window is invisible until it opens. This is the same class as
this morning's CAS finding, where the token was fetched *after* the recheck and the window it
measured was vacuous.

**MEASURED.** Holds *here*, and the reason is scope rather than virtue: this package has no Redis
and issues no grants. The claim that matters lives server-side.

**ENFORCED BY:** **none in this repository, and it cannot be.** Enforcing it needs the issuing
service. Out of scope — see *What needs an executor* below.

---

## 4. The atomic profile is not a collection of switchable flags

**RULE.** A profile is a versioned contract. Membership of an invariant is a property of the
profile, not of nine independently settable booleans.

**DEFECT CLASS.** Convention-as-contract — exactly why we decided TWICE this week what
ENFORCING_STRICT requires (10.0.0 for the execution grant, 12.0.0 for the conditional-write gate).
A contract makes that question unaskable.

**MEASURED — UPDATED 2026-08-27 WHEN `_V1` SHIPPED. STILL VIOLATED, BUT NARROWLY, AND THE
REMAINING GAP IS NOT THE ONE THIS RULE WAS WRITTEN ABOUT.**

*What shipped.* `WithCodeRiftsProfile` is now `'ENFORCING_STRICT' | 'ENFORCING_STRICT_V1'`.
`_V1` names the nine conditions and freezes them: a test pins the seven weakenable flags by name
and fails on a tenth, so tightening `_V1` under its own name is no longer possible without
deleting that test on purpose. The unsuffixed spelling is a deprecated alias resolving to `_V1`,
proven byte-identical field-by-field on a real construction. The wire value on `GuardConfig` is
deliberately unchanged, so no downstream comparison moved.

*What that fixes.* The defect this rule came from — 10.0.0 and 12.0.0 being MAJOR because the
meaning of `ENFORCING_STRICT` changed under its own name — cannot recur for `_V1`. The next
tightening is `_V2`, and every adopter on `_V1` keeps what they asked for at zero cost.

*Why the record is NOT flipped to held.* Two things remain true, and a shipped improvement must not
quietly claim more than it earned:

1. **The unsuffixed alias is still an accepted, UNVERSIONED public spelling.** A caller writing
   `profile: 'ENFORCING_STRICT'` is still naming a contract without naming its version. That it
   resolves to `_V1` today is guaranteed by a comment and a test, not by the type — the type
   accepts both, and nothing structurally prevents a future maintainer re-pointing the alias. The
   rule says a profile *is* a versioned contract; one of the two accepted spellings still is not.
2. **The contract is still expressed as procedural checks, not as data.** `_V1` is nine conditions
   scattered across `enforcingStrictWeakenFlags`, an inline resolver check and
   `enforcingStrictExecutionChainProblems` — frozen by a test that reads the source, which is a
   guard against drift rather than a declaration. A genuine contract would be a table `_V1` and
   `_V2` both point at.

*The honest summary:* the expensive half is closed, the definitional half is not. Removing the
alias in a future major, and moving the nine conditions into a versioned table, is what would earn
`HELD` here.

**ENFORCED BY:** `test/profile-v1.test.js` → *a real construction is IDENTICAL field by field under
both spellings*, *the NINE conditions of _V1 are exactly these, and adding a tenth must become
_V2*, and *records that the alias must resolve to _V1 FOREVER*. Those enforce what shipped; nothing
enforces the two gaps above, which is why this entry still reads as violated.

---

## 5. The GitHub Actions App ID is not a CodeRifts-specific identity

**RULE.** `app_id 15368` is GitHub Actions, shared by every workflow in the repository. Binding a
required check to it proves the check came from Actions — never that it came from *our* workflow.

**DEFECT CLASS.** Identity borrowed from a shared issuer, then described as ours. The 2026-08-26
P0 was the mirror image: binding to the CodeRifts App, whose check cannot block.

**MEASURED.** Holds, and the code says so unprompted:
`src/provider/required-check-contract.js` (CLI) — *"RESIDUAL, named rather than solved: this issuer
is shared by every GitHub Actions workflow in the repository."* No source measured claims otherwise.

**ENFORCED BY:** `test/invariants.test.js` → *the shared-issuer residual is stated wherever the
enforcing app id is defined* (cross-repo read of the CLI constant). The conformance vector `ADV-7`
carries the same fact from the schema side.

---

## 6. No provider setup succeeds without a read-back

**RULE.** An installer that writes provider configuration re-reads it and grades the result with
the same verifier the enforcement path uses. "Wrote it" is not "it is in effect".

**DEFECT CLASS.** Write-without-verify — shipped as CLI 5.0.0's create-path defect, where the 404
branch wrote issuer-less legacy config and reported APPLIED.

**MEASURED.** Holds since CLI 6.0.0.

**ENFORCED BY:** `packages/cli/test/setup-required-check-verifier-readback.test.js` **in
coderifts-app**, notably *THE INVARIANT: APPLIED if and only if the enforcement verifier says
VERIFIED*. **Not enforceable from this repository** — the installer does not live here.

---

## 7. No automatic retry of an INDETERMINATE mutation

**RULE.** When a mutation's outcome cannot be determined, the guard never retries it. An
indeterminate write may have landed; retrying it is a second write.

**DEFECT CLASS.** Retry-on-unknown — the most common way an at-most-once system quietly becomes
at-least-once.

**MEASURED.** Holds. `indeterminate` appears 10 times across `src/*.ts` and in none of them next to
retry, loop or repeat logic; the status is surfaced, never acted on.

**ENFORCED BY:** `test/invariants.test.js` → *an indeterminate outcome is never retried
automatically*.

---

## 8. A host-reported commit does not earn `authorized_and_committed`

**RULE.** The success name requires an executor attestation verified against a customer-pinned
registry. A host saying "committed" is a claim, not a measurement.

**DEFECT CLASS.** Claim adopted as measurement — the same shape as `derive_is_self_authored`
trusting client-supplied provenance.

**MEASURED. WE DO NOT HOLD THIS AS STATED — it holds only under ENFORCING_STRICT.**
`buildCasAttestation` computes `authorized_and_committed = receipt_verified && cas.status ===
'committed'`, where `cas.status` comes from the host-supplied outcome. Only when
`opts.profile === 'ENFORCING_STRICT'` is it ANDed with `strictCommitObservation`, which demands
`evidence.class === 'executor_attested'` plus a kernel binding. The code states the split itself:
*"Non-strict keeps the 9.0.0 formula (receipt verified + clean commit)."*

**ENFORCED BY:** `test/invariants.test.js` → *the strict profile refuses a host-claimed commit*
**and** *DEFAULT PROFILE: a host-claimed commit still earns the name — the violation, pinned*. The
second test pins the violation rather than hiding it, so a future fix has to delete it deliberately.

---

## 9. No inescapable claim while the host can still write to the target

**RULE.** Nothing may be called inescapable while an actor in scope can still reach the target by
another path.

**DEFECT CLASS.** Public overstatement — our most expensive class, because an adopter quotes it.

**MEASURED. WE VIOLATE THIS, and the violation is in the NAME rather than in the basis.** See the
word-by-word finding below.

**ENFORCED BY:** `test/invariants.test.js` → *the inescapable basis names layers, never
unreachability*. The narrowing is proposed, not shipped — the wording is adopter-facing.

---

## 10. Different provider tiers do not get the same assurance level

**RULE.** A provider tier that *cannot* express a control and a repository we merely *could not
read* are different facts and must not share a status.

**DEFECT CLASS.** Collapsing "impossible" into "unknown" — the operator cannot tell whether to fix
permissions or to change plan.

**MEASURED. PARTIALLY HELD, AND NOT YET IN EFFECT.** This package has no tier concept at all, so
nothing here conflates them. The CLI's evidence vocabulary gained `UNSUPPORTED_PLAN` and
`PROVIDER_ERROR` earlier today, but **nothing emits them yet** — `evaluateLayers` still grades a
plan-limited 403 and a 5xx as `UNVERIFIABLE`. The names exist; the distinction does not.

**ENFORCED BY:** none here. The vocabulary test lives in
`packages/cli/test/evidence-expiry-vocabulary.test.js` in coderifts-app, and it asserts the names
exist — not that anything emits them. Recorded so the gap is not read as closed.

---

## Number 9 — the word-by-word finding

**What we say, exactly.** `enforce --check` emits `claim.inescapable_deploy` with a `basis` string.
On the true branch that string is, verbatim:

> `all six layers VERIFIED (issuer-bound required check + active workflow jobs + correlated environment)`

**The basis sentence is accurate.** It claims six layers are VERIFIED and lists them. It does not
say anything is unreachable. Read alone, it overstates nothing.

**The field name does overstate.** `inescapable_deploy: true` reads as *there is no way around
this*, and that is false while all six layers are VERIFIED, because:

1. **The workflow author is still in scope.** The enforcing issuer is `github-actions[bot]`, shared
   by every workflow in the repository, and `status-check-policy.checks[]` carries `{ context,
   app_id }` and no workflow-identifying field at all. Anyone who can edit `.github/workflows` can
   post the same check name under the same issuer. Measured from the GitHub OpenAPI description
   this morning; carried as conformance vector `ADV-7`.
2. **A repository admin with `enforce_admins` disabled merges past it**, and `enforce_admins` being
   VERIFIED is one of the six — but a ruleset `bypass_actor` is not, and `bypass_actors` was
   measured absent from every unauthenticated ruleset response.
3. **It is a configuration snapshot.** The evidence now carries `expires_at`, which concedes the
   point: a claim that expires was never a standing property.

**Proposed narrowing — NOT shipped, because the wording is adopter-facing.** Rename the field to
what it measures. `inescapable_deploy` → **`provider_configured_to_block`**, with the basis
extended by one clause:

> `all six layers VERIFIED (issuer-bound required check + active workflow jobs + correlated
> environment). This is a CONFIGURATION fact. It does not establish that no actor can reach the
> target by another path: the enforcing issuer is shared by every workflow in this repository, and
> bypass actors are not readable from here.`

If the name must stay for compatibility, the minimum honest change is that second sentence in the
basis, so the qualifier travels with the claim rather than living in documentation an adopter
quoting the field will not read.

---

## What needs an executor, and is therefore out of scope here

- **#3** (Redis nonce + API call) — needs the issuing service; this package has neither.
- **#6** (provider read-back) — enforced in coderifts-app, where the installer lives.
- **#10** (tier distinction) — the emission gap is in the CLI's `evaluateLayers`, not here.

A test in this repository asserting any of the three would be asserting a property of code that is
not in this repository, which is the vacuity this file exists to prevent.
