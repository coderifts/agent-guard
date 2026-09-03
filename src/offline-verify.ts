/**
 * Offline receipt verification for the guard (1307).
 *
 * ── THE ASYMMETRY THIS CLOSES ───────────────────────────────────────────────────────────────
 *
 * MEASURED across the four enforcement points:
 *
 *   contract-gate      offline, pinned keyring   (vendored receipt-verifier)
 *   k8s-admission      offline, pinned keyring   (vendored receipt-verifier)
 *   gateway-verifier   offline, pinned keyring   (vendored receipt-verifier)
 *   agent-guard        OVER THE NETWORK          config.client.verifyReceipt()
 *
 * A verifier that needs the network fails differently from one that does not: it fails when the
 * network fails, and it tells the issuer which receipts are being checked. Three of the four points
 * had already been given a pinned keyring and a byte copy of the public verifier; the fourth — the
 * one facing agent tool calls — had not. The sentence "the same proof at all four points, offline"
 * was false because of this one.
 *
 * ── WHAT THIS DOES NOT CHANGE ───────────────────────────────────────────────────────────────
 *
 * It does not replace the network path. `config.client.verifyReceipt()` stays exactly as it was and
 * remains the default, because an existing host that has no keyring configured must keep working.
 * Supplying a keyring OPTS IN to offline verification; supplying nothing changes nothing.
 *
 * Nor does it decide anything about the receipt: the vendored verifier decides, this file only
 * hands it the bytes and the keys.
 */

// MEASURED: this package compiles to CommonJS (tsconfig module), so `import.meta.url` is not
// available. The vendored core is plain CJS and is reached with a plain require, resolved lazily
// inside core() so a host that never opts in never loads it.
// eslint-disable-next-line @typescript-eslint/no-var-requires
declare const require: (id: string) => unknown;

/**
 * The shape the guard already consumes from its network verifier — matched exactly.
 * NOT re-exported from index: the guard's own types already publish this name, and two names for
 * one contract is how they drift apart.
 */
interface VerifyReceiptResultLike {
  valid: boolean;
  status: string;
  reason?: string | null;
  payload?: Record<string, unknown>;
}

/**
 * A keyring the host pins. Same document the other three points load:
 * `{ keys: [{ kid, public_key_pem, status, ... }] }` — a local file or an already-parsed object.
 *
 * NEVER FETCHED. If this were fetchable the offline claim would be a configuration detail rather
 * than a property, and an attacker who could answer the fetch would choose the keys.
 */
export type PinnedKeyring = string | { keys: unknown[] };

interface VendoredCore {
  verifyReceipt: (token: string, opts: unknown) => VerifyReceiptResultLike;
  loadKeyring: (source: unknown) => Promise<Map<string, unknown>> | Map<string, unknown>;
}

function core(): VendoredCore {
  // Resolved lazily so a host that never opts in never loads it, and so this module can be
  // imported by tests that only inspect its contract.
  return require('./vendor/verify.js') as VendoredCore;
}

/**
 * Build an offline verifier from a pinned keyring.
 *
 * @returns a function with the SAME shape as `config.client.verifyReceipt`, so the guard's existing
 *          call site does not learn which one it is holding — which is the point: the two must be
 *          interchangeable, or the offline path would be a second, differently-behaving verifier.
 */
export async function offlineReceiptVerifier(
  keyring: PinnedKeyring,
): Promise<(token: string) => Promise<VerifyReceiptResultLike>> {
  const c = core();
  const ring = await c.loadKeyring(keyring);
  if (!ring || (ring instanceof Map && ring.size === 0)) {
    // Fail LOUDLY at construction rather than quietly at the first verification. An empty keyring
    // would make every receipt UNKNOWN_KEY, which reads as "the receipts are bad" when the truth is
    // "we were given no keys".
    throw new Error(
      'offlineReceiptVerifier: the pinned keyring is empty or unreadable. Offline verification '
      + 'with no keys refuses every receipt for the wrong reason — supply the keyring the issuer '
      + 'publishes at /.well-known/coderifts-keys.json, pinned locally.',
    );
  }
  return async function verifyReceiptOffline(token: string): Promise<VerifyReceiptResultLike> {
    // expectedKid null: accept any kid PRESENT IN THE PINNED RING. Rotation is additive; a kid the
    // ring does not carry resolves to UNKNOWN_KEY, which is fail-closed.
    return c.verifyReceipt(token, { ctx: { keyring: ring, expectedKid: null } });
  };
}

/**
 * Missing-receipt posture (1307, the second half).
 *
 * MEASURED at guard.ts:812 — the guard fails closed when a receipt is PRESENT and does not verify,
 * but an envelope carrying NO receipt token proceeds on the unsigned envelope, reconciled but not
 * cryptographically bound. `enforceable = receiptVerified && …` records the downgrade honestly, and
 * for many hosts proceeding is the right default (the analyze path has no receipt at all).
 *
 * It is not the right default for a host that has decided every action must be receipt-backed.
 * `requireReceipt` is that decision, made once at configuration time rather than inferred per call.
 */
export type MissingReceiptPolicy = 'proceed' | 'fail-closed';

export function missingReceiptDecision(
  policy: MissingReceiptPolicy | undefined,
  hasReceiptToken: boolean,
): { stop: boolean; cause?: string; detail?: string } {
  if (hasReceiptToken) return { stop: false };
  if (policy !== 'fail-closed') return { stop: false };
  return {
    stop: true,
    cause: 'RECEIPT_MISSING',
    detail:
      'requireReceipt is fail-closed and the decision envelope carried no receipt token. An '
      + 'envelope without a receipt is not tamper-evident: a proxy can change execution_action and '
      + 'nothing detects it. This host has chosen to stop rather than act on that.',
  };
}
