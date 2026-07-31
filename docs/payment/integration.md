# Payment integration

How real payments credit a customer's account. Credits are applied **only** from
a signature-verified provider webhook — never from a client call (the M18 stub
`/payment/confirm` is not exposed by the production control plane).

**`/accounts/open`, `/payment/intent`, and `/billing/issue` are admin-token-gated
machine/operator routes** (`x-ct-admin-token: <CT_CP_EDGE_ADMIN_TOKEN>`, same as
`/enroll/issue`), not something a customer or a customer-facing client calls
directly — see `#194` in `service.rs`: they debit/grow the ledger for an
account named in the request body with no possession proof, so the control
plane fail-closes them (mounted only, and gated, when the admin token is
configured; absent — `404` — otherwise). The flow below is the operator/backend
integration sequence a payment-provider integration runs server-side, not a
customer-callable API. The real customer-facing balance paths are the
session-authed portal top-up and the OIDC `/me/issue` endpoint.

## Flow

1. **Open an account** (once): `POST /accounts/open` (admin token required) →
   `{account}`. In production the account is derived from the authenticated
   Keycloak subject.
2. **Create an intent**: `POST /payment/intent` (admin token required)
   `{account, credits}` → `{payment}`. The `payment` is our `PaymentId`; attach
   it to the provider's payment intent as metadata so it comes back on the
   webhook.
3. **Customer pays** at the provider (Stripe, etc.) — out of band.
4. **Provider webhook**: the provider POSTs a signed event to
   `POST /payment/webhook` (no admin token — gated by the provider's HMAC
   signature instead, see below). The control plane verifies the signature, and
   on `status == "succeeded"` credits the account for the intent's credits.
5. **Spend**: `POST /billing/issue` (admin token required) debits credit and
   mints a routing token.

## Webhook signature scheme

The provider signs the message `"<timestamp>.<raw-body>"` with the shared webhook
secret using HMAC-SHA256, and sends:

| Header | Value |
|--------|-------|
| `X-CT-Webhook-Timestamp` | unix seconds, the `<timestamp>` that was signed |
| `X-CT-Webhook-Signature` | hex HMAC-SHA256 of `"<timestamp>.<raw-body>"` |

The control plane rejects (`401`):

- a signature that does not match (forged or tampered body),
- a timestamp more than **300 seconds** from now (replay protection).

Delivery is **idempotent**: a replayed `succeeded` event returns `200` without
double-crediting. Unknown `payment` → `404`; non-`succeeded` events are acked
`200` without crediting.

The event body must be JSON containing at least:

```json
{ "payment": "<hex PaymentId from step 2>", "status": "succeeded" }
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `CT_PAYMENT_WEBHOOK_SECRET` | The provider's webhook signing secret. Must match the provider dashboard exactly. |

If `CT_PAYMENT_WEBHOOK_SECRET` is unset or empty, the control plane starts with a
random secret and logs `payment webhook disabled` — every webhook then fails
signature verification, so **no credit can be applied** until a real secret is
configured. This is fail-safe: an unconfigured deployment cannot be tricked into
crediting an account. The secret is provided via the deployment environment
(`.env` / Kubernetes Secret), never committed.

## Testing a deployment

1. Set `CT_PAYMENT_WEBHOOK_SECRET` and `CT_CP_EDGE_ADMIN_TOKEN` to known values.
2. `POST /accounts/open`, then `POST /payment/intent {account, credits}` (both
   with `x-ct-admin-token: <CT_CP_EDGE_ADMIN_TOKEN>`) to get a `payment` id.
3. Build body `{"payment":"<id>","status":"succeeded"}`, sign
   `"<now>.<body>"` with the webhook secret (HMAC-SHA256, hex), and POST it to
   `/payment/webhook` with the two headers above (no admin token needed here —
   the signature is the auth).
4. Expect `200`; `POST /billing/issue {account, price}` (admin token again) now
   succeeds against the credited balance.

The `credit_via_webhook` test helper in `service.rs` demonstrates exactly this
signing and posting sequence.
