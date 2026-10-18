# aap-issuer-service

The Issuer Service is the only server component that registers users' devices.
Users sign agent mandates in a dedicated iOS Issuer App with a Secure Enclave
P-256 key behind Face ID; **the server never holds a user private key**. This
crate (phase R1) covers device enrollment and the binding of each later mandate
to the attested app instance. It does not issue credentials yet (R2).

One binary serves staging and production. They differ only in configuration,
keys and data.

## Assurance recorded

iOS gives **AL2-A** (app-attested): App Attest proves a genuine instance of an
allow-listed app (`TEAMID.bundleId`) holds an App Attest key. It says nothing
about the Secure Enclave key's flags or whether Face ID happened. The service
records exactly that: `attestation_type = "app_attest"`.

## Endpoints

All bodies are JSON. Errors are `{"error": "<code>"}` with an optional
`"reason"` code; request content is never echoed.

| Endpoint | Purpose |
|---|---|
| `GET /health` | `200 {"status":"ok","env":"staging\|production"}` if the database answers, else `503` |
| `POST /v1/enrollment/challenge` | `201 {challenge_id, challenge, expires_at}`. 32 random bytes, single use, 5 minute TTL. Body ignored (max 1 KiB). |
| `POST /v1/enrollment` | Enrolls a device, `201 {user_id, device_id, attestation_type, environment}` |
| `POST /v1/assertions/verify` | Binds a payload digest to the attested app instance, `200 {verified, device_id, user_id, counter, attestation_type, environment}` |

### `POST /v1/enrollment`

```json
{
  "challenge_id": "<uuid>",
  "key_id": "<App Attest key id, standard base64>",
  "attestation": "<attestation object (CBOR), base64url>",
  "principal_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "pop_jws": "<compact ES256 JWS signed by the principal key>"
}
```

The `pop_jws` payload is exactly `{"purpose": "aap-enrollment-pop/v1", "challenge": "<b64url>",
"key_id": "<as above>", "jwk_thumbprint": "<b64url RFC 7638 thumbprint>"}`. The fixed
`purpose` separates this signature from mandates signed with the same key. The attestation's
`clientDataHash` must be `SHA256(challenge || thumbprint)` (raw bytes).

Checks, in order: strict parsing; challenge consumed atomically (a failed
attempt burns it); PoP signature and contents; the full App Attest attestation
(x5c chain to the pinned Apple App Attestation Root CA, nonce, keyId, rpIdHash
against the allow-list, counter 0, aaguid per environment policy,
credentialId). On success a user (random UUID, no personal data) and a device
are created in one transaction.

### `POST /v1/assertions/verify`

```json
{"device_id": "<uuid>", "payload_digest": "<SHA-256 of the mandate bytes, base64url>", "assertion": "<assertion object (CBOR), base64url>"}
```

Verifies the signature over `SHA256(authenticatorData || payload_digest)` and
the rpIdHash, then advances the stored counter with a single conditional
`UPDATE`. A validly signed assertion whose counter is not strictly greater than
the stored one is rejected:

* a verbatim replay, or an older assertion submitted late, gets `409
  assertion_replay`. The device is **not** flagged, because anyone who has seen
  an assertion (a merchant, a log reader) could otherwise lock the user out;
* a *different* assertion carrying the counter that was already accepted gets
  `409 counter_conflict` and flags the device. An honest App Attest key never
  produces two assertions with the same counter. A flagged device gets `403
  device_not_active` from then on.

Clients should send assertions in counter order: a later assertion that
arrives first makes the earlier one stale.

Verified assertions are written to the audit log with the payload digest and
counter.

## Safety properties

* `ISSUER_ENV` must be `staging` or `production`. Accepting the App Attest
  `development` aaguid requires `ISSUER_ALLOW_DEVELOPMENT_AAGUID=true`, which
  is only valid with `staging`; **the service refuses to start otherwise**. The
  policy is re-applied at assertion time, not only at enrollment.
* Binds to `127.0.0.1` by default. Request bodies are size-limited per route,
  parsed with `deny_unknown_fields`, and every decoded field is length- and
  encoding-checked (canonical base64, canonical JWK coordinates, on-curve
  points). Requests time out after 15 s.
* Per-IP rate limits (in memory, per process; IPv6 keyed by /64). The client IP
  is the socket peer unless `ISSUER_CLIENT_IP_HEADER` names a header written by
  a trusted reverse proxy, in which case its rightmost entry is used.
* Fail closed: any database or parsing error is a rejection. Logs are
  structured JSON; they never contain request bodies, keys or client IPs.
* The leaf credCert is only valid for ~3 days, so the chain is verified once at
  enrollment and only the App Attest public key is kept. The AT flag of
  assertion `authenticatorData` is not trusted (iOS 27 sets it on bare 37-byte
  data). ES256 signatures are accepted high-S.

## Database

SQL migrations live in `migrations/` and are applied **only** by
`aap-issuer-service migrate`, as a migration role. The server never migrates
implicitly and refuses to start if the schema does not match its embedded
migrations (checksums included). Applied files must not be edited; add a new
numbered file instead.

Two roles, provisioned out of band (no credentials in this repository):

* a **migration** role that owns the schema (`ISSUER_MIGRATE_DATABASE_URL`);
* an **app** role the service connects as (`ISSUER_DATABASE_URL`), named by
  `ISSUER_APP_ROLE` (default `aap_issuer_app`) when migrating. Migration 1
  grants it the minimum: no UPDATE/DELETE/TRUNCATE on `audit_events` (a trigger
  blocks them for every role as a second line), UPDATE only on the
  device counter/status columns, DELETE only on expired enrollment challenges.

Tables: `users` (random UUID only), `devices`, `enrollment_challenges`,
`audit_events` (append-only).

## Configuration

| Variable | Meaning |
|---|---|
| `ISSUER_ENV` | `staging` or `production` (required) |
| `ISSUER_DATABASE_URL` | app-role connection URL (required for `serve`) |
| `ISSUER_APP_IDS` | comma-separated allow-list of `TEAMID.bundleId` (required) |
| `ISSUER_ALLOW_DEVELOPMENT_AAGUID` | `true` to accept App Attest `development` (staging only) |
| `ISSUER_BIND` | listen address, default `127.0.0.1:3010` |
| `ISSUER_CLIENT_IP_HEADER` | header with the proxy-written client IP (optional) |
| `ISSUER_RATE_CHALLENGE_PER_MIN`, `ISSUER_RATE_ENROLLMENT_PER_MIN`, `ISSUER_RATE_ASSERTION_PER_MIN` | per-IP limits, defaults 20 / 10 / 120 |
| `ISSUER_MIGRATE_DATABASE_URL`, `ISSUER_APP_ROLE` | `migrate` only |
| `RUST_LOG` | log filter, default `info` |

## Tests

```bash
# Unit and attestation tests need nothing. The integration tests need a
# throwaway Postgres where the URL's role may create databases and roles;
# they create and drop their own and skip without the variable.
ISSUER_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres cargo test -p aap-issuer-service
```

CI sets `ISSUER_TEST_REQUIRE_DB=1`, so a missing database fails instead of
skipping. No device captures are committed: the attestation tests build a
synthetic Apple-style certificate chain (`tests/common`) and inject it as the
trust anchor, which only test code can do.

### Fuzzing

```bash
cd crates/issuer-service
cargo +nightly fuzz run attestation   # also: assertion, auth_data, requests
```

Seeds can be generated with
`FUZZ_SEED_DIR=<dir> cargo test --test attestation -- --ignored write_fuzz_seeds`.
