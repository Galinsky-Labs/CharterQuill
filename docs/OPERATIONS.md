# Operations and credential requirements

Foundation has no authentication, database, network API, encrypted collaboration, production signing, payment, blockchain transaction or deployed service. npm run check is dependency-free and does not need credentials. Core npm run demo binds loopback and serves an in-memory design demonstrator; restarting or reloading loses demo state. Never expose it as the production service.

Production target: shared engine API/realtime/worker on isolated Render services; Neon Postgres with tested TLS and row isolation; S3-compatible encrypted-object storage; optional Key Value for rate limits/fanout (never sole ballot authority). Frontends can be independently deployed. Provision only within authorized costs and verify actual trust/transport boundaries. No resource has been created by this foundation.

Required credentials by future capability: OIDC client and verified mail domain (identity); project-scoped database migration/runtime users; object storage scoped credentials; session protection; mail vendor; payment and webhook test/live keys; anchor RPC and protected signer reference with spend limits; code-host CI and deployment scopes. E2EE content/device keys remain at clients and cannot be injected as server environment secrets.

Registration: public GitHub source repository Galinsky-Labs/CharterQuill, immutable repository ID 1422879201, was created by the owner and write access verified. The foundation is being published via a real PR. After the canonical registry reaches the default branch, perform authenticated Engine Room/Boardroom source discovery and retain actual synchronization acknowledgments. Repository existence and a tracking issue do not establish live dashboard registration.

PR protocol: use a foundation bootstrap commit, then create dependency-ordered PRs with stable IDs, actual GitHub mappings and required CI. All planned PR specs are reviewable documents; opening every dependency-blocked empty PR is not useful. Use scripts/verify-pr-merge.mjs for exact-head verification and merging only when authenticated and green. Missing/rate-limited/unstarted/skipped checks never count as passed.

Deployment requires readiness/health, isolated resource identity, migration and rollback records, live multiuser browser journeys, real anchor receipts and source-bound security evidence. Archive backups/recovery tests and cost/scale assumptions. Human review is a post-deployment handoff, never a fictional completed audit.

## Enterprise integrations (CORP-012)

All integrations are off unless their configuration is present on the Render service. Nothing in this repository holds their values.

| Variable | Provider | Unlocks |
|---|---|---|
| `CHARTER_SCIM_TOKEN` (≥32 chars) and `CHARTER_SCIM_TENANT_ID` (workspace UUID) | Customer IdP (Okta, Entra ID, Google) | SCIM 2.0 `/api/charter/scim/v2/Users`. Deactivations queue removals that an owner applies. |
| `CHARTER_CAPTABLE_WEBHOOK_SECRET` (≥32 chars) | Cap-table provider (Carta, Pulley) via a relay that signs `Quill-Signature` | `POST /api/charter/integrations/{workspace}/webhooks/captable`. The cap table is compared with the register; a mismatch report is recorded and the register is never changed. |
| `CHARTER_ESIGN_WEBHOOK_SECRET` (≥32 chars) | E-sign provider (DocuSign, Dropbox Sign) via a signing relay | `POST /api/charter/integrations/{workspace}/webhooks/esign`. Envelope states are stored as non-authoritative evidence. |
| `CHARTER_WEBHOOK_ENCRYPTION_KEY` (64 hex) | none | Outbound signed webhooks: `minute-book.entry`, `integration.captable-mismatch` and `scim.deprovision-queued`, with backoff retries. |
| `OIDC_ISSUER` (plus the engine's OIDC client variables) and `CHARTER_SSO_ALLOWED_DOMAINS` | Customer IdP | Enterprise SSO. The domain policy is reported in `/integrations` but is not yet enforced at engine login. |

- **Seat licensing** uses the engine's shared `seats` entitlement grants. `GET /api/workspaces/{id}/charter/seats` reports whether the workspace is within its licence, unlicensed or over its licence. It never removes members.
- **Signature format:** `Quill-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">` with a 300-second tolerance. Event IDs are idempotent, and reusing an ID with a different body returns 409.
- **Not implemented:**
  - Direct provider API clients that pull from Carta or DocuSign.
  - Stripe seat checkout. The engine's Stripe provider handles document credits; seat grants are created by administrators.
  - SSO domain enforcement inside the engine's login.
