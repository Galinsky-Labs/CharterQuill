// CORP-012: pure enterprise integration logic. Signed/idempotent webhooks,
// SCIM 2.0 user resources, SSO claim policy, licensed seat reconciliation,
// cap-table provider normalization and e-sign status mapping. Nothing here
// can change a frozen ownership snapshot or a vote: providers only produce
// evidence and reconciliation reports that people act on through the
// ordinary audited paths.
import { createHmac, createHash, timingSafeEqual } from "node:crypto";

export const WEBHOOK_TOLERANCE_SECONDS = 300;
const HEX64 = /^[a-f0-9]{64}$/;

/** `t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">` */
export function signWebhook({ secret, timestamp, body }) {
  if (typeof secret !== "string" || secret.length < 32) throw Error("Webhook secret too short");
  if (!Number.isSafeInteger(timestamp)) throw Error("Invalid webhook timestamp");
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  const mac = createHmac("sha256", secret).update(String(timestamp) + ".").update(bytes).digest("hex");
  return "t=" + timestamp + ",v1=" + mac;
}

/** Verifies a signature header in constant time with a replay window. */
export function verifyWebhook({ secret, header, body, now, tolerance = WEBHOOK_TOLERANCE_SECONDS }) {
  if (typeof header !== "string" || header.length > 512) return { ok: false, reason: "missing-signature" };
  const parts = Object.fromEntries(header.split(",").map((p) => p.trim().split("=")).filter((p) => p.length === 2));
  const timestamp = Number(parts.t);
  if (!Number.isSafeInteger(timestamp) || !HEX64.test(parts.v1 ?? "")) return { ok: false, reason: "malformed-signature" };
  if (Math.abs(Math.floor(now / 1000) - timestamp) > tolerance) return { ok: false, reason: "stale-signature" };
  const expected = Buffer.from(signWebhook({ secret, timestamp, body }).split("v1=")[1], "hex");
  const given = Buffer.from(parts.v1, "hex");
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return { ok: false, reason: "bad-signature" };
  return { ok: true, timestamp };
}

export const bodyDigest = (body) => createHash("sha256").update(body).digest("hex");

const SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCIM_QUILL_EXTENSION = "urn:ietf:params:scim:schemas:extension:quill:2.0:User";
const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

/** Normalizes a SCIM 2.0 User resource to the fields CharterQuill keeps. */
export function parseScimUser(resource) {
  if (!resource || typeof resource !== "object" || !Array.isArray(resource.schemas) || !resource.schemas.includes(SCIM_USER)) throw Error("SCIM_INVALID_SCHEMA");
  const externalId = resource.externalId ?? resource.id;
  if (typeof externalId !== "string" || !/^[A-Za-z0-9._@:-]{1,200}$/.test(externalId)) throw Error("SCIM_INVALID_EXTERNAL_ID");
  if (typeof resource.userName !== "string" || resource.userName.length < 1 || resource.userName.length > 254) throw Error("SCIM_INVALID_USERNAME");
  const accountId = resource[SCIM_QUILL_EXTENSION]?.accountId ?? null;
  if (accountId !== null && !UUID.test(accountId)) throw Error("SCIM_INVALID_ACCOUNT");
  const active = resource.active === undefined ? true : resource.active;
  if (typeof active !== "boolean") throw Error("SCIM_INVALID_ACTIVE");
  return { externalId, userName: resource.userName, accountId, active };
}

/** Applies a SCIM PatchOp; only `active` and `userName` may change. */
export function applyScimPatch(user, patch) {
  if (!patch || !Array.isArray(patch.Operations) || patch.Operations.length > 20) throw Error("SCIM_INVALID_PATCH");
  const next = { ...user };
  for (const op of patch.Operations) {
    const kind = String(op.op ?? "").toLowerCase();
    if (!["replace", "add"].includes(kind)) throw Error("SCIM_UNSUPPORTED_OPERATION");
    const values = op.path ? { [op.path]: op.value } : op.value;
    if (!values || typeof values !== "object") throw Error("SCIM_INVALID_PATCH");
    for (const [path, value] of Object.entries(values)) {
      if (path === "active") { if (typeof value !== "boolean") throw Error("SCIM_INVALID_ACTIVE"); next.active = value; }
      else if (path === "userName") { if (typeof value !== "string" || !value || value.length > 254) throw Error("SCIM_INVALID_USERNAME"); next.userName = value; }
      else throw Error("SCIM_UNSUPPORTED_ATTRIBUTE");
    }
  }
  return next;
}

export const scimResource = (u) => ({ schemas: [SCIM_USER], id: u.externalId, externalId: u.externalId, userName: u.userName, active: u.active,
  ...(u.accountId ? { [SCIM_QUILL_EXTENSION]: { accountId: u.accountId } } : {}) });

/**
 * Enterprise SSO policy over already-verified ID token claims. The engine's
 * OIDC client verifies signature and nonce; this adds issuer/audience pinning,
 * clock bounds and an allowed e-mail domain list.
 */
export function checkSsoClaims(claims, { issuer, clientId, allowedDomains = [], now, skewSeconds = 120 }) {
  const problems = [];
  if (claims.iss !== issuer) problems.push("issuer");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) problems.push("audience");
  if (aud.length > 1 && claims.azp !== clientId) problems.push("authorized-party");
  const t = Math.floor(now / 1000);
  if (!Number.isSafeInteger(claims.exp) || claims.exp + skewSeconds < t) problems.push("expired");
  if (Number.isSafeInteger(claims.iat) && claims.iat - skewSeconds > t) problems.push("issued-in-future");
  if (allowedDomains.length) {
    const domain = typeof claims.email === "string" ? claims.email.split("@").pop().toLowerCase() : null;
    if (!claims.email_verified || !allowedDomains.includes(domain)) problems.push("domain");
  }
  return { ok: problems.length === 0, problems };
}

/** Licensed seats against active members. Never removes anyone. */
export function seatReconciliation({ licensedSeats, unlimited = false, activeMembers }) {
  if (!Number.isSafeInteger(activeMembers) || activeMembers < 0) throw Error("Invalid member count");
  if (unlimited) return { status: "within-license", licensedSeats: null, activeMembers, overBy: 0, available: null };
  if (!Number.isSafeInteger(licensedSeats) || licensedSeats < 0) throw Error("Invalid seat count");
  const overBy = Math.max(0, activeMembers - licensedSeats);
  return { status: licensedSeats === 0 ? "unlicensed" : overBy ? "over-license" : "within-license", licensedSeats, activeMembers, overBy, available: Math.max(0, licensedSeats - activeMembers) };
}

const DECIMAL = /^(0|[1-9][0-9]{0,23})(\.[0-9]{1,18})?$/;
/** Normalizes a provider cap-table export into register rows (holder, class, quantity). */
export function normalizeCapTable(payload) {
  if (!payload || !Array.isArray(payload.holdings) || payload.holdings.length > 100000) throw Error("CAPTABLE_INVALID");
  const asOf = payload.asOf;
  if (typeof asOf !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(asOf)) throw Error("CAPTABLE_INVALID_DATE");
  const rows = new Map();
  for (const h of payload.holdings) {
    if (!UUID.test(h.accountId ?? "") || !/^[a-z][a-z0-9-]{0,39}$/.test(h.classId ?? "") || !DECIMAL.test(h.quantity ?? "")) throw Error("CAPTABLE_INVALID_HOLDING");
    const key = h.accountId + "|" + h.classId;
    if (rows.has(key)) throw Error("CAPTABLE_DUPLICATE_HOLDING");
    rows.set(key, { accountId: h.accountId, classId: h.classId, quantity: h.quantity });
  }
  return { asOf, rows: [...rows.values()].sort((a, b) => (a.accountId + a.classId).localeCompare(b.accountId + b.classId)) };
}

const toUnits = (quantity, scale) => {
  const [i, f = ""] = quantity.split(".");
  if (f.replace(/0+$/, "").length > scale) return null;
  return BigInt(i + f.padEnd(scale, "0").slice(0, scale));
};
/**
 * Compares a provider cap table with the register positions as of the same
 * date (integer units at each class's scale). The result is a report only:
 * the register and frozen record-date snapshots never change from here.
 */
export function capTableMismatches(provider, registerPositions, scales) {
  const ours = new Map(registerPositions.map((r) => [r.accountId + "|" + r.classId, BigInt(r.units)]));
  const theirs = new Map(), mismatches = [];
  for (const r of provider.rows) {
    if (!Object.hasOwn(scales, r.classId)) { mismatches.push({ accountId: r.accountId, classId: r.classId, problem: "unknown-class" }); continue; }
    const u = toUnits(r.quantity, scales[r.classId]);
    if (u === null) { mismatches.push({ accountId: r.accountId, classId: r.classId, problem: "precision" }); continue; }
    theirs.set(r.accountId + "|" + r.classId, u);
  }
  for (const key of new Set([...theirs.keys(), ...ours.keys()])) {
    const a = ours.get(key) ?? 0n, b = theirs.get(key) ?? 0n;
    if (a !== b) { const [accountId, classId] = key.split("|"); mismatches.push({ accountId, classId, problem: "quantity", register: a.toString(), provider: b.toString() }); }
  }
  return { matches: mismatches.length === 0, mismatches: mismatches.sort((x, y) => (x.accountId + x.classId).localeCompare(y.accountId + y.classId)) };
}

/** Maps provider e-sign envelope states onto evidence states. */
export const ESIGN_STATES = Object.freeze({ sent: "sent", delivered: "sent", viewed: "sent", completed: "externally-completed", signed: "externally-completed", declined: "declined", voided: "voided" });
export function esignEvidence(event) {
  const state = ESIGN_STATES[String(event?.status ?? "").toLowerCase()];
  if (!state) throw Error("ESIGN_UNKNOWN_STATUS");
  if (typeof event.envelopeId !== "string" || !/^[A-Za-z0-9-]{1,100}$/.test(event.envelopeId)) throw Error("ESIGN_INVALID_ENVELOPE");
  if (event.documentDigest !== undefined && !HEX64.test(event.documentDigest)) throw Error("ESIGN_INVALID_DIGEST");
  // External completion is evidence only; the engine's execution signatures remain authoritative.
  return { envelopeId: event.envelopeId, state, documentDigest: event.documentDigest ?? null, authoritative: false };
}

/** Outbound webhook endpoint policy: HTTPS, public host, bounded scopes. */
export const OUTBOUND_SCOPES = Object.freeze(["minute-book.entry", "integration.captable-mismatch", "scim.deprovision-queued"]);
export function validateEndpoint({ url, scopes }) {
  let parsed;
  try { parsed = new URL(url); } catch { throw Error("WEBHOOK_INVALID_URL"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || url.length > 500) throw Error("WEBHOOK_INVALID_URL");
  const host = parsed.hostname;
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || /^[0-9.]+$/.test(host) || host.includes(":") || !host.includes(".")) throw Error("WEBHOOK_PRIVATE_HOST");
  if (!Array.isArray(scopes) || !scopes.length || scopes.length > OUTBOUND_SCOPES.length || scopes.some((s) => !OUTBOUND_SCOPES.includes(s)) || new Set(scopes).size !== scopes.length) throw Error("WEBHOOK_INVALID_SCOPES");
  return { url: parsed.href, scopes: [...scopes].sort() };
}

/** Exponential retry schedule for outbound deliveries (seconds), capped. */
export const retryDelaySeconds = (attempts) => Math.min(6 * 3600, 30 * 2 ** Math.max(0, attempts - 1));
export const MAX_DELIVERY_ATTEMPTS = 12;
