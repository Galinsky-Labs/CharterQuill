// CORP-012 enterprise integrations for CharterQuill, each disabled unless its
// configuration is present:
//   SCIM 2.0 provisioning   CHARTER_SCIM_TOKEN + CHARTER_SCIM_TENANT_ID
//   Cap-table webhooks      CHARTER_CAPTABLE_WEBHOOK_SECRET
//   E-sign webhooks         CHARTER_ESIGN_WEBHOOK_SECRET
//   Outbound webhooks       CHARTER_WEBHOOK_ENCRYPTION_KEY (64 hex)
//   SSO domain policy       OIDC_ISSUER + CHARTER_SSO_ALLOWED_DOMAINS (report only)
// Seat reconciliation reads the engine's shared `seats` entitlement grants.
// No provider can alter register entries, frozen snapshots or votes; secrets,
// bodies and identities are never logged.
import { readFileSync } from "node:fs";
import { randomUUID, randomBytes, createHash, timingSafeEqual, createCipheriv, createDecipheriv } from "node:crypto";
import { boundedJson, HttpError } from "@distributed-governance/engine/account-http";
import { defineExtension } from "@distributed-governance/engine/extension-sdk";
import {
  verifyWebhook, signWebhook, bodyDigest, parseScimUser, applyScimPatch, scimResource, seatReconciliation,
  normalizeCapTable, capTableMismatches, esignEvidence, validateEndpoint, retryDelaySeconds, MAX_DELIVERY_ATTEMPTS, OUTBOUND_SCOPES,
} from "../src/enterprise.mjs";

const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const WEBHOOK_LIMIT = 1_000_000, SCIM_LIMIT = 65536;
const migration = (name) => ({ name, sql: readFileSync(new URL("../migrations/enterprise/" + name, import.meta.url), "utf8") });

/** Reads configuration; anything missing or malformed leaves that integration off. */
export function enterpriseConfig(env = {}) {
  const secret = (v) => (typeof v === "string" && v.length >= 32 ? v : null);
  const scimToken = secret(env.CHARTER_SCIM_TOKEN), scimTenant = UUID.test(env.CHARTER_SCIM_TENANT_ID ?? "") ? env.CHARTER_SCIM_TENANT_ID : null;
  const key = /^[a-f0-9]{64}$/.test(env.CHARTER_WEBHOOK_ENCRYPTION_KEY ?? "") ? Buffer.from(env.CHARTER_WEBHOOK_ENCRYPTION_KEY, "hex") : null;
  const domains = (env.CHARTER_SSO_ALLOWED_DOMAINS ?? "").split(",").map((d) => d.trim().toLowerCase()).filter((d) => /^[a-z0-9.-]{3,253}$/.test(d));
  return Object.freeze({
    scim: scimToken && scimTenant ? { tokenDigest: createHash("sha256").update(scimToken).digest(), tenantId: scimTenant } : null,
    webhookSecrets: Object.freeze({ captable: secret(env.CHARTER_CAPTABLE_WEBHOOK_SECRET), esign: secret(env.CHARTER_ESIGN_WEBHOOK_SECRET) }),
    outboundKey: key,
    sso: env.OIDC_ISSUER ? { issuer: env.OIDC_ISSUER, allowedDomains: domains } : null,
  });
}

class EnterpriseError extends Error { constructor(code, status = 400) { super(code); this.code = code; this.status = status; } }
const need = (c, code, status) => { if (!c) throw new EnterpriseError(code, status); };
const scoped = (db, tenantId) => db.query("SELECT set_config('dge.tenant_id',$1,true)", [tenantId]);

const seal = (key, plaintext, aad) => {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  return Buffer.concat([iv, cipher.update(plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
};
const open = (key, sealed, aad) => {
  const decipher = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]).toString("utf8");
};

async function rawBody(request, limit) {
  if (Number(request.headers.get("content-length") ?? 0) > limit) throw new HttpError(413, "BODY_TOO_LARGE");
  const bytes = Buffer.from(await request.arrayBuffer());
  if (bytes.length > limit) throw new HttpError(413, "BODY_TOO_LARGE");
  return bytes;
}

export function createEnterpriseService({ identity, transaction, entitlements, config, clock = Date.now, fetcher = globalThis.fetch }) {
  const now = () => new Date(clock());
  const run = (credentials, tenantId, roles, fn, options = {}) => {
    need(UUID.test(tenantId ?? ""), "INVALID_WORKSPACE");
    return identity.withTenant(credentials, tenantId, { write: options.write ?? true, recent: options.recent ?? false, roles }, fn);
  };

  async function inboundWebhook(tenantId, provider, body, header) {
    const secret = config.webhookSecrets[provider];
    need(secret, "INTEGRATION_DISABLED", 404);
    need(UUID.test(tenantId ?? ""), "INVALID_WORKSPACE");
    const verdict = verifyWebhook({ secret, header, body, now: clock() });
    need(verdict.ok, "WEBHOOK_SIGNATURE_INVALID", 401);
    let event;
    try { event = JSON.parse(body.toString("utf8")); } catch { throw new EnterpriseError("WEBHOOK_EVENT_INVALID"); }
    need(event && typeof event.id === "string" && event.id.length >= 1 && event.id.length <= 200 && typeof event.type === "string" && event.type.length <= 80, "WEBHOOK_EVENT_INVALID");
    return transaction(async (db) => {
      await scoped(db, tenantId);
      const tenant = (await db.query("SELECT 1 FROM app_charter.organizations WHERE tenant_id=$1", [tenantId])).rows[0];
      need(tenant, "ORGANIZATION_NOT_CONFIGURED", 404);
      const prior = (await db.query("SELECT tenant_id,body_digest,outcome,report FROM app_charter.integration_events WHERE provider=$1 AND event_id=$2", [provider, event.id])).rows[0];
      if (prior) {
        need(prior.tenant_id === tenantId && prior.body_digest === bodyDigest(body), "WEBHOOK_EVENT_CONFLICT", 409);
        return { received: true, duplicate: true, outcome: prior.outcome };
      }
      let outcome = "recorded", report = null;
      if (provider === "captable") {
        const table = (() => { try { return normalizeCapTable(event.data); } catch (e) { throw new EnterpriseError(e.message); } })();
        const scales = Object.fromEntries((await db.query("SELECT id,scale FROM app_charter.share_classes WHERE tenant_id=$1", [tenantId])).rows.map((r) => [r.id, r.scale]));
        const entries = (await db.query(`SELECT DISTINCT ON (holder_account_id,class_id) holder_account_id AS "accountId",class_id AS "classId",units::text AS units
          FROM app_charter.register_entries WHERE tenant_id=$1 AND effective_date<=$2::date ORDER BY holder_account_id,class_id,effective_date DESC,sequence DESC`, [tenantId, table.asOf])).rows;
        report = { asOf: table.asOf, ...capTableMismatches(table, entries, scales) };
        outcome = report.matches ? "captable-matches" : "captable-mismatch";
      } else {
        report = (() => { try { return esignEvidence(event.data); } catch (e) { throw new EnterpriseError(e.message); } })();
      }
      await db.query("INSERT INTO app_charter.integration_events(provider,event_id,tenant_id,kind,body_digest,outcome,report,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        [provider, event.id, tenantId, event.type, bodyDigest(body), outcome, report, now()]);
      if (outcome === "captable-mismatch") await enqueue(db, tenantId, "integration.captable-mismatch", "captable:" + event.id, { asOf: report.asOf, mismatches: report.mismatches.length });
      return { received: true, duplicate: false, outcome };
    });
  }

  async function enqueue(db, tenantId, kind, eventId, payload) {
    if (!config.outboundKey) return;
    const endpoints = (await db.query("SELECT id FROM app_charter.webhook_endpoints WHERE tenant_id=$1 AND disabled_at IS NULL AND $2=ANY(scopes)", [tenantId, kind])).rows;
    for (const e of endpoints)
      await db.query("INSERT INTO app_charter.webhook_deliveries(tenant_id,endpoint_id,event_id,kind,payload,next_attempt_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT DO NOTHING",
        [tenantId, e.id, eventId, kind, { id: eventId, type: kind, tenantId, data: payload }, now()]);
  }

  const scimAuth = (request) => {
    need(config.scim, "INTEGRATION_DISABLED", 404);
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    const given = createHash("sha256").update(token).digest();
    need(token.length >= 32 && timingSafeEqual(given, config.scim.tokenDigest), "SCIM_UNAUTHORIZED", 401);
    return config.scim.tenantId;
  };
  const scimRow = (r) => ({ externalId: r.external_id, userName: r.user_name, accountId: r.account_id, active: r.active });
  async function scimWrite(db, tenantId, user) {
    const prior = (await db.query("SELECT * FROM app_charter.scim_users WHERE tenant_id=$1 AND external_id=$2 FOR UPDATE", [tenantId, user.externalId])).rows[0];
    if (prior) await db.query("UPDATE app_charter.scim_users SET user_name=$3,account_id=coalesce($4,account_id),active=$5,updated_at=$6 WHERE tenant_id=$1 AND external_id=$2",
      [tenantId, user.externalId, user.userName, user.accountId, user.active, now()]);
    else await db.query("INSERT INTO app_charter.scim_users(tenant_id,external_id,user_name,account_id,active,updated_at) VALUES($1,$2,$3,$4,$5,$6)",
      [tenantId, user.externalId, user.userName, user.accountId, user.active, now()]);
    const saved = (await db.query("SELECT * FROM app_charter.scim_users WHERE tenant_id=$1 AND external_id=$2", [tenantId, user.externalId])).rows[0];
    // Deactivation queues removal for an owner to apply through the engine's
    // audited membership path; SCIM never edits memberships directly.
    if ((prior?.active ?? true) && !saved.active) {
      const pending = (await db.query("SELECT 1 FROM app_charter.scim_deprovisions WHERE tenant_id=$1 AND external_id=$2 AND applied_at IS NULL", [tenantId, user.externalId])).rows[0];
      if (!pending) {
        await db.query("INSERT INTO app_charter.scim_deprovisions(tenant_id,id,external_id,account_id,requested_at) VALUES($1,$2,$3,$4,$5)", [tenantId, randomUUID(), user.externalId, saved.account_id, now()]);
        await enqueue(db, tenantId, "scim.deprovision-queued", "scim:" + user.externalId + ":" + clock(), { externalId: user.externalId });
      }
    }
    return scimRow(saved);
  }

  async function scim(request, rest) {
    const tenantId = scimAuth(request);
    const id = rest ? decodeURIComponent(rest) : null;
    let parsed = null;
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      const bytes = await rawBody(request, SCIM_LIMIT);
      try { parsed = JSON.parse(bytes.toString("utf8")); } catch { throw new EnterpriseError("SCIM_INVALID_JSON"); }
    }
    return transaction(async (db) => {
      await scoped(db, tenantId);
      const existing = id ? (await db.query("SELECT * FROM app_charter.scim_users WHERE tenant_id=$1 AND external_id=$2", [tenantId, id])).rows[0] : null;
      try {
        if (request.method === "GET" && !id) {
          const rows = (await db.query("SELECT * FROM app_charter.scim_users WHERE tenant_id=$1 ORDER BY external_id LIMIT 200", [tenantId])).rows;
          return { schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: rows.length, Resources: rows.map((r) => scimResource(scimRow(r))) };
        }
        if (request.method === "POST" && !id) return scimResource(await scimWrite(db, tenantId, parseScimUser(parsed)));
        need(existing, "SCIM_NOT_FOUND", 404);
        if (request.method === "GET") return scimResource(scimRow(existing));
        if (request.method === "PUT") { const user = parseScimUser(parsed); need(user.externalId === id, "SCIM_ID_MISMATCH"); return scimResource(await scimWrite(db, tenantId, user)); }
        if (request.method === "PATCH") return scimResource(await scimWrite(db, tenantId, applyScimPatch(scimRow(existing), parsed)));
        if (request.method === "DELETE") { await scimWrite(db, tenantId, { ...scimRow(existing), active: false }); return { deleted: true }; }
      } catch (e) { if (e instanceof EnterpriseError) throw e; if (/^SCIM_/.test(e?.message ?? "")) throw new EnterpriseError(e.message); throw e; }
      throw new EnterpriseError("METHOD_NOT_ALLOWED", 405);
    });
  }

  return {
    inboundWebhook, scim,
    status: (credentials, tenantId) => run(credentials, tenantId, ["owner", "admin"], async () => ({
      scim: config.scim ? (config.scim.tenantId === tenantId ? "enabled" : "enabled-for-another-workspace") : "disabled",
      captableWebhooks: config.webhookSecrets.captable ? "enabled" : "disabled",
      esignWebhooks: config.webhookSecrets.esign ? "enabled" : "disabled",
      outboundWebhooks: config.outboundKey ? "enabled" : "disabled",
      sso: config.sso ? { issuer: config.sso.issuer, allowedDomains: config.sso.allowedDomains } : "disabled",
      seatBilling: "shared-entitlements",
      note: "Integrations record evidence and reports only; they never change the register, frozen snapshots or votes.",
    }), { write: false }),
    seats: async (credentials, tenantId) => {
      const status = await entitlements.tenantStatus(credentials, tenantId);
      const seatGrants = status.grants.filter((g) => g.resource === "seats" && g.state === "active");
      let activeMembers = 0, after = null;
      do { const page = await identity.members(credentials, tenantId, { after, limit: 200 }); activeMembers += page.items.length; after = page.nextCursor; } while (after);
      const unlimited = seatGrants.some((g) => g.unlimited);
      const licensedSeats = seatGrants.reduce((n, g) => n + (g.unlimited ? 0 : Number(g.quantity)), 0);
      return { ...seatReconciliation({ licensedSeats, unlimited, activeMembers }), grants: seatGrants.map((g) => g.id) };
    },
    events: (credentials, tenantId) => run(credentials, tenantId, ["owner", "admin"], async (db) => ({
      items: (await db.query("SELECT provider,event_id,kind,outcome,report,received_at FROM app_charter.integration_events WHERE tenant_id=$1 ORDER BY received_at DESC LIMIT 100", [tenantId])).rows
        .map((r) => ({ provider: r.provider, eventId: r.event_id, kind: r.kind, outcome: r.outcome, report: r.report, receivedAt: r.received_at.toISOString() })),
    }), { write: false }),
    deprovisions: (credentials, tenantId) => run(credentials, tenantId, ["owner", "admin"], async (db) => ({
      items: (await db.query("SELECT id,external_id,account_id,requested_at,applied_at,outcome FROM app_charter.scim_deprovisions WHERE tenant_id=$1 ORDER BY requested_at DESC LIMIT 200", [tenantId])).rows
        .map((r) => ({ id: r.id, externalId: r.external_id, accountId: r.account_id, requestedAt: r.requested_at.toISOString(), appliedAt: r.applied_at?.toISOString() ?? null, outcome: r.outcome })),
    }), { write: false }),
    /** Owner applies queued SCIM deprovisions through the engine's membership API. */
    applyDeprovisions: async (credentials, tenantId) => {
      const pending = await run(credentials, tenantId, ["owner"], async (db) =>
        (await db.query("SELECT id,account_id FROM app_charter.scim_deprovisions WHERE tenant_id=$1 AND applied_at IS NULL ORDER BY requested_at LIMIT 100", [tenantId])).rows, { write: false });
      const results = [];
      for (const item of pending) {
        let outcome = "unmatched";
        if (item.account_id) {
          const role = await run(credentials, tenantId, ["owner"], async (db) =>
            (await db.query("SELECT role FROM dge_identity.memberships WHERE tenant_id=$1 AND account_id=$2 AND active", [tenantId, item.account_id])).rows[0]?.role ?? null, { write: false });
          if (!role) outcome = "not-a-member";
          else if (role === "owner") outcome = "owner-protected";
          else { await identity.changeMember(credentials, tenantId, item.account_id, null); outcome = "removed"; }
        }
        await run(credentials, tenantId, ["owner"], async (db, actor) =>
          db.query("UPDATE app_charter.scim_deprovisions SET applied_at=$3,applied_by=$4,outcome=$5 WHERE tenant_id=$1 AND id=$2 AND applied_at IS NULL", [tenantId, item.id, now(), actor.accountId, outcome]));
        results.push({ id: item.id, outcome });
      }
      return { applied: results };
    },
    createEndpoint: (credentials, tenantId, body) => run(credentials, tenantId, ["owner"], async (db, actor) => {
      need(config.outboundKey, "INTEGRATION_DISABLED", 404);
      const endpoint = (() => { try { return validateEndpoint(body); } catch (e) { throw new EnterpriseError(e.message); } })();
      const count = (await db.query("SELECT count(*)::int AS n FROM app_charter.webhook_endpoints WHERE tenant_id=$1 AND disabled_at IS NULL", [tenantId])).rows[0].n;
      need(count < 5, "WEBHOOK_ENDPOINT_LIMIT", 429);
      const id = randomUUID(), secret = randomBytes(32).toString("hex");
      const cursor = (await db.query("SELECT coalesce(max(sequence),0)::bigint AS n FROM app_charter.minute_entries WHERE tenant_id=$1", [tenantId])).rows[0].n;
      await db.query("INSERT INTO app_charter.webhook_endpoints(tenant_id,id,url,scopes,secret_ciphertext,created_by,created_at,minute_cursor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        [tenantId, id, endpoint.url, endpoint.scopes, seal(config.outboundKey, secret, tenantId + ":" + id), actor.accountId, now(), cursor]);
      // The signing secret is shown once and stored only encrypted.
      return { id, url: endpoint.url, scopes: endpoint.scopes, signingSecret: secret, signature: "Quill-Signature: t=<unix>,v1=<hex HMAC-SHA256 of \"<t>.<body>\">" };
    }, { recent: true }),
    endpoints: (credentials, tenantId) => run(credentials, tenantId, ["owner", "admin"], async (db) => ({
      scopes: OUTBOUND_SCOPES,
      items: (await db.query(`SELECT e.id,e.url,e.scopes,e.created_at,e.disabled_at,
          count(d.*) FILTER (WHERE d.delivered_at IS NOT NULL)::int AS delivered,
          count(d.*) FILTER (WHERE d.delivered_at IS NULL AND NOT d.abandoned)::int AS pending,
          count(d.*) FILTER (WHERE d.abandoned)::int AS abandoned
        FROM app_charter.webhook_endpoints e LEFT JOIN app_charter.webhook_deliveries d ON d.tenant_id=e.tenant_id AND d.endpoint_id=e.id
        WHERE e.tenant_id=$1 GROUP BY e.tenant_id,e.id ORDER BY e.created_at`, [tenantId])).rows
        .map((r) => ({ id: r.id, url: r.url, scopes: r.scopes, createdAt: r.created_at.toISOString(), disabledAt: r.disabled_at?.toISOString() ?? null, delivered: r.delivered, pending: r.pending, abandoned: r.abandoned })),
    }), { write: false }),
    disableEndpoint: (credentials, tenantId, endpointId) => run(credentials, tenantId, ["owner"], async (db) => {
      const r = await db.query("UPDATE app_charter.webhook_endpoints SET disabled_at=$3 WHERE tenant_id=$1 AND id=$2 AND disabled_at IS NULL RETURNING id", [tenantId, endpointId, now()]);
      need(r.rows.length, "WEBHOOK_ENDPOINT_NOT_FOUND", 404);
      return { disabled: true };
    }),
    /** One worker pass: enqueue new minute-book entries, then deliver due events. */
    async tick({ batch = 25 } = {}) {
      if (!config.outboundKey) return { delivered: 0, failed: 0 };
      await transaction(async (db) => {
        const endpoints = (await db.query("SELECT tenant_id,id,minute_cursor FROM app_charter.webhook_endpoints WHERE disabled_at IS NULL AND 'minute-book.entry'=ANY(scopes) LIMIT 200")).rows;
        for (const e of endpoints) {
          await scoped(db, e.tenant_id);
          const entries = (await db.query("SELECT sequence,digest,recorded_at FROM app_charter.minute_entries WHERE tenant_id=$1 AND sequence>$2 ORDER BY sequence LIMIT 100", [e.tenant_id, e.minute_cursor])).rows;
          for (const m of entries)
            await db.query("INSERT INTO app_charter.webhook_deliveries(tenant_id,endpoint_id,event_id,kind,payload,next_attempt_at,created_at) VALUES($1,$2,$3,'minute-book.entry',$4,$5,$5) ON CONFLICT DO NOTHING",
              [e.tenant_id, e.id, "minute:" + m.sequence, { id: "minute:" + m.sequence, type: "minute-book.entry", tenantId: e.tenant_id, data: { sequence: Number(m.sequence), digest: m.digest.trim(), recordedAt: m.recorded_at.toISOString() } }, now()]);
          if (entries.length) await db.query("UPDATE app_charter.webhook_endpoints SET minute_cursor=$3 WHERE tenant_id=$1 AND id=$2", [e.tenant_id, e.id, entries.at(-1).sequence]);
        }
      });
      const due = await transaction(async (db) => (await db.query(`SELECT d.tenant_id,d.endpoint_id,d.event_id,d.payload,d.attempts,e.url,e.secret_ciphertext
        FROM app_charter.webhook_deliveries d JOIN app_charter.webhook_endpoints e ON e.tenant_id=d.tenant_id AND e.id=d.endpoint_id
        WHERE d.delivered_at IS NULL AND NOT d.abandoned AND d.next_attempt_at<=$1 AND e.disabled_at IS NULL ORDER BY d.next_attempt_at LIMIT $2`, [now(), batch])).rows);
      let delivered = 0, failed = 0;
      for (const d of due) {
        const body = JSON.stringify(d.payload);
        let status = 0;
        try {
          const secret = open(config.outboundKey, d.secret_ciphertext, d.tenant_id + ":" + d.endpoint_id);
          const response = await fetcher(d.url, { method: "POST", redirect: "manual", signal: AbortSignal.timeout(10000),
            headers: { "content-type": "application/json", "quill-signature": signWebhook({ secret, timestamp: Math.floor(clock() / 1000), body }), "quill-event-id": d.event_id }, body });
          status = response.status;
        } catch { status = 0; }
        const ok = status >= 200 && status < 300, attempts = d.attempts + 1;
        await transaction((db) => db.query(`UPDATE app_charter.webhook_deliveries SET attempts=$4,last_status=$5,delivered_at=$6,next_attempt_at=$7,abandoned=$8
          WHERE tenant_id=$1 AND endpoint_id=$2 AND event_id=$3`, [d.tenant_id, d.endpoint_id, d.event_id, attempts, status, ok ? now() : null,
          new Date(clock() + retryDelaySeconds(attempts) * 1000), !ok && attempts >= MAX_DELIVERY_ATTEMPTS]));
        if (ok) delivered++; else failed++;
      }
      return { delivered, failed };
    },
  };
}

const TENANT_ROUTES = [
  ["GET", /^integrations$/, (s, c, t) => s.status(c, t)],
  ["GET", /^integrations\/events$/, (s, c, t) => s.events(c, t)],
  ["GET", /^seats$/, (s, c, t) => s.seats(c, t)],
  ["GET", /^integrations\/scim\/deprovisions$/, (s, c, t) => s.deprovisions(c, t)],
  ["POST", /^integrations\/scim\/deprovisions\/apply$/, (s, c, t) => s.applyDeprovisions(c, t), []],
  ["GET", /^webhooks$/, (s, c, t) => s.endpoints(c, t)],
  ["POST", /^webhooks$/, (s, c, t, b) => s.createEndpoint(c, t, b), ["url", "scopes"], ["url", "scopes"]],
  ["POST", /^webhooks\/([a-f0-9-]{36})\/disable$/, (s, c, t, b, m) => s.disableEndpoint(c, t, m[1]), []],
];

export function createEnterpriseRoutes(service) {
  const wrap = async (fn) => {
    try { return await fn(); }
    catch (cause) {
      if (cause instanceof EnterpriseError) throw new HttpError(cause.status, cause.code);
      if (cause?.constructor?.name === "DocumentError" && Number.isInteger(cause.status)) throw new HttpError(cause.status, cause.code);
      throw cause;
    }
  };
  return async ({ request, url, credentials, write, method }) => {
    // Provider webhooks: authenticated by signature, never by browser session.
    const hook = url.pathname.match(/^\/api\/charter\/integrations\/([a-f0-9-]{36})\/webhooks\/(captable|esign)$/);
    if (hook) {
      method(["POST"]);
      const body = await rawBody(request, WEBHOOK_LIMIT);
      return wrap(() => service.inboundWebhook(hook[1], hook[2], body, request.headers.get("quill-signature")));
    }
    const scim = url.pathname.match(/^\/api\/charter\/scim\/v2\/Users(?:\/([A-Za-z0-9._@:%-]{1,300}))?$/);
    if (scim) {
      method(scim[1] ? ["GET", "PUT", "PATCH", "DELETE"] : ["GET", "POST"]);
      const result = await wrap(() => service.scim(request, scim[1]));
      return new Response(request.method === "DELETE" ? null : JSON.stringify(result), { status: request.method === "DELETE" ? 204 : request.method === "POST" ? 201 : 200,
        headers: request.method === "DELETE" ? {} : { "content-type": "application/scim+json" } });
    }
    const match = url.pathname.match(/^\/api\/workspaces\/([a-f0-9-]{36})\/charter\/((?:integrations|seats|webhooks)(?:\/.*)?)$/);
    if (!match) return null;
    if (url.search) throw new HttpError(400, "INVALID_QUERY");
    const [, tenantId, rest] = match;
    const candidates = TENANT_ROUTES.filter(([, pattern]) => pattern.test(rest));
    if (!candidates.length) throw new HttpError(404, "NOT_FOUND");
    method([...new Set(candidates.map(([verb]) => verb))]);
    const [verb, pattern, handler, allowed = [], required = allowed] = candidates.find(([v]) => v === request.method);
    return wrap(async () => {
      let body = {};
      if (verb !== "GET") { write(); body = allowed.length ? await boundedJson(request, allowed, required, 8192) : {}; }
      return handler(service, credentials, tenantId, body, rest.match(pattern));
    });
  };
}

/** Extension factory; integrations stay disabled unless configured. */
export function createEnterpriseExtension({ env = process.env, clock, fetcher } = {}) {
  const config = enterpriseConfig(env);
  let service;
  const get = (services) => (service ??= createEnterpriseService({ ...services, config, ...(clock ? { clock } : {}), ...(fetcher ? { fetcher } : {}) }));
  return defineExtension({
    id: "charter-enterprise",
    migrations: [migration("001-enterprise.sql")],
    config,
    createRoutes: (services) => [{ routes: createEnterpriseRoutes(get(services)),
      bodyLimit: (path) => (/\/api\/charter\/integrations\//.test(path) ? WEBHOOK_LIMIT : path.startsWith("/api/charter/scim/") ? SCIM_LIMIT : 8192) }],
    createWorkers: (services) => (config.outboundKey ? [{ name: "charter-webhooks", intervalMs: 30000, tick: () => get(services).tick() }] : []),
  }, { engine: "^1.1.0", profile: "charter", capabilities: ["identity", "billing"], surfaces: ["routes", "workers", "migrations"] });
}
