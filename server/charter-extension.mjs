// CharterQuill engine extension: organization profile and governing rules,
// share classes and register, record-date snapshots, meetings and notices,
// written consents, interests and recusals, a digest-chained minute book,
// retention schedules, legal holds and an access log. Votes, proxies, class
// approvals, private encryption and signatures use the engine.
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { boundedJson, HttpError } from "@distributed-governance/engine/account-http";
import { defineExtension } from "@distributed-governance/engine/extension-sdk";
import { digest } from "@distributed-governance/engine/src/integrity.mjs";
import { ENTITY_TYPES, validateRule } from "../src/entities.mjs";
import { validateShareClass, parseRegisterCsv, recordDateSnapshot } from "../src/share-ledger.mjs";
import { validateMeeting, noticeCompliance, consentOutcome, validateInterest, applyRecusals, minuteEntry, DELIVERY_METHODS } from "../src/meetings.mjs";
import { RECORD_CLASSES, validateSchedule, disposalDecision, CHARTER_SETTINGS_DEFAULTS, CHARTER_CATALOG } from "../src/retention.mjs";

const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const migration = (name) => ({ name, sql: readFileSync(new URL("../migrations/" + name, import.meta.url), "utf8") });
export const CHARTER_PAGES = Object.freeze(["/charter/organization", "/charter/register", "/charter/meetings", "/charter/consents", "/charter/conflicts", "/charter/minute-book", "/charter/records"]);
const MANAGERS = ["owner", "admin"];
const MEMBERS = ["owner", "admin", "editor", "participant", "viewer"];

class CharterError extends Error { constructor(code, status = 400) { super(code); this.code = code; this.status = status; } }
const need = (c, code, status) => { if (!c) throw new CharterError(code, status); };
const parse = (fn, code) => { try { return fn(); } catch (e) { throw new CharterError(code + (e?.message ? ": " + e.message.slice(0, 120) : "")); } };
const iso = (v) => (v ? new Date(v).toISOString() : null);

export function createCharterService({ identity, clock = Date.now }) {
  const now = () => new Date(clock());
  const run = (credentials, tenantId, roles, fn, { write = true, recent = false } = {}) => {
    need(UUID.test(tenantId ?? ""), "INVALID_WORKSPACE");
    return identity.withTenant(credentials, tenantId, { write, roles, recent }, fn);
  };
  const log = (db, tenantId, accountId, action, subject) =>
    db.query("INSERT INTO app_charter.access_log(tenant_id,id,account_id,action,subject,at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, randomUUID(), accountId, action, subject.slice(0, 200), now()]);
  const organization = async (db, tenantId) => {
    const row = (await db.query("SELECT * FROM app_charter.organizations WHERE tenant_id=$1", [tenantId])).rows[0];
    need(row, "ORGANIZATION_NOT_CONFIGURED", 404);
    return row;
  };
  const classesOf = async (db, tenantId) => (await db.query("SELECT id,name,votes_per_share::text AS votes,scale FROM app_charter.share_classes WHERE tenant_id=$1 ORDER BY id", [tenantId])).rows
    .map((r) => ({ id: r.id, name: r.name, votesPerShare: r.votes, scale: r.scale, voting: r.votes !== "0" }));
  const appendMinute = async (db, tenantId, actor, { meetingId = null, kind, text }) => {
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["minutes:" + tenantId]);
    const last = (await db.query("SELECT sequence,digest FROM app_charter.minute_entries WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1", [tenantId])).rows[0];
    const entry = minuteEntry({ previousDigest: last?.digest ?? null, meetingId, kind, text, recordedAt: now().toISOString() }, digest);
    const sequence = (last?.sequence ?? 0) + 1;
    await db.query("INSERT INTO app_charter.minute_entries(tenant_id,sequence,entry,digest,recorded_by,recorded_at) VALUES($1,$2,$3,$4,$5,$6)",
      [tenantId, sequence, entry, entry.digest, actor.accountId, now()]);
    return { sequence, digest: entry.digest };
  };

  return {
    configure: (credentials, tenantId, body) => run(credentials, tenantId, ["owner"], async (db, actor) => {
      need(ENTITY_TYPES[body.entityType] && typeof body.legalName === "string" && body.legalName.trim() && body.legalName.length <= 300 &&
        typeof body.jurisdiction === "string" && body.jurisdiction.trim() && body.jurisdiction.length <= 120, "INVALID_ORGANIZATION");
      try {
        await db.query("INSERT INTO app_charter.organizations(tenant_id,entity_type,legal_name,jurisdiction,recusal_policy,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
          [tenantId, body.entityType, body.legalName.trim(), body.jurisdiction.trim(), body.recusalPolicy === "count-for-quorum" ? "count-for-quorum" : "exclude", actor.accountId, now()]);
      } catch (e) { if (e?.code === "23505") throw new CharterError("ORGANIZATION_ALREADY_CONFIGURED", 409); throw e; }
      return { tenantId, entityType: body.entityType, profile: ENTITY_TYPES[body.entityType] };
    }),
    profile: (credentials, tenantId) => run(credentials, tenantId, MEMBERS, async (db) => {
      const org = await organization(db, tenantId);
      const rules = (await db.query("SELECT DISTINCT ON (id) id,version,rule FROM app_charter.governing_rules WHERE tenant_id=$1 ORDER BY id,version DESC", [tenantId])).rows;
      return {
        tenantId, entityType: org.entity_type, legalName: org.legal_name, jurisdiction: org.jurisdiction, recusalPolicy: org.recusal_policy,
        entity: ENTITY_TYPES[org.entity_type], rules: rules.map((r) => ({ id: r.id, version: r.version, ...r.rule })),
        classes: await classesOf(db, tenantId),
      };
    }, { write: false }),
    setRule: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      const org = await organization(db, tenantId);
      const rule = parse(() => validateRule(body, org.entity_type), "INVALID_RULE");
      const id = body.id ?? randomUUID();
      need(UUID.test(id), "INVALID_RULE");
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [id]);
      const version = Number((await db.query("SELECT COALESCE(max(version),0) AS v FROM app_charter.governing_rules WHERE tenant_id=$1 AND id=$2", [tenantId, id])).rows[0].v) + 1;
      await db.query("INSERT INTO app_charter.governing_rules(tenant_id,id,version,rule,recorded_by,recorded_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, id, version, rule, actor.accountId, now()]);
      return { id, version, ...rule };
    }, { recent: true }),
    addClass: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db) => {
      await organization(db, tenantId);
      const cls = parse(() => validateShareClass(body), "INVALID_CLASS");
      try { await db.query("INSERT INTO app_charter.share_classes(tenant_id,id,name,votes_per_share,scale,created_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, cls.id, cls.name, cls.votesPerShare, cls.scale, now()]); }
      catch (e) { if (e?.code === "23505") throw new CharterError("CLASS_EXISTS", 409); throw e; }
      return cls;
    }, { recent: true }),
    importRegister: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      const classes = await classesOf(db, tenantId);
      const rows = parse(() => parseRegisterCsv(body.csv, classes), "INVALID_REGISTER");
      need(rows.length, "INVALID_REGISTER");
      const members = new Set((await db.query("SELECT account_id FROM dge_identity.memberships WHERE tenant_id=$1 AND active", [tenantId])).rows.map((r) => r.account_id));
      const outsider = rows.find((r) => !members.has(r.holderAccountId));
      need(!outsider, "HOLDER_NOT_A_MEMBER", 409);
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["register:" + tenantId]);
      let sequence = Number((await db.query("SELECT COALESCE(max(sequence),0) AS s FROM app_charter.register_entries WHERE tenant_id=$1", [tenantId])).rows[0].s);
      const batch = randomUUID();
      for (const r of rows)
        await db.query("INSERT INTO app_charter.register_entries(tenant_id,sequence,holder_account_id,class_id,units,effective_date,beneficial_owner_ref,import_batch,recorded_by,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
          [tenantId, ++sequence, r.holderAccountId, r.classId, r.units, r.effectiveDate, r.beneficialOwnerRef, batch, actor.accountId, now()]);
      await log(db, tenantId, actor.accountId, "register-import", batch);
      return { batch, rows: rows.length };
    }, { recent: true }),
    snapshot: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      need(typeof body.recordDate === "string" && /^\d{4}-\d{2}-\d{2}$/.test(body.recordDate), "INVALID_RECORD_DATE");
      const classes = await classesOf(db, tenantId);
      const entries = (await db.query("SELECT sequence,holder_account_id,class_id,units::text AS units,to_char(effective_date,'YYYY-MM-DD') AS effective,beneficial_owner_ref FROM app_charter.register_entries WHERE tenant_id=$1 AND effective_date<=$2::date", [tenantId, body.recordDate])).rows
        .map((r) => ({ sequence: Number(r.sequence), holderAccountId: r.holder_account_id, classId: r.class_id, units: r.units, effectiveDate: r.effective, beneficialOwnerRef: r.beneficial_owner_ref }));
      const snap = recordDateSnapshot(entries, classes, body.recordDate);
      const id = randomUUID(), snapDigest = digest("charterquill-record-snapshot-v1", snap);
      await db.query("INSERT INTO app_charter.record_snapshots(tenant_id,id,record_date,snapshot,digest,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)", [tenantId, id, body.recordDate, snap, snapDigest, actor.accountId, now()]);
      await log(db, tenantId, actor.accountId, "record-snapshot", id);
      // Roster entries for the engine's frozen electorate (units per class).
      return { id, digest: snapDigest, ...snap, rosterEntries: snap.members.map((m) => ({ principalId: m.principalId, units: m.votingUnits, class: m.class })) };
    }),
    snapshots: (credentials, tenantId) => run(credentials, tenantId, MANAGERS, async (db) =>
      ({ items: (await db.query("SELECT id,to_char(record_date,'YYYY-MM-DD') AS record_date,digest,created_at,snapshot->'totals' AS totals FROM app_charter.record_snapshots WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50", [tenantId])).rows
        .map((r) => ({ id: r.id, recordDate: r.record_date, digest: r.digest, totals: r.totals, createdAt: iso(r.created_at) })) }), { write: false }),

    scheduleMeeting: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      await organization(db, tenantId);
      const meeting = parse(() => validateMeeting(body, { now: clock() }), "INVALID_MEETING");
      const id = randomUUID();
      await db.query("INSERT INTO app_charter.meetings(tenant_id,id,meeting,created_by,created_at) VALUES($1,$2,$3,$4,$5)", [tenantId, id, meeting, actor.accountId, now()]);
      return { id, ...meeting, status: "scheduled" };
    }),
    meetings: (credentials, tenantId) => run(credentials, tenantId, MEMBERS, async (db) =>
      ({ items: (await db.query("SELECT id,meeting,status FROM app_charter.meetings WHERE tenant_id=$1 ORDER BY meeting->>'startsAt' DESC LIMIT 100", [tenantId])).rows.map((r) => ({ id: r.id, ...r.meeting, status: r.status })) }), { write: false }),
    recordNotice: (credentials, tenantId, meetingId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      need(UUID.test(meetingId) && UUID.test(body.recipientId ?? "") && DELIVERY_METHODS.includes(body.method) && !Number.isNaN(Date.parse(body.deliveredAt)), "INVALID_NOTICE");
      need(Date.parse(body.deliveredAt) <= clock(), "NOTICE_IN_FUTURE");
      need((await db.query("SELECT 1 FROM app_charter.meetings WHERE tenant_id=$1 AND id=$2", [tenantId, meetingId])).rows.length, "MEETING_NOT_FOUND", 404);
      await db.query("INSERT INTO app_charter.notices(tenant_id,meeting_id,recipient_id,method,delivered_at,recorded_by,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        [tenantId, meetingId, body.recipientId, body.method, new Date(body.deliveredAt), actor.accountId, now()]);
      return { recorded: true };
    }),
    noticeStatus: (credentials, tenantId, meetingId) => run(credentials, tenantId, MANAGERS, async (db) => {
      need(UUID.test(meetingId), "INVALID_MEETING");
      const m = (await db.query("SELECT meeting FROM app_charter.meetings WHERE tenant_id=$1 AND id=$2", [tenantId, meetingId])).rows[0];
      need(m, "MEETING_NOT_FOUND", 404);
      const recipients = (await db.query("SELECT account_id FROM dge_identity.memberships WHERE tenant_id=$1 AND active AND role<>'viewer'", [tenantId])).rows.map((r) => r.account_id);
      const deliveries = (await db.query("SELECT recipient_id,delivered_at FROM app_charter.notices WHERE tenant_id=$1 AND meeting_id=$2", [tenantId, meetingId])).rows.map((r) => ({ recipientId: r.recipient_id, deliveredAt: iso(r.delivered_at) }));
      return noticeCompliance({ startsAt: m.meeting.startsAt, minimumNoticeDays: m.meeting.minimumNoticeDays, recipients, deliveries });
    }, { write: false }),
    recordMinutes: (credentials, tenantId, meetingId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      need(UUID.test(meetingId) && typeof body.text === "string", "INVALID_MINUTES");
      const m = (await db.query("SELECT status FROM app_charter.meetings WHERE tenant_id=$1 AND id=$2", [tenantId, meetingId])).rows[0];
      need(m, "MEETING_NOT_FOUND", 404);
      if (m.status === "scheduled") await db.query("UPDATE app_charter.meetings SET status='held' WHERE tenant_id=$1 AND id=$2", [tenantId, meetingId]);
      return appendMinute(db, tenantId, actor, { meetingId, kind: "minutes", text: body.text });
    }),

    openConsent: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      need(typeof body.title === "string" && body.title.trim() && body.title.length <= 300 && typeof body.resolutionText === "string" && body.resolutionText.trim() && body.resolutionText.length <= 100000 &&
        typeof body.body === "string" && body.body.length <= 60 && Number.isSafeInteger(body.hours) && body.hours >= 1 && body.hours <= 2160, "INVALID_CONSENT");
      const eligible = Array.isArray(body.eligible) ? [...new Set(body.eligible)] : [];
      need(eligible.length >= 1 && eligible.length <= 1000 && eligible.every((a) => UUID.test(a)), "INVALID_CONSENT");
      const members = new Set((await db.query("SELECT account_id FROM dge_identity.memberships WHERE tenant_id=$1 AND active", [tenantId])).rows.map((r) => r.account_id));
      need(eligible.every((a) => members.has(a)), "SIGNATORY_NOT_A_MEMBER", 409);
      const t = body.threshold ?? { numerator: 1, denominator: 1 };
      need(Number.isSafeInteger(t.numerator) && Number.isSafeInteger(t.denominator) && t.numerator >= 1 && t.numerator <= t.denominator && t.denominator <= 100, "INVALID_CONSENT");
      const id = randomUUID(), textDigest = digest("charterquill-written-consent-v1", { title: body.title.trim(), resolutionText: body.resolutionText });
      await db.query("INSERT INTO app_charter.consents(tenant_id,id,title,body,resolution_text,text_digest,eligible,threshold_numerator,threshold_denominator,closes_at,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        [tenantId, id, body.title.trim(), body.body, body.resolutionText, textDigest, eligible, t.numerator, t.denominator, new Date(clock() + body.hours * 3600000), actor.accountId, now()]);
      return { id, textDigest, eligible: eligible.length };
    }, { recent: true }),
    consents: (credentials, tenantId) => run(credentials, tenantId, MEMBERS, async (db, actor) => {
      const rows = (await db.query("SELECT * FROM app_charter.consents WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100", [tenantId])).rows;
      const sigs = (await db.query("SELECT consent_id,account_id,choice FROM app_charter.consent_signatures WHERE tenant_id=$1", [tenantId])).rows;
      return { items: rows.map((r) => {
        const mine = sigs.filter((s) => s.consent_id === r.id);
        const outcome = consentOutcome({ eligible: r.eligible, consents: mine.map((s) => ({ accountId: s.account_id, choice: s.choice })), threshold: { numerator: r.threshold_numerator, denominator: r.threshold_denominator } });
        return { id: r.id, title: r.title, body: r.body, resolutionText: r.resolution_text, textDigest: r.text_digest, closesAt: iso(r.closes_at),
          open: Date.parse(r.closes_at) > clock() && !outcome.passed, outcome, eligibleToSign: r.eligible.includes(actor.accountId),
          myChoice: mine.find((s) => s.account_id === actor.accountId)?.choice ?? null };
      }) };
    }, { write: false }),
    signConsent: (credentials, tenantId, consentId, body) => run(credentials, tenantId, MEMBERS, async (db, actor) => {
      need(UUID.test(consentId) && ["consent", "withhold"].includes(body.choice) && /^[a-f0-9]{64}$/.test(body.textDigest ?? ""), "INVALID_CONSENT_SIGNATURE");
      await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["consent:" + consentId]);
      const c = (await db.query("SELECT * FROM app_charter.consents WHERE tenant_id=$1 AND id=$2", [tenantId, consentId])).rows[0];
      need(c, "CONSENT_NOT_FOUND", 404);
      need(c.eligible.includes(actor.accountId), "NOT_AN_ELIGIBLE_SIGNATORY", 403);
      need(c.text_digest === body.textDigest, "CONSENT_TEXT_CHANGED", 409);
      need(Date.parse(c.closes_at) > clock(), "CONSENT_CLOSED", 409);
      try { await db.query("INSERT INTO app_charter.consent_signatures(tenant_id,consent_id,account_id,choice,text_digest,signed_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, consentId, actor.accountId, body.choice, body.textDigest, now()]); }
      catch (e) { if (e?.code === "23505") throw new CharterError("ALREADY_SIGNED", 409); throw e; }
      const all = (await db.query("SELECT account_id,choice FROM app_charter.consent_signatures WHERE tenant_id=$1 AND consent_id=$2", [tenantId, consentId])).rows;
      const outcome = consentOutcome({ eligible: c.eligible, consents: all.map((s) => ({ accountId: s.account_id, choice: s.choice })), threshold: { numerator: c.threshold_numerator, denominator: c.threshold_denominator } });
      if (outcome.passed && all.length && !(await db.query("SELECT 1 FROM app_charter.minute_entries WHERE tenant_id=$1 AND entry->>'kind'='consent' AND entry->>'text' LIKE $2", [tenantId, "%" + c.text_digest + "%"])).rows.length)
        await appendMinute(db, tenantId, actor, { kind: "consent", text: `Action by written consent adopted: “${c.title}”. Consents ${outcome.consents} of ${outcome.eligible} (${outcome.threshold}). Text digest ${c.text_digest}.` });
      return { choice: body.choice, outcome };
    }),

    declareInterest: (credentials, tenantId, body) => run(credentials, tenantId, MEMBERS, async (db, actor) => {
      const interest = parse(() => validateInterest(body), "INVALID_INTEREST");
      need(typeof body.subject === "string" && body.subject.trim() && body.subject.length <= 300, "INVALID_INTEREST");
      const id = randomUUID();
      await db.query("INSERT INTO app_charter.interests(tenant_id,id,account_id,interest,subject,recorded_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, id, actor.accountId, interest, body.subject.trim(), now()]);
      if (interest.recusal) await appendMinute(db, tenantId, actor, { kind: "recusal", text: `A member recused from “${body.subject.trim()}” after disclosing a ${interest.kind} interest.` });
      return { id, ...interest };
    }, { write: true }),
    interests: (credentials, tenantId) => run(credentials, tenantId, MANAGERS, async (db, actor) => {
      await log(db, tenantId, actor.accountId, "view-interests", "register");
      return { items: (await db.query("SELECT id,account_id,interest,subject,recorded_at FROM app_charter.interests WHERE tenant_id=$1 ORDER BY recorded_at DESC LIMIT 200", [tenantId])).rows
        .map((r) => ({ id: r.id, accountId: r.account_id, subject: r.subject, ...r.interest, recordedAt: iso(r.recorded_at) })) };
    }),
    /** Electorate for a matter after recusals under the organization's disclosed policy. */
    electorateFor: (credentials, tenantId, body) => run(credentials, tenantId, MANAGERS, async (db) => {
      const org = await organization(db, tenantId);
      need(UUID.test(body.snapshotId ?? "") && typeof body.subject === "string", "INVALID_ELECTORATE_REQUEST");
      const snap = (await db.query("SELECT snapshot FROM app_charter.record_snapshots WHERE tenant_id=$1 AND id=$2", [tenantId, body.snapshotId])).rows[0];
      need(snap, "SNAPSHOT_NOT_FOUND", 404);
      const recused = (await db.query("SELECT account_id FROM app_charter.interests WHERE tenant_id=$1 AND subject=$2 AND (interest->>'recusal')::boolean", [tenantId, body.subject])).rows.map((r) => r.account_id);
      return applyRecusals(snap.snapshot.members, recused, org.recusal_policy);
    }, { write: false }),

    minuteBook: (credentials, tenantId) => run(credentials, tenantId, MEMBERS, async (db, actor) => {
      const rows = (await db.query("SELECT sequence,entry,digest FROM app_charter.minute_entries WHERE tenant_id=$1 ORDER BY sequence", [tenantId])).rows;
      let previous = null, intact = true;
      for (const r of rows) {
        const { digest: stored, ...entry } = r.entry;
        if (entry.previousDigest !== previous || digest("charterquill-minute-entry-v1", entry) !== r.digest) intact = false;
        previous = r.digest;
      }
      await log(db, tenantId, actor.accountId, "view-minute-book", "minute-book");
      return { intact, entries: rows.map((r) => ({ sequence: r.sequence, ...r.entry })) };
    }),

    setSchedule: (credentials, tenantId, body) => run(credentials, tenantId, ["owner"], async (db, actor) => {
      const schedule = parse(() => validateSchedule(body), "INVALID_SCHEDULE");
      const version = Number((await db.query("SELECT COALESCE(max(version),0) AS v FROM app_charter.retention_schedules WHERE tenant_id=$1 AND record_class=$2", [tenantId, schedule.recordClass])).rows[0].v) + 1;
      await db.query("INSERT INTO app_charter.retention_schedules(tenant_id,record_class,version,schedule,recorded_by,recorded_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, schedule.recordClass, version, schedule, actor.accountId, now()]);
      return { ...schedule, version };
    }, { recent: true }),
    placeHold: (credentials, tenantId, body) => run(credentials, tenantId, ["owner", "admin"], async (db, actor) => {
      need(typeof body.name === "string" && body.name.trim() && body.name.length <= 200 && Array.isArray(body.recordClasses) && body.recordClasses.every((c) => RECORD_CLASSES.includes(c)), "INVALID_HOLD");
      const id = randomUUID();
      await db.query("INSERT INTO app_charter.legal_holds(tenant_id,id,name,record_classes,placed_by,placed_at) VALUES($1,$2,$3,$4,$5,$6)", [tenantId, id, body.name.trim(), body.recordClasses, actor.accountId, now()]);
      return { id };
    }, { recent: true }),
    releaseHold: (credentials, tenantId, holdId) => run(credentials, tenantId, ["owner"], async (db, actor) => {
      need(UUID.test(holdId), "INVALID_HOLD");
      need((await db.query("UPDATE app_charter.legal_holds SET released_by=$3,released_at=$4 WHERE tenant_id=$1 AND id=$2 AND released_at IS NULL RETURNING id", [tenantId, holdId, actor.accountId, now()])).rows.length, "HOLD_NOT_ACTIVE", 409);
      return { released: true };
    }, { recent: true }),
    records: (credentials, tenantId) => run(credentials, tenantId, ["owner", "admin"], async (db) => {
      const schedules = (await db.query("SELECT DISTINCT ON (record_class) schedule FROM app_charter.retention_schedules WHERE tenant_id=$1 ORDER BY record_class,version DESC", [tenantId])).rows.map((r) => r.schedule);
      const holds = (await db.query("SELECT id,name,record_classes,placed_at,released_at FROM app_charter.legal_holds WHERE tenant_id=$1 ORDER BY placed_at DESC", [tenantId])).rows
        .map((h) => ({ id: h.id, name: h.name, recordClasses: h.record_classes, placedAt: iso(h.placed_at), releasedAt: iso(h.released_at) }));
      const access = (await db.query("SELECT account_id,action,subject,at FROM app_charter.access_log WHERE tenant_id=$1 ORDER BY at DESC LIMIT 100", [tenantId])).rows
        .map((a) => ({ accountId: a.account_id, action: a.action, subject: a.subject, at: iso(a.at) }));
      const oldest = (await db.query("SELECT min(recorded_at) AS t FROM app_charter.minute_entries WHERE tenant_id=$1", [tenantId])).rows[0].t;
      const disposal = RECORD_CLASSES.map((recordClass) => ({ recordClass, ...disposalDecision({ recordClass, createdAt: oldest ?? now(), schedules, holds, now: clock() }) }));
      return { schedules, holds, access, disposal, note: "CharterQuill never deletes records automatically; disposal decisions are advisory and holds always prevail." };
    }, { write: false }),
  };
}

const ROUTES = [
  ["POST", /^organization$/, (s, c, t, b) => s.configure(c, t, b), ["entityType", "legalName", "jurisdiction", "recusalPolicy"], ["entityType", "legalName", "jurisdiction"]],
  ["GET", /^organization$/, (s, c, t) => s.profile(c, t)],
  ["POST", /^rules$/, (s, c, t, b) => s.setRule(c, t, b), ["id", "body", "matter", "reserved", "source", "authority", "rule", "requiresStages"], ["body", "matter", "source", "authority"]],
  ["POST", /^share-classes$/, (s, c, t, b) => s.addClass(c, t, b), ["id", "name", "votesPerShare", "scale"], ["id", "name"]],
  ["POST", /^register-imports$/, (s, c, t, b) => s.importRegister(c, t, b), ["csv"], ["csv"], 20_000_000],
  ["POST", /^snapshots$/, (s, c, t, b) => s.snapshot(c, t, b), ["recordDate"], ["recordDate"]],
  ["GET", /^snapshots$/, (s, c, t) => s.snapshots(c, t)],
  ["POST", /^meetings$/, (s, c, t, b) => s.scheduleMeeting(c, t, b), ["kind", "body", "title", "startsAt", "location", "remoteLink", "minimumNoticeDays", "agenda"], ["kind", "body", "title", "startsAt"], 65536],
  ["GET", /^meetings$/, (s, c, t) => s.meetings(c, t)],
  ["POST", /^meetings\/([a-f0-9-]{36})\/notices$/, (s, c, t, b, m) => s.recordNotice(c, t, m[1], b), ["recipientId", "method", "deliveredAt"]],
  ["GET", /^meetings\/([a-f0-9-]{36})\/notices$/, (s, c, t, b, m) => s.noticeStatus(c, t, m[1])],
  ["POST", /^meetings\/([a-f0-9-]{36})\/minutes$/, (s, c, t, b, m) => s.recordMinutes(c, t, m[1], b), ["text"], ["text"], 262144],
  ["POST", /^consents$/, (s, c, t, b) => s.openConsent(c, t, b), ["title", "body", "resolutionText", "eligible", "threshold", "hours"], ["title", "body", "resolutionText", "eligible", "hours"], 262144],
  ["GET", /^consents$/, (s, c, t) => s.consents(c, t)],
  ["POST", /^consents\/([a-f0-9-]{36})\/signatures$/, (s, c, t, b, m) => s.signConsent(c, t, m[1], b), ["choice", "textDigest"]],
  ["POST", /^interests$/, (s, c, t, b) => s.declareInterest(c, t, b), ["kind", "description", "counterparty", "recusal", "subject"], ["kind", "description", "subject"]],
  ["GET", /^interests$/, (s, c, t) => s.interests(c, t)],
  ["POST", /^electorates$/, (s, c, t, b) => s.electorateFor(c, t, b), ["snapshotId", "subject"]],
  ["GET", /^minute-book$/, (s, c, t) => s.minuteBook(c, t)],
  ["POST", /^retention$/, (s, c, t, b) => s.setSchedule(c, t, b), ["recordClass", "retainYears", "basis"], ["recordClass", "retainYears"]],
  ["POST", /^holds$/, (s, c, t, b) => s.placeHold(c, t, b), ["name", "recordClasses"]],
  ["POST", /^holds\/([a-f0-9-]{36})\/release$/, (s, c, t, b, m) => s.releaseHold(c, t, m[1]), []],
  ["GET", /^records$/, (s, c, t) => s.records(c, t)],
];

export function createCharterRoutes(service) {
  return async ({ request, url, credentials, write, method }) => {
    if (url.pathname === "/api/public/charter/catalog") {
      method(["GET"]);
      return { entityTypes: ENTITY_TYPES, recordClasses: RECORD_CLASSES, plans: CHARTER_CATALOG, defaults: CHARTER_SETTINGS_DEFAULTS };
    }
    const match = url.pathname.match(/^\/api\/workspaces\/([a-f0-9-]{36})\/charter\/(.+)$/);
    if (!match) return null;
    if (url.search) throw new HttpError(400, "INVALID_QUERY");
    const [, tenantId, rest] = match;
    const candidates = ROUTES.filter(([, pattern]) => pattern.test(rest));
    if (!candidates.length) throw new HttpError(404, "NOT_FOUND");
    method([...new Set(candidates.map(([verb]) => verb))]);
    const [verb, pattern, handler, allowed = [], required = allowed, limit = 16384] = candidates.find(([v]) => v === request.method);
    try {
      let body = {};
      if (verb !== "GET") { write(); body = await boundedJson(request, allowed, required, limit); }
      return await handler(service, credentials, tenantId, body, rest.match(pattern));
    } catch (cause) {
      if (cause instanceof CharterError) throw new HttpError(cause.status, cause.code.split(":")[0]);
      if (cause?.constructor?.name === "DocumentError" && Number.isInteger(cause.status)) throw new HttpError(cause.status, cause.code);
      throw cause;
    }
  };
}

export const charterExtension = defineExtension({
  id: "charter",
  migrations: [migration("001-charter.sql")],
  pagePaths: CHARTER_PAGES,
  createRoutes(services) {
    return [{ routes: createCharterRoutes(createCharterService(services)), bodyLimit: (path) => (path.endsWith("/charter/register-imports") ? 20_000_000 : path.includes("/charter/") ? 262144 : 16384) }];
  },
}, { engine: "^1.1.0", profile: "charter", capabilities: ["identity"], surfaces: ["routes", "migrations", "pages"] });
