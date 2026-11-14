import React, { useEffect, useState } from "react";
import { createAccountAPI } from "@distributed-governance/engine/web/account-api.mjs";

const api = createAccountAPI();
const explain = (e) => ({
  AUTHENTICATION_REQUIRED: "Sign in to continue.",
  ACCESS_DENIED: "Your role in this organization does not allow this action.",
  REAUTHENTICATION_REQUIRED: "Sign in again: this action needs a recent sign-in.",
  ORGANIZATION_NOT_CONFIGURED: "Set up the organization profile first.",
  HOLDER_NOT_A_MEMBER: "Every holder must already be a member of this workspace.",
  CONSENT_TEXT_CHANGED: "The resolution text changed; review the current text before signing.",
}[e?.code] ?? "The request could not be completed (" + (e?.code ?? "error") + "). Nothing was assumed to succeed.");

function useOrganization() {
  const [workspaces, setWorkspaces] = useState([]);
  const [tenantId, setTenantId] = useState("");
  const [profile, setProfile] = useState(null);
  const [status, setStatus] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => { api("/api/workspaces?limit=100").then((r) => { setWorkspaces(r.items); setTenantId(r.items[0]?.tenantId ?? ""); }).catch((e) => setStatus(explain(e))); }, []);
  useEffect(() => {
    if (!tenantId) return;
    api("/api/workspaces/" + tenantId + "/charter/organization").then(setProfile).catch((e) => { setProfile(null); if (e.code !== "ORGANIZATION_NOT_CONFIGURED") setStatus(explain(e)); });
  }, [tenantId, refresh]);
  const role = workspaces.find((w) => w.tenantId === tenantId)?.role;
  const call = (path, options) => api("/api/workspaces/" + tenantId + "/charter/" + path, options);
  const picker = (
    <label>Organization workspace
      <select value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
        {!workspaces.length && <option value="">No workspaces yet</option>}
        {workspaces.map((w) => <option key={w.tenantId} value={w.tenantId}>Workspace {w.tenantId.slice(0, 8)} · {w.role}</option>)}
      </select>
    </label>
  );
  return { tenantId, role, profile, picker, call, status, setStatus, reload: () => setRefresh((n) => n + 1) };
}
const Status = ({ children }) => <p role="status" aria-live="polite" className="console-status">{children}</p>;

export function OrganizationPage() {
  const org = useOrganization();
  const [setup, setSetup] = useState({ entityType: "corporation", legalName: "", jurisdiction: "", recusalPolicy: "exclude" });
  const [rule, setRule] = useState({ body: "board", matter: "", source: "", authority: "", reserved: false });
  const [cls, setCls] = useState({ id: "", name: "", votesPerShare: "1" });
  const act = async (fn, done) => { try { await fn(); org.setStatus(done); org.reload(); } catch (e) { org.setStatus(explain(e)); } };
  return (
    <>
      <section className="console-card"><div className="console-form">{org.picker}</div><Status>{org.status}</Status></section>
      {!org.profile ? (
        <form className="console-card" onSubmit={(e) => { e.preventDefault(); act(() => org.call("organization", { method: "POST", body: setup }), "Organization configured."); }}>
          <h2>Organization profile</h2>
          <div className="console-form">
            <label>Entity type<select value={setup.entityType} onChange={(e) => setSetup({ ...setup, entityType: e.target.value })}>
              <option value="corporation">Corporation</option><option value="llc">LLC</option><option value="cooperative">Cooperative</option><option value="nonprofit">Nonprofit</option></select></label>
            <label>Legal name<input required value={setup.legalName} onChange={(e) => setSetup({ ...setup, legalName: e.target.value })} /></label>
            <label>Jurisdiction of formation<input required value={setup.jurisdiction} onChange={(e) => setSetup({ ...setup, jurisdiction: e.target.value })} /></label>
            <label>Recused members<select value={setup.recusalPolicy} onChange={(e) => setSetup({ ...setup, recusalPolicy: e.target.value })}>
              <option value="exclude">Leave the electorate and quorum</option><option value="count-for-quorum">Count toward quorum only</option></select></label>
          </div>
          <button disabled={org.role !== "owner"}>Save profile</button>
        </form>
      ) : (
        <>
          <section className="console-card"><h2>{org.profile.legalName}</h2>
            <p>{org.profile.entity.label} · {org.profile.jurisdiction} · governing instruments: {org.profile.entity.governingInstruments.join(", ")}</p>
            <h3>Governing rules</h3>
            {org.profile.rules.length ? <table className="console-table"><thead><tr><th scope="col">Matter</th><th scope="col">Body</th><th scope="col">Rule</th><th scope="col">Source</th></tr></thead>
              <tbody>{org.profile.rules.map((r) => <tr key={r.id}><td>{r.matter}{r.reserved ? " (reserved)" : ""}</td><td>{r.body}</td>
                <td>{r.rule.weighting === "units" ? "By voting units" : "One vote per person"}; approval {r.rule.approval.numerator}/{r.rule.approval.denominator} of {r.rule.approval.basis}{r.rule.classRequirements.length ? "; class approvals: " + r.rule.classRequirements.map((c) => c.class).join(", ") : ""}</td>
                <td>{r.source} — {r.authority}</td></tr>)}</tbody></table> : <p>No rules recorded. Defaults for {org.profile.entity.label.toLowerCase()} bodies apply until you record them.</p>}
            <p className="console-notice">Rules are configured from your governing documents. CharterQuill applies them exactly but does not verify their legal validity.</p>
          </section>
          <form className="console-card" onSubmit={(e) => { e.preventDefault(); act(() => org.call("rules", { method: "POST", body: rule }), "Rule recorded as a new version."); }}>
            <h2>Record a governing rule</h2>
            <div className="console-form">
              <label>Body<select value={rule.body} onChange={(e) => setRule({ ...rule, body: e.target.value })}>{org.profile.entity.bodies.map((b) => <option key={b}>{b}</option>)}</select></label>
              <label>Matter<input required value={rule.matter} onChange={(e) => setRule({ ...rule, matter: e.target.value })} /></label>
              <label>Source (article, section)<input required value={rule.source} onChange={(e) => setRule({ ...rule, source: e.target.value })} /></label>
              <label>Authority<input required value={rule.authority} onChange={(e) => setRule({ ...rule, authority: e.target.value })} /></label>
              <label className="console-check"><input type="checkbox" checked={rule.reserved} onChange={(e) => setRule({ ...rule, reserved: e.target.checked })} /> Reserved matter</label>
            </div><button>Record rule</button>
          </form>
          <form className="console-card" onSubmit={(e) => { e.preventDefault(); act(() => org.call("share-classes", { method: "POST", body: cls }), "Class added."); }}>
            <h2>Share and unit classes</h2>
            <ul>{org.profile.classes.map((c) => <li key={c.id}>{c.name} ({c.id}) — {c.voting ? c.votesPerShare + " vote(s) per share" : "non-voting"}</li>)}</ul>
            <div className="console-form">
              <label>Class ID<input required pattern="[a-z][a-z0-9-]{0,39}" value={cls.id} onChange={(e) => setCls({ ...cls, id: e.target.value })} /></label>
              <label>Name<input required value={cls.name} onChange={(e) => setCls({ ...cls, name: e.target.value })} /></label>
              <label>Votes per share<input required inputMode="numeric" pattern="[0-9]+" value={cls.votesPerShare} onChange={(e) => setCls({ ...cls, votesPerShare: e.target.value })} /></label>
            </div><button>Add class</button>
          </form>
        </>
      )}
    </>
  );
}

export function RegisterPage() {
  const org = useOrganization();
  const [csv, setCsv] = useState("");
  const [recordDate, setRecordDate] = useState("");
  const [snapshots, setSnapshots] = useState([]);
  const [latest, setLatest] = useState(null);
  const load = () => org.tenantId && org.call("snapshots").then((r) => setSnapshots(r.items)).catch(() => {});
  useEffect(load, [org.tenantId]);
  return (
    <>
      <form className="console-card" onSubmit={async (e) => { e.preventDefault(); try { const r = await org.call("register-imports", { method: "POST", body: { csv } }); org.setStatus(r.rows + " register rows recorded."); setCsv(""); } catch (err) { org.setStatus(explain(err)); } }}>
        <h2>Import register positions</h2>
        <p>CSV columns: <code>holder_account_id,class_id,quantity,effective_date[,beneficial_owner_ref]</code>. Quantities are exact; precision beyond the class scale is rejected, never rounded. Each row records the holder's position from its effective date.</p>
        <div className="console-form">{org.picker}
          <label>Register file<input type="file" accept=".csv,text/csv" onChange={async (e) => e.target.files[0] && setCsv(await e.target.files[0].text())} /></label>
        </div>
        <textarea aria-label="Register CSV" rows={6} value={csv} onChange={(e) => setCsv(e.target.value)} style={{ width: "100%" }} />
        <button disabled={!csv}>Record positions</button>
        <Status>{org.status}</Status>
      </form>
      <form className="console-card" onSubmit={async (e) => { e.preventDefault(); try { setLatest(await org.call("snapshots", { method: "POST", body: { recordDate } })); load(); } catch (err) { org.setStatus(explain(err)); } }}>
        <h2>Record-date snapshot</h2>
        <p>Freezes voting units per holder and class at the record date. Transfers dated later never change a snapshot already taken.</p>
        <div className="console-form"><label>Record date<input type="date" required value={recordDate} onChange={(e) => setRecordDate(e.target.value)} /></label></div>
        <button>Take snapshot</button>
        {latest && <dl className="console-facts"><dt>Digest</dt><dd><code>{latest.digest}</code></dd>
          {Object.entries(latest.totals).map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v.shares} share units · {v.votes} voting units</dd></React.Fragment>)}</dl>}
        {snapshots.length > 0 && <ul>{snapshots.map((s) => <li key={s.id}>{s.recordDate} — <code>{s.digest.slice(0, 16)}…</code></li>)}</ul>}
      </form>
    </>
  );
}

export function MeetingsPage() {
  const org = useOrganization();
  const [meetings, setMeetings] = useState([]);
  const [form, setForm] = useState({ kind: "regular", body: "board", title: "", startsAt: "", minimumNoticeDays: 2, agenda: "" });
  const [compliance, setCompliance] = useState({});
  const [minutes, setMinutes] = useState({});
  const load = () => org.tenantId && org.call("meetings").then((r) => setMeetings(r.items)).catch(() => {});
  useEffect(load, [org.tenantId]);
  const check = async (id) => { try { setCompliance({ ...compliance, [id]: await org.call("meetings/" + id + "/notices") }); } catch (e) { org.setStatus(explain(e)); } };
  return (
    <>
      <form className="console-card" onSubmit={async (e) => {
        e.preventDefault();
        try {
          await org.call("meetings", { method: "POST", body: { ...form, minimumNoticeDays: Number(form.minimumNoticeDays), startsAt: new Date(form.startsAt).toISOString(),
            agenda: form.agenda.split("\n").map((t) => t.trim()).filter(Boolean).map((title) => ({ title })) } });
          org.setStatus("Meeting scheduled."); load();
        } catch (err) { org.setStatus(explain(err)); }
      }}>
        <h2>Schedule a meeting</h2>
        <div className="console-form">{org.picker}
          <label>Kind<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="regular">Regular</option><option value="special">Special</option><option value="annual">Annual</option><option value="committee">Committee</option></select></label>
          <label>Body<select value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })}>{(org.profile?.entity.bodies ?? ["board"]).map((b) => <option key={b}>{b}</option>)}</select></label>
          <label>Title<input required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></label>
          <label>Starts<input type="datetime-local" required value={form.startsAt} onChange={(e) => setForm({ ...form, startsAt: e.target.value })} /></label>
          <label>Minimum notice (days)<input type="number" min={0} max={90} value={form.minimumNoticeDays} onChange={(e) => setForm({ ...form, minimumNoticeDays: e.target.value })} /></label>
          <label>Agenda (one item per line)<textarea rows={3} value={form.agenda} onChange={(e) => setForm({ ...form, agenda: e.target.value })} /></label>
        </div><button>Schedule</button><Status>{org.status}</Status>
      </form>
      {meetings.map((m) => (
        <section key={m.id} className="console-card">
          <h2>{m.title} <span className="console-pill">{m.status}</span></h2>
          <p>{m.kind} {m.body} meeting · {new Date(m.startsAt).toLocaleString()} · notice at least {m.minimumNoticeDays} day(s)</p>
          {m.agenda.length > 0 && <ol>{m.agenda.map((a) => <li key={a.order}>{a.title}</li>)}</ol>}
          <button onClick={() => check(m.id)}>Check notice compliance</button>
          {compliance[m.id] && <p>{compliance[m.id].compliant ? "Notice requirements met" : "Notice incomplete"}: {compliance[m.id].notified} of {compliance[m.id].of} notified by {new Date(compliance[m.id].deadline).toLocaleString()}.</p>}
          <label>Minutes<textarea rows={4} value={minutes[m.id] ?? ""} onChange={(e) => setMinutes({ ...minutes, [m.id]: e.target.value })} style={{ width: "100%" }} /></label>
          <button disabled={!minutes[m.id]} onClick={async () => { try { await org.call("meetings/" + m.id + "/minutes", { method: "POST", body: { text: minutes[m.id] } }); org.setStatus("Minutes added to the minute book."); load(); } catch (e) { org.setStatus(explain(e)); } }}>Record minutes</button>
        </section>
      ))}
    </>
  );
}

export function ConsentsPage() {
  const org = useOrganization();
  const [items, setItems] = useState([]);
  const [members, setMembers] = useState([]);
  const [form, setForm] = useState({ title: "", body: "board", resolutionText: "", eligible: [], hours: 168, unanimous: true });
  const load = () => org.tenantId && org.call("consents").then((r) => setItems(r.items)).catch(() => {});
  useEffect(() => { load(); if (org.tenantId) api("/api/workspaces/" + org.tenantId + "/members?limit=100").then((r) => setMembers(r.items)).catch(() => setMembers([])); }, [org.tenantId]);
  const sign = async (c, choice) => { try { await org.call("consents/" + c.id + "/signatures", { method: "POST", body: { choice, textDigest: c.textDigest } }); load(); } catch (e) { org.setStatus(explain(e)); } };
  return (
    <>
      <form className="console-card" onSubmit={async (e) => {
        e.preventDefault();
        try {
          await org.call("consents", { method: "POST", body: { title: form.title, body: form.body, resolutionText: form.resolutionText, eligible: form.eligible, hours: Number(form.hours), threshold: form.unanimous ? { numerator: 1, denominator: 1 } : { numerator: 2, denominator: 3 } } });
          org.setStatus("Written consent opened."); load();
        } catch (err) { org.setStatus(explain(err)); }
      }}>
        <h2>Action by written consent</h2>
        <p>Signatories consent to the exact text shown. Any change to the text requires a new consent.</p>
        <div className="console-form">{org.picker}
          <label>Title<input required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></label>
          <label>Body<input required value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} /></label>
          <label>Open for (hours)<input type="number" min={1} max={2160} value={form.hours} onChange={(e) => setForm({ ...form, hours: e.target.value })} /></label>
          <label className="console-check"><input type="checkbox" checked={form.unanimous} onChange={(e) => setForm({ ...form, unanimous: e.target.checked })} /> Require unanimity (otherwise two-thirds)</label>
        </div>
        <label>Resolution text<textarea required rows={5} value={form.resolutionText} onChange={(e) => setForm({ ...form, resolutionText: e.target.value })} style={{ width: "100%" }} /></label>
        <fieldset className="console-fieldset"><legend>Eligible signatories</legend>
          {members.map((m) => <label key={m.accountId} className="console-check"><input type="checkbox" checked={form.eligible.includes(m.accountId)}
            onChange={(e) => setForm({ ...form, eligible: e.target.checked ? [...form.eligible, m.accountId] : form.eligible.filter((x) => x !== m.accountId) })} /> {m.displayName ?? m.accountId.slice(0, 8)} ({m.role})</label>)}
        </fieldset>
        <button disabled={!form.eligible.length}>Open consent</button><Status>{org.status}</Status>
      </form>
      {items.map((c) => (
        <section key={c.id} className="console-card">
          <h2>{c.title} <span className="console-pill">{c.outcome.passed ? "Adopted" : c.open ? "Open" : "Closed"}</span></h2>
          <blockquote>{c.resolutionText}</blockquote>
          <p>{c.outcome.consents} consent · {c.outcome.withheld} withheld · {c.outcome.eligible} eligible ({c.outcome.threshold}) · text digest <code>{c.textDigest.slice(0, 16)}…</code></p>
          {c.eligibleToSign && !c.myChoice && c.open && <p><button onClick={() => sign(c, "consent")}>I consent to this exact text</button> <button onClick={() => sign(c, "withhold")}>Withhold consent</button></p>}
          {c.myChoice && <p>Your response: {c.myChoice}</p>}
        </section>
      ))}
    </>
  );
}

export function ConflictsPage() {
  const org = useOrganization();
  const [form, setForm] = useState({ kind: "financial", description: "", counterparty: "", subject: "", recusal: true });
  const [items, setItems] = useState(null);
  const load = () => org.tenantId && ["owner", "admin"].includes(org.role) && org.call("interests").then((r) => setItems(r.items)).catch(() => setItems(null));
  useEffect(load, [org.tenantId, org.role]);
  return (
    <>
      <form className="console-card" onSubmit={async (e) => { e.preventDefault(); try { await org.call("interests", { method: "POST", body: { ...form, counterparty: form.counterparty || undefined } }); org.setStatus("Disclosure recorded" + (form.recusal ? " and recusal noted in the minute book." : ".")); load(); } catch (err) { org.setStatus(explain(err)); } }}>
        <h2>Disclose an interest</h2>
        <p>Disclosures are visible to organization managers only. Recusal removes you from the electorate for that matter under the organization's disclosed policy. Software records do not by themselves create legal privilege.</p>
        <div className="console-form">{org.picker}
          <label>Kind<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="financial">Financial</option><option value="employment">Employment</option><option value="family">Family</option><option value="other">Other</option></select></label>
          <label>Matter<input required value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} /></label>
          <label>Counterparty (optional)<input value={form.counterparty} onChange={(e) => setForm({ ...form, counterparty: e.target.value })} /></label>
          <label>Description<textarea required value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
          <label className="console-check"><input type="checkbox" checked={form.recusal} onChange={(e) => setForm({ ...form, recusal: e.target.checked })} /> Recuse from this matter</label>
        </div><button>Record disclosure</button><Status>{org.status}</Status>
      </form>
      {items && <section className="console-card"><h2>Interest register</h2>
        <table className="console-table"><thead><tr><th scope="col">Matter</th><th scope="col">Kind</th><th scope="col">Member</th><th scope="col">Recusal</th></tr></thead>
          <tbody>{items.map((i) => <tr key={i.id}><td>{i.subject}</td><td>{i.kind}</td><td>{i.accountId.slice(0, 8)}</td><td>{i.recusal ? "Yes" : "No"}</td></tr>)}</tbody></table></section>}
    </>
  );
}

export function MinuteBookPage() {
  const org = useOrganization();
  const [book, setBook] = useState(null);
  useEffect(() => { if (org.tenantId) org.call("minute-book").then(setBook).catch((e) => org.setStatus(explain(e))); }, [org.tenantId]);
  return (
    <section className="console-card"><div className="console-form">{org.picker}</div><Status>{org.status}</Status>
      {book && <>
        <p className={book.intact ? "" : "console-notice"}>{book.intact ? "Every entry's digest chain verifies." : "WARNING: the minute book's digest chain does not verify."}</p>
        <ol>{book.entries.map((e) => <li key={e.sequence}><strong>{e.kind}</strong> · {new Date(e.recordedAt).toLocaleString()}<p>{e.text}</p><small><code>{e.digest}</code></small></li>)}</ol>
      </>}
    </section>
  );
}

export function RecordsPage() {
  const org = useOrganization();
  const [data, setData] = useState(null);
  const [hold, setHold] = useState({ name: "", recordClasses: [] });
  const [schedule, setSchedule] = useState({ recordClass: "minutes", retainYears: 7 });
  const load = () => org.tenantId && org.call("records").then(setData).catch((e) => org.setStatus(explain(e)));
  useEffect(load, [org.tenantId]);
  const act = async (fn, done) => { try { await fn(); org.setStatus(done); load(); } catch (e) { org.setStatus(explain(e)); } };
  const classes = ["minutes", "resolutions", "consents", "ballots", "drafts", "access-logs", "exports"];
  return (
    <>
      <section className="console-card"><div className="console-form">{org.picker}</div><Status>{org.status}</Status>
        {data && <><h2>Retention and disposal</h2><p>{data.note}</p>
          <table className="console-table"><thead><tr><th scope="col">Record class</th><th scope="col">Status</th></tr></thead>
            <tbody>{data.disposal.map((d) => <tr key={d.recordClass}><td>{d.recordClass}</td><td>{d.reason}{d.until ? " until " + d.until.slice(0, 10) : ""}</td></tr>)}</tbody></table></>}
      </section>
      <form className="console-card" onSubmit={(e) => { e.preventDefault(); act(() => org.call("retention", { method: "POST", body: { ...schedule, retainYears: Number(schedule.retainYears) } }), "Schedule recorded."); }}>
        <h2>Retention schedule</h2>
        <div className="console-form">
          <label>Record class<select value={schedule.recordClass} onChange={(e) => setSchedule({ ...schedule, recordClass: e.target.value })}>{classes.map((c) => <option key={c}>{c}</option>)}</select></label>
          <label>Retain (years)<input type="number" min={1} max={100} value={schedule.retainYears} onChange={(e) => setSchedule({ ...schedule, retainYears: e.target.value })} /></label>
        </div><button>Save schedule</button>
      </form>
      <form className="console-card" onSubmit={(e) => { e.preventDefault(); act(() => org.call("holds", { method: "POST", body: hold }), "Legal hold placed."); }}>
        <h2>Legal holds</h2>
        {data?.holds.map((h) => <p key={h.id}>{h.name} — {h.recordClasses.join(", ") || "all records"} · {h.releasedAt ? "released " + h.releasedAt.slice(0, 10) : <button type="button" onClick={() => act(() => org.call("holds/" + h.id + "/release", { method: "POST", body: {} }), "Hold released.")}>Release</button>}</p>)}
        <div className="console-form">
          <label>Name<input required value={hold.name} onChange={(e) => setHold({ ...hold, name: e.target.value })} /></label>
          <fieldset className="console-fieldset"><legend>Record classes (none selected = all)</legend>
            {classes.map((c) => <label key={c} className="console-check"><input type="checkbox" checked={hold.recordClasses.includes(c)} onChange={(e) => setHold({ ...hold, recordClasses: e.target.checked ? [...hold.recordClasses, c] : hold.recordClasses.filter((x) => x !== c) })} /> {c}</label>)}
          </fieldset>
        </div><button>Place hold</button>
      </form>
      {data && <section className="console-card"><h2>Access log</h2><ul>{data.access.map((a, i) => <li key={i}>{a.at.slice(0, 19).replace("T", " ")} · {a.action} · {a.accountId.slice(0, 8)}</li>)}</ul></section>}
    </>
  );
}

export const charterPages = [
  { path: "/charter/organization", title: "Organization", nav: "Governance", Component: OrganizationPage, description: "Entity profile, governing rules with their sources, and share or unit classes." },
  { path: "/charter/register", title: "Register and record dates", nav: "Governance", Component: RegisterPage },
  { path: "/charter/meetings", title: "Meetings and notices", nav: "Governance", Component: MeetingsPage },
  { path: "/charter/consents", title: "Written consents", nav: "Governance", Component: ConsentsPage },
  { path: "/charter/conflicts", title: "Conflicts and recusals", nav: "Governance", Component: ConflictsPage },
  { path: "/charter/minute-book", title: "Minute book", nav: "Records", Component: MinuteBookPage },
  { path: "/charter/records", title: "Retention and legal holds", nav: "Records", Component: RecordsPage },
];
