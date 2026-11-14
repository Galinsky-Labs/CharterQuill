// Meetings, notices, written consents, conflicts and minute books.
export const MEETING_KINDS = Object.freeze(["regular", "special", "annual", "committee"]);
export const DELIVERY_METHODS = Object.freeze(["email", "in-app", "mail", "hand"]);
export const INTEREST_KINDS = Object.freeze(["financial", "employment", "family", "other"]);

const text = (v, max, name, optional = false) => {
  if (optional && (v === undefined || v === null || v === "")) return null;
  if (typeof v !== "string" || !v.trim() || v.length > max) throw new Error("Invalid " + name);
  return v.trim();
};
const instant = (v, name) => {
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) throw new Error("Invalid " + name);
  return new Date(v).toISOString();
};

export function validateMeeting(input, { now = Date.now() } = {}) {
  if (!MEETING_KINDS.includes(input.kind)) throw new Error("Invalid meeting kind");
  const startsAt = instant(input.startsAt, "start time");
  const noticeDays = input.minimumNoticeDays ?? 0;
  if (!Number.isSafeInteger(noticeDays) || noticeDays < 0 || noticeDays > 90) throw new Error("Invalid notice period");
  if (Date.parse(startsAt) < now) throw new Error("Meetings must be scheduled in the future");
  const agenda = Array.isArray(input.agenda) ? input.agenda.map((a, i) => ({
    order: i + 1, title: text(a.title, 300, "agenda item"),
    proposalId: a.proposalId && /^[a-f0-9-]{36}$/.test(a.proposalId) ? a.proposalId : null,
    body: a.body ? text(a.body, 60, "body") : null,
  })) : [];
  if (agenda.length > 100) throw new Error("Too many agenda items");
  return {
    kind: input.kind, body: text(input.body, 60, "governing body"), title: text(input.title, 300, "title"),
    startsAt, location: text(input.location, 300, "location", true), remoteLink: input.remoteLink ? new URL(input.remoteLink).href : null,
    minimumNoticeDays: noticeDays, agenda,
  };
}

/** Notice is sufficient only if every eligible recipient was notified in time. */
export function noticeCompliance({ startsAt, minimumNoticeDays, recipients, deliveries }) {
  const deadline = Date.parse(startsAt) - minimumNoticeDays * 86400000;
  const delivered = new Map();
  for (const d of deliveries) {
    const t = Date.parse(d.deliveredAt);
    if (t <= deadline && (!delivered.has(d.recipientId) || t < delivered.get(d.recipientId))) delivered.set(d.recipientId, t);
  }
  const missing = recipients.filter((r) => !delivered.has(r));
  return { compliant: missing.length === 0, deadline: new Date(deadline).toISOString(), notified: recipients.length - missing.length, of: recipients.length, missing };
}

/**
 * Written consent in lieu of a meeting: passes only when the required share
 * of eligible signatories consents to the exact frozen text. Unanimity is the
 * common default for boards.
 */
export function consentOutcome({ eligible, consents, threshold = { numerator: 1, denominator: 1 } }) {
  const valid = new Set(consents.filter((c) => eligible.includes(c.accountId) && c.choice === "consent").map((c) => c.accountId));
  const withheld = new Set(consents.filter((c) => eligible.includes(c.accountId) && c.choice === "withhold").map((c) => c.accountId));
  const passed = BigInt(valid.size) * BigInt(threshold.denominator) >= BigInt(eligible.length) * BigInt(threshold.numerator) && eligible.length > 0;
  return { passed, consents: valid.size, withheld: withheld.size, eligible: eligible.length, threshold: `${threshold.numerator}/${threshold.denominator} of eligible signatories` };
}

export function validateInterest(input) {
  if (!INTEREST_KINDS.includes(input.kind)) throw new Error("Invalid interest kind");
  return {
    kind: input.kind,
    description: text(input.description, 2000, "description"),
    counterparty: text(input.counterparty, 300, "counterparty", true),
    recusal: input.recusal === true,
  };
}

/**
 * Electorate after recusals. The disclosed policy decides whether recused
 * weight leaves the quorum denominator ("exclude") or stays as non-voting
 * presence ("count-for-quorum").
 */
export function applyRecusals(members, recusedIds, policy = "exclude") {
  if (!["exclude", "count-for-quorum"].includes(policy)) throw new Error("Invalid recusal policy");
  const recused = new Set(recusedIds);
  return {
    voters: members.filter((m) => !recused.has(m.principalId)),
    recused: members.filter((m) => recused.has(m.principalId)).map((m) => m.principalId),
    policy,
    statement: policy === "exclude" ? "Recused members are excluded from the electorate and from quorum." : "Recused members count toward quorum but cannot vote.",
  };
}

/** Minute book: an ordered, digest-chained record of meetings and actions. */
export function minuteEntry({ previousDigest, meetingId, kind, text: body, recordedAt }, digest) {
  if (!["minutes", "resolution", "consent", "notice", "recusal"].includes(kind)) throw new Error("Invalid minute entry kind");
  const entry = { meetingId, kind, text: text(body, 50000, "minutes"), recordedAt: instant(recordedAt, "time"), previousDigest: previousDigest ?? null };
  return { ...entry, digest: digest("charterquill-minute-entry-v1", entry) };
}
