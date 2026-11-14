// Retention schedules and legal holds. A hold always wins over a schedule.
export const RECORD_CLASSES = Object.freeze(["minutes", "resolutions", "consents", "ballots", "drafts", "access-logs", "exports"]);

export function validateSchedule(input) {
  if (!RECORD_CLASSES.includes(input.recordClass)) throw new Error("Invalid record class");
  const years = input.retainYears;
  if (!(years === null || (Number.isSafeInteger(years) && years >= 1 && years <= 100))) throw new Error("Retention must be 1–100 years or permanent");
  return { recordClass: input.recordClass, retainYears: years, basis: String(input.basis ?? "").slice(0, 300) || "Organization policy" };
}

/** Whether a record may be disposed of at `now`. */
export function disposalDecision({ recordClass, createdAt, schedules, holds, now = Date.now() }) {
  const activeHold = holds.find((h) => !h.releasedAt && (h.recordClasses.length === 0 || h.recordClasses.includes(recordClass)));
  if (activeHold) return { dispose: false, reason: "legal-hold", holdId: activeHold.id };
  const schedule = schedules.find((s) => s.recordClass === recordClass);
  if (!schedule || schedule.retainYears === null) return { dispose: false, reason: "permanent-retention" };
  const due = new Date(createdAt);
  due.setUTCFullYear(due.getUTCFullYear() + schedule.retainYears);
  return due.getTime() <= now ? { dispose: true, reason: "retention-period-elapsed" } : { dispose: false, reason: "retention-period-running", until: due.toISOString() };
}

export const CHARTER_SETTINGS_DEFAULTS = Object.freeze({
  "documents.privacyDefault": "private",
  "anchoring.enabled": false,
  "votes.defaultWeighting": "units",
  "quota.weeklyFreeDocuments": 0,
  "billing.model": "organization-seats",
});
export const CHARTER_CATALOG = Object.freeze([
  { id: "charter-team", kind: "subscription", interval: "month", resource: "seats", quantity: 10, label: "Team — 10 seats" },
  { id: "charter-organization", kind: "subscription", interval: "year", resource: "seats", quantity: 50, label: "Organization — 50 seats" },
  { id: "charter-enterprise", kind: "enterprise-license", resource: "seats", quantity: null, label: "Enterprise — contracted seats" },
]);
