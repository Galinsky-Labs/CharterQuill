// Share and unit ledger: exact fixed-point quantities, classes with voting
// multipliers independent of economic rights, and record-date snapshots.
import { shareUnits } from "./index.mjs";

const CLASS_ID = /^[a-z][a-z0-9-]{0,39}$/;

export function validateShareClass(input) {
  if (!CLASS_ID.test(input.id ?? "")) throw new Error("Invalid class identifier");
  const multiplier = input.votesPerShare ?? "1";
  if (typeof multiplier !== "string" || !/^(0|[1-9][0-9]{0,8})$/.test(multiplier)) throw new Error("Votes per share must be a whole number");
  if (typeof input.name !== "string" || !input.name.trim() || input.name.length > 120) throw new Error("Invalid class name");
  return { id: input.id, name: input.name.trim(), votesPerShare: multiplier, scale: input.scale ?? 6, voting: multiplier !== "0" };
}

/**
 * Parses a holder register CSV: holder_account_id,class_id,quantity,effective_date[,beneficial_owner_ref]
 * Every row is validated; the whole import fails on the first bad row.
 */
export function parseRegisterCsv(text, classes, { maxRows = 100000 } = {}) {
  if (typeof text !== "string" || text.length > 20_000_000) throw new Error("Register too large");
  const known = new Map(classes.map((c) => [c.id, c]));
  const lines = text.replace(/\r\n/g, "\n").split("\n").filter((l) => l.trim());
  const header = lines.shift()?.split(",").map((h) => h.trim());
  if (header?.join(",") !== "holder_account_id,class_id,quantity,effective_date" && header?.join(",") !== "holder_account_id,class_id,quantity,effective_date,beneficial_owner_ref")
    throw new Error("Unexpected register header");
  if (lines.length > maxRows) throw new Error("Too many register rows");
  return lines.map((line, i) => {
    const [holder, classId, quantity, effective, beneficial] = line.split(",").map((v) => v.trim());
    const where = " on row " + (i + 2);
    if (!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(holder)) throw new Error("Invalid holder" + where);
    const cls = known.get(classId);
    if (!cls) throw new Error("Unknown class" + where);
    let units;
    try { units = shareUnits(quantity, cls.scale); } catch { throw new Error("Invalid quantity" + where); }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(effective) || Number.isNaN(Date.parse(effective + "T00:00:00Z"))) throw new Error("Invalid effective date" + where);
    if (beneficial !== undefined && beneficial !== "" && !/^[A-Za-z0-9._:-]{1,120}$/.test(beneficial)) throw new Error("Invalid beneficial owner reference" + where);
    return { holderAccountId: holder, classId, units, effectiveDate: effective, beneficialOwnerRef: beneficial || null };
  });
}

/**
 * Positions at a record date: the latest entry per (holder, class) effective
 * on or before the date. Voting units = shares × class votes-per-share.
 * Transfers dated after the record date never affect the snapshot.
 */
export function recordDateSnapshot(entries, classes, recordDate) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(recordDate)) throw new Error("Invalid record date");
  const byClass = new Map(classes.map((c) => [c.id, c]));
  const latest = new Map();
  for (const e of entries) {
    if (e.effectiveDate > recordDate) continue;
    const key = e.holderAccountId + "|" + e.classId;
    const prior = latest.get(key);
    if (!prior || e.effectiveDate > prior.effectiveDate || (e.effectiveDate === prior.effectiveDate && e.sequence > prior.sequence)) latest.set(key, e);
  }
  const positions = [...latest.values()].filter((e) => BigInt(e.units) > 0n).sort((a, b) => (a.holderAccountId + a.classId).localeCompare(b.holderAccountId + b.classId));
  const totals = {};
  const members = positions.map((p) => {
    const cls = byClass.get(p.classId);
    const votes = (BigInt(p.units) * BigInt(cls.votesPerShare)).toString();
    const t = (totals[p.classId] ??= { shares: 0n, votes: 0n });
    t.shares += BigInt(p.units); t.votes += BigInt(votes);
    return { principalId: p.holderAccountId, class: p.classId, shares: p.units, votingUnits: votes, beneficialOwnerRef: p.beneficialOwnerRef ?? null };
  });
  return {
    recordDate,
    members: members.filter((m) => m.votingUnits !== "0"),
    nonVoting: members.filter((m) => m.votingUnits === "0").length,
    totals: Object.fromEntries(Object.entries(totals).map(([k, v]) => [k, { shares: v.shares.toString(), votes: v.votes.toString() }])),
    note: "Ownership does not by itself create equal voting rights across classes; each class's votes-per-share is applied.",
  };
}
