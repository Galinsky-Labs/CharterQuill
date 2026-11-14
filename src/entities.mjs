// Entity rule profiles. Each rule names its source and authority; profiles
// are configurable defaults, never a jurisdiction-complete legality check.
const freeze = (v) => { Object.freeze(v); for (const x of Object.values(v)) if (x && typeof x === "object") freeze(x); return v; };

export const ENTITY_TYPES = freeze({
  corporation: {
    label: "Corporation", governingInstruments: ["certificate of incorporation", "bylaws"],
    bodies: ["board", "committee", "shareholders"],
    defaultRules: {
      board: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "2" }, approval: { basis: "participating", comparison: "gt", numerator: "1", denominator: "2" } },
      shareholders: { weighting: "units", quorum: { kind: "fraction-weight", numerator: "1", denominator: "2" }, approval: { basis: "participating", comparison: "gt", numerator: "1", denominator: "2" } },
    },
    reservedMatters: ["charter amendment", "merger or sale of substantially all assets", "dissolution", "new share class"],
  },
  llc: {
    label: "Limited liability company", governingInstruments: ["certificate of formation", "operating agreement"],
    bodies: ["managers", "members"],
    defaultRules: {
      managers: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "2" }, approval: { basis: "participating", comparison: "gt", numerator: "1", denominator: "2" } },
      members: { weighting: "units", quorum: { kind: "fraction-weight", numerator: "1", denominator: "2" }, approval: { basis: "eligible", comparison: "gt", numerator: "1", denominator: "2" } },
    },
    reservedMatters: ["admission of members", "amendment of the operating agreement", "dissolution"],
  },
  cooperative: {
    label: "Cooperative", governingInstruments: ["articles", "bylaws"],
    bodies: ["board", "members"],
    defaultRules: {
      board: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "2" }, approval: { basis: "participating", comparison: "gt", numerator: "1", denominator: "2" } },
      members: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "10" }, approval: { basis: "decisive", comparison: "gte", numerator: "2", denominator: "3" } },
    },
    reservedMatters: ["bylaw amendment", "patronage allocation policy", "dissolution"],
  },
  nonprofit: {
    label: "Nonprofit corporation", governingInstruments: ["articles of incorporation", "bylaws"],
    bodies: ["board", "committee", "members"],
    defaultRules: {
      board: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "2" }, approval: { basis: "participating", comparison: "gt", numerator: "1", denominator: "2" } },
      members: { weighting: "equal", quorum: { kind: "fraction-count", numerator: "1", denominator: "10" }, approval: { basis: "decisive", comparison: "gt", numerator: "1", denominator: "2" } },
    },
    reservedMatters: ["bylaw amendment", "election of directors", "dissolution"],
  },
});

const text = (v, max, name) => {
  if (typeof v !== "string" || !v.trim() || v.length > max) throw new Error("Invalid " + name);
  return v.trim();
};

/** A configured rule: source citation + authority + voting rule for one body. */
export function validateRule(input, entityType) {
  const entity = ENTITY_TYPES[entityType] ?? (() => { throw new Error("Unknown entity type"); })();
  if (!entity.bodies.includes(input.body)) throw new Error("Unknown governing body");
  const base = entity.defaultRules[input.body] ?? entity.defaultRules.board;
  const rule = input.rule ?? base;
  if (!["equal", "units"].includes(rule.weighting)) throw new Error("Invalid weighting");
  return {
    body: input.body,
    matter: text(input.matter, 300, "matter"),
    reserved: input.reserved === true,
    source: text(input.source, 300, "rule source"),
    authority: text(input.authority, 300, "authority"),
    rule: { weighting: rule.weighting, quorum: rule.quorum, approval: rule.approval, classRequirements: rule.classRequirements ?? [] },
    requiresStages: Array.isArray(input.requiresStages) ? input.requiresStages.map((s) => text(s, 60, "stage")) : [],
    disclaimer: "Configured by the organization from its governing documents; CharterQuill does not verify legal validity.",
  };
}
