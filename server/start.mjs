// CharterQuill production entry: the shared engine runtime plus the charter
// extension and its enterprise integrations (each disabled unless configured).
// With MIGRATION_DATABASE_URL set, the release step migrates and provisions
// the least-privileged runtime login before serving.
import { releaseAndRun } from "@distributed-governance/engine/release";
import { charterExtension } from "./charter-extension.mjs";
import { createEnterpriseExtension } from "./enterprise-extension.mjs";

await releaseAndRun({
  extensions: [charterExtension, createEnterpriseExtension({ env: process.env })],
  env: { ...process.env, QUILL_PRODUCT: "charter" },
  assetDirectory: new URL("../dist/", import.meta.url),
});
