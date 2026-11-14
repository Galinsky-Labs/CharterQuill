// CharterQuill production entry: the shared engine runtime plus the civic
// extension. With MIGRATION_DATABASE_URL set, the release step migrates and
// provisions the least-privileged runtime login before serving.
import { releaseAndRun } from "@distributed-governance/engine/release";
import { charterExtension } from "./charter-extension.mjs";

await releaseAndRun({
  extensions: [charterExtension],
  env: { ...process.env, QUILL_PRODUCT: "charter" },
  assetDirectory: new URL("../dist/", import.meta.url),
});
