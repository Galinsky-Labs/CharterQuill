// Applies engine migrations, then CharterQuill's, with the separate migration
// credential. Runtime role grants remain an administrator action.
import { databasePool } from "@distributed-governance/engine/runtime";
import { applyIdentityMigrations, pgTransactions } from "@distributed-governance/engine/identity";
import { applyExtensionMigrations } from "@distributed-governance/engine/platform";
import { charterExtension } from "../server/charter-extension.mjs";

let pool;
try {
  if (!process.env.MIGRATION_DATABASE_URL) throw Error("Migration credential required");
  pool = databasePool(process.env.MIGRATION_DATABASE_URL, { max: 1 });
  await applyIdentityMigrations(pgTransactions(pool));
  const { applied } = await applyExtensionMigrations(pgTransactions(pool), charterExtension);
  console.log("Engine and CharterQuill migrations verified/applied (" + applied + " new charter migrations).");
} catch {
  console.error("Migration failed; the transaction was rolled back. No credential details were logged.");
  process.exitCode = 1;
} finally {
  await pool?.end();
}
