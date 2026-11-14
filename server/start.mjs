// CharterQuill production entry: the shared engine runtime plus the charter extension.
import { runPlatform } from "@distributed-governance/engine/runtime";
import { charterExtension } from "./charter-extension.mjs";

await runPlatform({
  extensions: [charterExtension],
  env: { ...process.env, QUILL_PRODUCT: "charter" },
  assetDirectory: new URL("../dist/", import.meta.url),
});
