import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { it } from "vitest";
import { DEFAULT_POLICY, OS_TARGETS, type Script } from "../model";
import { IRSEC_2026 } from "../presets/irsec2026";
import { renderBlocks, renderRules } from "./index";

// Writes every preset script to $MOAT_DUMP for the live tests in test/live.
// Rollback is 1 min so the tests don't wait forever.
it.skipIf(!process.env.MOAT_DUMP)("dumps every script", () => {
  const dir = process.env.MOAT_DUMP!;
  mkdirSync(dir, { recursive: true });
  const topo = { ...IRSEC_2026, team: 3 };
  const save = (name: string, s: Script) => writeFileSync(path.join(dir, `${name}.${s.lang === "powershell" ? "ps1" : s.lang === "text" ? "txt" : "sh"}`), s.body);
  for (const b of topo.boxes) {
    for (const t of OS_TARGETS[b.os]) {
      const r = renderRules(b, topo, { ...DEFAULT_POLICY, rollbackMinutes: 1 }, t);
      save(`${b.name}.${t}.apply`, r.apply);
      if (r.keep) save(`${b.name}.${t}.keep`, r.keep);
      if (r.undo) save(`${b.name}.${t}.undo`, r.undo);
      if (r.check) save(`${b.name}.${t}.check`, r.check);
      const out = renderRules(b, topo, { ...DEFAULT_POLICY, rollbackMinutes: 1, restrictOutbound: true }, t);
      save(`${b.name}.${t}.out.apply`, out.apply);
      if (out.check) save(`${b.name}.${t}.out.check`, out.check);
      const bl = renderBlocks(b, topo, t, ["10.3.1.66", "6.6.6.6"]);
      save(`${b.name}.${t}.block`, bl.block);
      save(`${b.name}.${t}.unblock`, bl.unblock);
    }
  }
});
