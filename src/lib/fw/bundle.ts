import type { ZipEntry } from "../zip";
import { checkBox, checkTopology } from "./guardrails";
import { targetFor, type Policy, type Target, type Topology } from "./model";
import { renderRules } from "./render";

/** Box names end up in paths: keep them to one plain path segment. */
const safe = (name: string) => name.replace(/[^\w.-]+/g, "-").replace(/^\.+/, "_");

export const bundleName = (topo: Topology) => `fud-moat-${topo.name.replace(/\W+/g, "-")}`;

/**
 * Every box's scripts, one folder per box, for scp-ing over instead of pasting
 * (terminals and editors mangle big pastes). Boxes with errors are skipped.
 */
export function bundle(topo: Topology, policy: Policy, targets: Record<string, Target>): { entries: ZipEntry[]; skipped: string[] } {
  const root = bundleName(topo);
  const blocked = checkTopology(topo).some((f) => f.level === "error");
  const entries: ZipEntry[] = [];
  const skipped: string[] = [];

  for (const box of topo.boxes) {
    const target = targetFor(box, targets);
    if (blocked || checkBox(box, topo, target, policy).some((f) => f.level === "error")) {
      skipped.push(box.name);
      continue;
    }
    const out = renderRules(box, topo, policy, target);
    const dir = `${root}/${safe(box.name)}`;
    for (const s of [out.apply, out.keep, out.check, out.undo]) {
      if (s) entries.push({ path: `${dir}/${safe(s.filename)}`, text: s.body, exec: s.lang === "sh" });
    }
  }
  return { entries, skipped };
}
