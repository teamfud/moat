import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { zip } from "../zip";
import { bundle } from "./bundle";
import { DEFAULT_POLICY, type Topology } from "./model";
import { IRSEC_2026 } from "./presets/irsec2026";

const topo: Topology = { ...IRSEC_2026, team: 3 };

describe("bundle", () => {
  it("has a folder per box with its scripts", () => {
    const { entries, skipped } = bundle(topo, DEFAULT_POLICY, {});
    const dirs = new Set(entries.map((e) => e.path.split("/").slice(0, 2).join("/")));
    expect(dirs.size + skipped.length).toBe(topo.boxes.length);
    expect(entries.some((e) => e.path.endsWith("pitlane-rules.sh") && e.exec)).toBe(true);
    for (const e of entries) expect(e.path.split("/")).toHaveLength(3);
  });

  it("zips into something unzip reads back byte for byte, scripts executable", () => {
    const { entries } = bundle(topo, DEFAULT_POLICY, {});
    const dir = mkdtempSync(path.join(tmpdir(), "moat-zip-"));
    writeFileSync(path.join(dir, "all.zip"), zip(entries));
    execFileSync("unzip", ["-q", "all.zip"], { cwd: dir });
    for (const e of entries) {
      const f = path.join(dir, e.path);
      expect(readFileSync(f, "utf8")).toBe(e.text);
      if (e.exec) expect(statSync(f).mode & 0o111).not.toBe(0);
    }
  });
});
