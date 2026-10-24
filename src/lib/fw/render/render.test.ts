import { describe, expect, it } from "vitest";
import { checkBox } from "../guardrails";
import { DEFAULT_POLICY, OS_TARGETS, type Topology } from "../model";
import { DATADOG } from "../plan";
import { IRSEC_2026 } from "../presets/irsec2026";
import { renderBlocks, renderRules } from "./index";

const topo: Topology = { ...IRSEC_2026, team: 3 };
const box = (name: string) => topo.boxes.find((b) => b.name === name)!;
const combos = topo.boxes.flatMap((b) => OS_TARGETS[b.os].map((t) => [b, t] as const));

describe("renderRules", () => {
  it.each(combos.map(([b, t]) => [b.name, t, b] as const))("%s × %s matches the snapshot", (_n, t, b) => {
    expect(checkBox(b, topo, t, DEFAULT_POLICY).filter((f) => f.level === "error")).toEqual([]);
    const out = renderRules(b, topo, DEFAULT_POLICY, t);
    expect(out.apply.body).toMatchSnapshot();
  });

  it.each(combos.filter(([b]) => b.os !== "pfsense").map(([b, t]) => [b.name, t, b] as const))(
    "%s × %s keeps the mgmt net, datadog and every scored port open",
    (_n, t, b) => {
      const body = renderRules(b, topo, DEFAULT_POLICY, t).apply.body;
      expect(body).toContain("172.16.1.0/24");
      expect(body).toContain(DATADOG.ipv4[0]);
      expect(body).toContain(DATADOG.ipv4.at(-1)!);
      for (const s of b.scored) {
        if (s.proto === "icmp") continue;
        for (const p of s.ports.split(",")) {
          const [lo, hi] = p.split("-");
          expect(body).toMatch(new RegExp(hi ? `${lo}[-:]${hi}` : `\\b${lo}\\b`));
        }
      }
      expect(body).toMatch(/rollback/);
    },
  );

  it("opens 514 from barrier on timing (rule 14.vi)", () => {
    for (const t of OS_TARGETS.ubuntu) {
      const body = renderRules(box("timing"), topo, DEFAULT_POLICY, t).apply.body;
      expect(body).toContain("10.3.1.254");
      expect(body).toMatch(/514/);
    }
  });

  it("restricts admin services to the admin sources", () => {
    const body = renderRules(box("scrutineering"), topo, DEFAULT_POLICY, "nftables").apply.body;
    expect(body).toContain('ip saddr { 10.3.1.0/24 } tcp dport { 22 } accept');
    expect(body).toContain('tcp dport { 3306 } accept comment "mariadb (scored)"');
  });

  it("uses the rollback minutes everywhere", () => {
    const p = { ...DEFAULT_POLICY, rollbackMinutes: 7 };
    expect(renderRules(box("pitlane"), topo, p, "nftables").apply.body).toContain("sleep 420");
    expect(renderRules(box("pitwall"), topo, p, "powershell").apply.body).toContain("AddMinutes(7)");
  });

  it("leaves logging off when asked", () => {
    const p = { ...DEFAULT_POLICY, logDrops: false };
    expect(renderRules(box("pitlane"), topo, p, "nftables").apply.body).not.toContain("log prefix");
    expect(renderRules(box("pitwall"), topo, p, "powershell").apply.body).not.toContain("LogBlocked True");
  });

  it("gives pfsense a checklist, not a script", () => {
    const out = renderRules(box("barrier"), topo, DEFAULT_POLICY, "pfsense");
    expect(out.apply.lang).toBe("text");
    expect(out.keep).toBeUndefined();
    expect(out.apply.body).toContain("192.168.3.4:514");
  });
});

describe("renderBlocks", () => {
  const ips = ["10.3.1.66", "6.6.6.6"];
  it.each(combos.map(([b, t]) => [b.name, t, b] as const))("%s × %s mentions every ip both ways", (_n, t, b) => {
    const out = renderBlocks(b, topo, t, ips);
    for (const ip of ips) {
      expect(out.block.body).toContain(ip);
      expect(out.unblock.body).toContain(ip);
    }
  });

  it("blocks lan ips on lan and the rest on wan in pfsense", () => {
    const body = renderBlocks(box("barrier"), topo, "pfsense", ips).block.body;
    expect(body).toContain("easyrule block lan 10.3.1.66");
    expect(body).toContain("easyrule block wan 6.6.6.6");
  });

  it("puts nft blocks in their own table", () => {
    expect(renderBlocks(box("pitlane"), topo, "nftables", ips).block.body).toContain("table inet fud_moat_block {");
  });
});
