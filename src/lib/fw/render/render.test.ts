import { describe, expect, it } from "vitest";
import { checkBox } from "../guardrails";
import { DEFAULT_POLICY, OS_TARGETS, type Topology } from "../model";
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
    "%s × %s keeps trusted ranges and every scored port open",
    (_n, t, b) => {
      const body = renderRules(b, topo, DEFAULT_POLICY, t).apply.body;
      expect(body).toContain("172.16.1.0/24");
      for (const t of topo.trusted) expect(body).toContain(t.cidr);
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

  it("opens syslog on timing to anyone, so barrier always gets through", () => {
    expect(renderRules(box("timing"), topo, DEFAULT_POLICY, "nftables").apply.body).toMatch(/^\s+tcp dport \{ 514 \} accept/m);
    expect(renderRules(box("timing"), topo, DEFAULT_POLICY, "ufw").apply.body).toContain("ufw allow proto udp from any to any port 514");
  });

  it("lets admin sources reach scope services too", () => {
    const body = renderRules(box("timing"), topo, DEFAULT_POLICY, "nftables").apply.body;
    expect(body).toContain("ip saddr { 10.3.1.0/24, 192.168.3.0/24, 172.20.1.3 } tcp dport { 1514-1515 } accept");
  });

  it("restricts admin services to the admin sources", () => {
    const body = renderRules(box("scrutineering"), topo, DEFAULT_POLICY, "nftables").apply.body;
    expect(body).toContain('ip saddr { 10.3.1.0/24, 172.20.1.3 } tcp dport { 22 } accept');
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
    expect(out.apply.body).toContain("172.16.1.0/24");
  });
});

describe("outbound", () => {
  const out = { ...DEFAULT_POLICY, restrictOutbound: true };
  const scripted = combos.filter(([b]) => b.os !== "pfsense");

  it.each(scripted.map(([b, t]) => [b.name, t, b] as const))("%s × %s leaves outbound open by default", (_n, t, b) => {
    const body = renderRules(b, topo, DEFAULT_POLICY, t).apply.body;
    expect(body).not.toMatch(/fud_moat_out \{|chain output|FUD_OUT$|deny outgoing|DefaultOutboundAction Block/m);
  });

  it.each(scripted.map(([b, t]) => [b.name, t, b] as const))("%s × %s lets trusted, own ranges and dns out when restricted", (_n, t, b) => {
    const body = renderRules(b, topo, out, t).apply.body;
    expect(body).toMatch(/fud_moat_out \{|chain output|ipt -I OUTPUT 1 -j FUD_OUT|deny outgoing|DefaultOutboundAction Block/);
    for (const c of ["172.16.1.0/24", "10.3.1.0/24", "192.168.3.0/24", "172.20.1.3"]) expect(body).toContain(c);
    expect(body).toMatch(/53/);
  });

  it("puts firewalld's outbound in its own nft table, and keep it re-applies it at boot", () => {
    const r = renderRules(box("scrutineering"), topo, out, "firewalld");
    expect(r.apply.body).toContain("table inet fud_moat_out {");
    expect(r.keep!.body).toContain("fud-moat.service");
  });
});

describe("check", () => {
  it.each(combos.filter(([b]) => b.os !== "pfsense").map(([b, t]) => [b.name, t, b] as const))("%s × %s snapshots on apply and compares on check", (_n, t, b) => {
    const r = renderRules(b, topo, DEFAULT_POLICY, t);
    expect(r.apply.body).toContain("expected.txt");
    expect(r.check!.body).toContain("expected.txt");
    expect(r.check!.body).toMatch(/open tcp sessions/);
    expect(r.apply.body).toMatch(/open tcp sessions/);
  });

  it("flags inbound sessions on ports the rules don't allow", () => {
    expect(renderRules(box("garage"), topo, DEFAULT_POLICY, "nftables").apply.body).toContain('awk -v ok="21 40000-50000 22"');
    expect(renderRules(box("pitwall"), topo, DEFAULT_POLICY, "powershell").apply.body).toContain("'49152-65535'");
  });
});

it("puts each trusted group in one windows rule", () => {
  const body = renderRules(box("pitwall"), topo, DEFAULT_POLICY, "powershell").apply.body;
  expect(body.match(/Allow 'fud-moat trusted: /g)).toHaveLength(2);
});

it("uses named, auto-merged nft sets for trusted groups", () => {
  const body = renderRules(box("pitlane"), topo, DEFAULT_POLICY, "nftables").apply.body;
  expect(body).toContain("set trusted_1 {");
  expect(body).toContain('ip saddr @trusted_1 accept comment "trusted: datadog"');
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
