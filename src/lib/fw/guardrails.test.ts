import { describe, expect, it } from "vitest";
import { checkBlock, checkBox, checkTopology } from "./guardrails";
import { DEFAULT_POLICY, type Topology } from "./model";
import { IRSEC_2026 } from "./presets/irsec2026";

const topo: Topology = { ...IRSEC_2026, team: 3, trusted: [{ cidr: "172.16.1.0/24", why: "management network" }] };
const box = (name: string) => topo.boxes.find((b) => b.name === name)!;

describe("checkBlock", () => {
  it("refuses subnets", () => {
    const v = checkBlock("10.3.1.0/24", topo);
    expect(v.level).toBe("error");
    expect(v.msg).toContain("single ips only");
    expect(checkBlock("6.6.6.0/31", topo).level).toBe("error");
  });

  it("refuses trusted ranges", () => {
    const v = checkBlock("172.16.1.5", topo);
    expect(v.level).toBe("error");
    expect(v.msg).toContain("management network");
  });

  it("refuses our own boxes, including barrier and timing", () => {
    expect(checkBlock("10.3.1.254", topo).msg).toContain("barrier");
    expect(checkBlock("192.168.3.4", topo).msg).toContain("timing");
  });

  it("refuses junk and non-hosts", () => {
    expect(checkBlock("nope", topo).level).toBe("error");
    expect(checkBlock("127.0.0.1", topo).level).toBe("error");
    expect(checkBlock("224.0.0.1", topo).level).toBe("error");
  });

  it("allows a rogue in-scope ip, warns on out of scope", () => {
    expect(checkBlock("10.3.1.66", topo)).toMatchObject({ level: "ok", ip: "10.3.1.66" });
    expect(checkBlock("10.3.1.66/32", topo)).toMatchObject({ level: "ok", ip: "10.3.1.66" });
    expect(checkBlock("6.6.6.6", topo)).toMatchObject({ level: "warn", ip: "6.6.6.6" });
    // another team's lan is out of scope too
    expect(checkBlock("10.4.1.5", topo).level).toBe("warn");
  });
});

describe("checkTopology", () => {
  it("passes the preset", () => {
    expect(checkTopology(topo)).toEqual([]);
  });

  it("catches duplicates and broken ranges", () => {
    const bad: Topology = {
      ...topo,
      scope: ["10.{x}.1.5/24"],
      boxes: [...topo.boxes, { ...box("pitlane"), id: "dupe" }],
    };
    const msgs = checkTopology(bad).map((f) => f.msg);
    expect(msgs.some((m) => m.includes("both claim 10.3.1.4"))).toBe(true);
    expect(msgs.some((m) => m.includes('2 boxes called "pitlane"'))).toBe(true);
    expect(msgs.some((m) => m.includes("scope range"))).toBe(true);
  });

  it("nudges u to add trusted ranges", () => {
    expect(checkTopology({ ...topo, trusted: [] })).toContainEqual(expect.objectContaining({ level: "warn", msg: expect.stringContaining("no trusted ranges") }));
    expect(checkTopology({ ...topo, trusted: [], boxes: [] })).toEqual([]);
  });
});

describe("checkBox", () => {
  it("passes clean preset boxes", () => {
    expect(checkBox(box("pitlane"), topo, "nftables", DEFAULT_POLICY)).toEqual([]);
    expect(checkBox(box("pitwall"), topo, "powershell", DEFAULT_POLICY)).toEqual([]);
  });

  it("errors on a target that doesn't run on the os", () => {
    expect(checkBox(box("pitwall"), topo, "ufw", DEFAULT_POLICY).some((f) => f.level === "error")).toBe(true);
  });

  it("errors on broken scored ports", () => {
    const b = { ...box("pitlane"), scored: [{ label: "ssh", proto: "tcp" as const, ports: "twenty-two", from: "any" as const }] };
    const f = checkBox(b, topo, "nftables", DEFAULT_POLICY);
    expect(f).toContainEqual(expect.objectContaining({ level: "error", msg: expect.stringContaining("ssh") }));
  });

  it("warns on docker boxes", () => {
    expect(checkBox(box("grandstand"), topo, "ufw", DEFAULT_POLICY)).toContainEqual(expect.objectContaining({ level: "warn", msg: expect.stringContaining("docker") }));
  });

  it("bounds the rollback timer", () => {
    expect(checkBox(box("pitlane"), topo, "nftables", { ...DEFAULT_POLICY, rollbackMinutes: 0 }).some((f) => f.level === "error")).toBe(true);
  });
});
