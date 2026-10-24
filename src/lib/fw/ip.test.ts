import { describe, expect, it } from "vitest";
import { cidrToString, contains, fill, formatIp, parseCidr, parseIp } from "./ip";

describe("ip", () => {
  it("parses and formats addresses", () => {
    expect(parseIp("10.3.1.4")).toBe(0x0a030104);
    expect(formatIp(parseIp("255.255.255.255")!)).toBe("255.255.255.255");
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-1", "a.b.c.d", "1.2.3.4x", "01234.1.1.1"]) {
      expect(parseIp(bad)).toBeNull();
    }
  });

  it("treats a bare ip as a /32 and rejects host bits", () => {
    expect(parseCidr("1.2.3.4")).toEqual({ base: parseIp("1.2.3.4"), prefix: 32 });
    expect(parseCidr("10.3.1.0/24")?.prefix).toBe(24);
    expect(parseCidr("10.3.1.5/24")).toBeNull();
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("0.0.0.0/0")).toEqual({ base: 0, prefix: 0 });
    expect(cidrToString(parseCidr("10.3.1.4/32")!)).toBe("10.3.1.4");
  });

  it("checks containment", () => {
    const lan = parseCidr("10.3.1.0/24")!;
    expect(contains(lan, parseCidr("10.3.1.200")!)).toBe(true);
    expect(contains(lan, parseCidr("10.3.2.1")!)).toBe(false);
    expect(contains(lan, parseCidr("10.3.0.0/16")!)).toBe(false);
    expect(contains(parseCidr("0.0.0.0/0")!, lan)).toBe(true);
  });

  it("fills the team number", () => {
    expect(fill("10.{x}.1.4", 12)).toBe("10.12.1.4");
    expect(fill("192.168.{x}.0/24", 3)).toBe("192.168.3.0/24");
  });
});
