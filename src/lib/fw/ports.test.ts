import { describe, expect, it } from "vitest";
import { chunkPorts, parsePorts } from "./ports";

describe("ports", () => {
  it("parses lists and ranges", () => {
    expect(parsePorts("22")).toEqual([[22, 22]]);
    expect(parsePorts("80, 443,49152-65535")).toEqual([[80, 80], [443, 443], [49152, 65535]]);
    expect(parsePorts("3268:3269")).toEqual([[3268, 3269]]);
  });

  it("rejects junk", () => {
    expect(parsePorts("")).toBeTypeOf("string");
    expect(parsePorts("0")).toBeTypeOf("string");
    expect(parsePorts("70000")).toBeTypeOf("string");
    expect(parsePorts("200-100")).toBeTypeOf("string");
    expect(parsePorts("ssh")).toBeTypeOf("string");
  });

  it("chunks to 15 slots, ranges cost 2", () => {
    const many = Array.from({ length: 20 }, (_, i) => [i + 1, i + 1] as [number, number]);
    expect(chunkPorts(many).map((c) => c.length)).toEqual([15, 5]);
    const ranges = Array.from({ length: 8 }, (_, i) => [i * 10 + 1, i * 10 + 5] as [number, number]);
    expect(chunkPorts(ranges).map((c) => c.length)).toEqual([7, 1]);
  });
});
