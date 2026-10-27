import { OS_TARGETS, type Box, type From, type Os, type Proto, type Service, type Topology } from "./model";

// Imported JSON comes from a teammate's export or a hand edit, so check every field.

const isStr = (v: unknown): v is string => typeof v === "string";
const OSES = Object.keys(OS_TARGETS) as Os[];
const PROTOS: Proto[] = ["tcp", "udp", "icmp"];
const FROMS: From[] = ["any", "admin", "scope"];

function service(v: unknown, where: string): Service {
  const s = v as Partial<Service>;
  if (!s || !isStr(s.label) || !PROTOS.includes(s.proto as Proto) || !isStr(s.ports ?? "")) throw new Error(`${where} is broken`);
  return { label: s.label, proto: s.proto as Proto, ports: s.ports ?? "", from: FROMS.includes(s.from as From) ? (s.from as From) : "any" };
}

function box(v: unknown, i: number): Box {
  const b = v as Partial<Box>;
  if (!b || !isStr(b.name) || !b.name.trim()) throw new Error(`box #${i + 1} has no name`);
  if (!isStr(b.addr)) throw new Error(`${b.name} has no address`);
  if (!OSES.includes(b.os as Os)) throw new Error(`${b.name} has an unknown os "${String(b.os)}"`);
  return {
    id: isStr(b.id) && b.id ? b.id : `${b.name}-${i}`,
    name: b.name.trim(),
    addr: b.addr.trim(),
    os: b.os as Os,
    scored: (Array.isArray(b.scored) ? b.scored : []).map((s, j) => service(s, `${b.name} scored service #${j + 1}`)),
    extra: (Array.isArray(b.extra) ? b.extra : []).map((s, j) => service(s, `${b.name} extra service #${j + 1}`)),
    docker: b.docker === true,
    notes: isStr(b.notes) ? b.notes : "",
  };
}

/** Throws with a readable message if `v` isn't a topology. */
export function parseTopology(v: unknown): Topology {
  const t = v as Partial<Topology>;
  if (!t || typeof t !== "object") throw new Error("that's not a topology");
  if (!Array.isArray(t.boxes)) throw new Error("no boxes in there");
  const strs = (a: unknown, what: string) => {
    if (!Array.isArray(a) || !a.every(isStr)) throw new Error(`${what} should be a list of ranges`);
    return a as string[];
  };
  const trusted = Array.isArray(t.trusted) ? t.trusted : [];
  if (!trusted.every((x) => x && isStr(x.cidr) && isStr(x.why))) throw new Error("trusted ranges are broken");
  return {
    name: isStr(t.name) ? t.name : "imported",
    team: Number.isInteger(t.team) ? (t.team as number) : 1,
    scope: strs(t.scope ?? [], "scope"),
    trusted,
    adminSources: strs(t.adminSources ?? [], "admin sources"),
    blockOutOfScope: t.blockOutOfScope === "never" ? "never" : "ask",
    boxes: t.boxes.map(box),
  };
}
