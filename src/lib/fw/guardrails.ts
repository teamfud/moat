import { contains, fill, formatIp, parseCidr, type Cidr } from "./ip";
import { OS_TARGETS, type Box, type Policy, type Target, type Topology } from "./model";
import { parsePorts } from "./ports";

export type Finding = { level: "error" | "warn"; msg: string };

const err = (msg: string): Finding => ({ level: "error", msg });
const warn = (msg: string): Finding => ({ level: "warn", msg });

const cidrs = (templates: string[], team: number) =>
  templates.map((s) => parseCidr(fill(s, team))).filter((c): c is Cidr => c !== null);

/** Problems with the topology as a whole. Errors here block every script. */
export function checkTopology(topo: Topology): Finding[] {
  const out: Finding[] = [];
  if (!Number.isInteger(topo.team) || topo.team < 0 || topo.team > 255) out.push(err(`team number ${topo.team} doesn't fit in an ip`));

  const ranges = [
    ...topo.scope.map((s) => ["scope range", s] as const),
    ...topo.trusted.map((s) => ["trusted range", s.cidr] as const),
    ...topo.adminSources.map((s) => ["admin source", s] as const),
  ];
  for (const [what, s] of ranges) {
    if (!parseCidr(fill(s, topo.team))) out.push(err(`${what} "${s}" isn't an ip or cidr`));
  }

  const names = new Map<string, number>();
  const ips = new Map<string, string>();
  for (const b of topo.boxes) {
    names.set(b.name, (names.get(b.name) ?? 0) + 1);
    const ip = fill(b.addr, topo.team);
    const other = ips.get(ip);
    if (other) out.push(err(`${b.name} and ${other} both claim ${ip}`));
    ips.set(ip, b.name);
  }
  for (const [n, count] of names) if (count > 1) out.push(err(`there are ${count} boxes called "${n}"`));

  if (topo.boxes.length && topo.trusted.length === 0) {
    out.push(warn("no trusted ranges. if ur comp has a management, scoring or monitoring network, add it so it never gets blocked"));
  }
  return out;
}

/** Problems generating rules for one box. Errors block that box's script. */
export function checkBox(box: Box, topo: Topology, target: Target, policy: Policy): Finding[] {
  const out: Finding[] = [];
  const ip = parseCidr(fill(box.addr, topo.team));
  if (!ip || ip.prefix !== 32) out.push(err(`address "${box.addr}" isn't a single ip`));
  else if (!cidrs(topo.scope, topo.team).some((s) => contains(s, ip))) out.push(warn(`${formatIp(ip.base)} is outside ur scope ranges`));

  if (!OS_TARGETS[box.os].includes(target)) out.push(err(`${target} doesn't run on ${box.os}`));

  for (const s of [...box.scored, ...box.extra]) {
    if (s.proto === "icmp") continue;
    const p = parsePorts(s.ports);
    if (typeof p === "string") out.push(err(`${s.label}: ${p}`));
  }

  if (!Number.isInteger(policy.rollbackMinutes) || policy.rollbackMinutes < 1 || policy.rollbackMinutes > 60) {
    out.push(err("rollback timer has to be 1-60 minutes"));
  }

  if (box.os === "pfsense") return out;

  if (box.scored.length === 0) out.push(warn("no scored services. everything inbound gets dropped except trusted ranges and extras"));
  if (topo.adminSources.length === 0 && box.extra.some((s) => s.from === "admin")) {
    out.push(warn("no admin sources set, so admin services (rdp, ssh, …) end up unreachable"));
  }
  if (box.docker) {
    out.push(
      warn(
        target === "firewalld"
          ? "docker box on firewalld: container ports skip these rules and ip blocks don't reach containers. use nftables or iptables for this box"
          : "docker publishes container ports through forward, not input, so the allowlist doesn't cover them (ip blocks do). unpublish what u don't need in compose",
      ),
    );
  }
  return out;
}

export type BlockVerdict = { input: string; ip: string | null; level: "ok" | "warn" | "error"; msg: string };

/** Can this address be blocked safely? */
export function checkBlock(input: string, topo: Topology): BlockVerdict {
  const raw = input.trim();
  const c = parseCidr(raw);
  const v = (level: BlockVerdict["level"], msg: string, ip: string | null = null): BlockVerdict => ({ input: raw, ip, level, msg });
  if (!c) return v("error", "not an ipv4 address");
  if (c.prefix < 32) return v("error", `${raw} is a subnet. single ips only: subnet blocks take out scoring and teammates, and most comps ban them`);

  const ip = formatIp(c.base);
  const first = c.base >>> 24;
  if (first === 0 || first === 127 || first >= 224) return v("error", "not a real host address");

  for (const tr of topo.trusted) {
    const t = parseCidr(fill(tr.cidr, topo.team));
    if (t && contains(t, c)) return v("error", `${ip} is in a trusted range (${tr.why}). never block it`);
  }

  const own = topo.boxes.find((b) => fill(b.addr, topo.team) === ip);
  if (own) return v("error", `that's ${own.name}, ur own box`);

  if (!cidrs(topo.scope, topo.team).some((s) => contains(s, c))) {
    return v("warn", "outside ur scope ranges. lots of comps ban blocking out of scope ips, so check the rules or ask white team first", ip);
  }
  return v("ok", "single in-scope ip, good to block", ip);
}
