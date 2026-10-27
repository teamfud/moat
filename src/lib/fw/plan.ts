import { fill } from "./ip";
import type { Box, Policy, Proto, Topology } from "./model";
import { parsePorts, type PortRange } from "./ports";

export type ResolvedBox = Box & { ip: string };

export type Allow = {
  label: string;
  proto: Proto;
  ports: PortRange[];
  /** Source CIDRs, or null for anywhere. */
  from: string[] | null;
  scored?: boolean;
};

/** Everything a renderer needs, independent of the firewall it renders for. */
export type RuleSet = {
  box: ResolvedBox;
  policy: Policy;
  /** Trusted ranges grouped by reason, so a long list is one rule, not hundreds. */
  trusted: { why: string; cidrs: string[] }[];
  /** Scope ranges plus admin sources: where outbound may go when it's restricted. */
  own: string[];
  allows: Allow[];
};

export function resolveBox(box: Box, team: number): ResolvedBox {
  return { ...box, ip: fill(box.addr, team) };
}

export function resolveAll(topo: Topology) {
  return topo.boxes.map((b) => resolveBox(b, topo.team));
}

function groupTrusted(topo: Topology, team: number) {
  const groups = new Map<string, string[]>();
  for (const tr of topo.trusted) groups.set(tr.why, [...(groups.get(tr.why) ?? []), fill(tr.cidr, team)]);
  return [...groups].map(([why, cidrs]) => ({ why, cidrs }));
}

export function buildRules(box: Box, topo: Topology, policy: Policy): RuleSet {
  const t = topo.team;
  const admin = topo.adminSources.map((s) => fill(s, t));
  // Admin sources count as in scope: behind nat, ur lan shows up as the router's outside ip.
  const own = [...new Set([...topo.scope.map((s) => fill(s, t)), ...admin])];
  const sources = { any: null, admin, scope: own };

  const allows: Allow[] = [];
  const add = (svc: Box["scored"][number], scored: boolean) => {
    const ports = svc.proto === "icmp" ? [] : parsePorts(svc.ports);
    if (typeof ports === "string") return; // guardrails report it
    // Scored services are always open to everyone: the scoring engine's IPs aren't known.
    allows.push({ label: svc.label, proto: svc.proto, ports, from: scored ? null : sources[svc.from], scored });
  };
  box.scored.forEach((s) => add(s, true));
  box.extra.forEach((s) => add(s, false));

  return {
    box: resolveBox(box, t),
    policy,
    trusted: groupTrusted(topo, t),
    own,
    allows,
  };
}

/** Every tcp port the box lets in, for spotting sessions on anything else. */
export const tcpPorts = (rs: RuleSet) => rs.allows.filter((a) => a.proto === "tcp").flatMap((a) => a.ports);
