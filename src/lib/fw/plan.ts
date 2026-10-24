import datadog from "./datadog.json";
import { fill } from "./ip";
import type { Box, Policy, Proto, Topology } from "./model";
import { parsePorts, type PortRange } from "./ports";

export const DATADOG: { source: string; fetched: string; modified: string | null; ipv4: string[] } = datadog;

export type ResolvedBox = Box & { ip: string };

export type Allow = {
  label: string;
  proto: Proto;
  ports: PortRange[];
  /** Source CIDRs, or null for anywhere. */
  from: string[] | null;
  scored?: boolean;
  /** Required by the packet, can't be turned off in the UI. */
  forced?: boolean;
};

/** Everything a renderer needs, independent of the firewall it renders for. */
export type RuleSet = {
  box: ResolvedBox;
  policy: Policy;
  trusted: { cidr: string; why: string }[];
  datadog: string[];
  allows: Allow[];
};

export function resolveBox(box: Box, team: number): ResolvedBox {
  return { ...box, ip: fill(box.addr, team) };
}

export function resolveAll(topo: Topology) {
  return topo.boxes.map((b) => resolveBox(b, topo.team));
}

export function buildRules(box: Box, topo: Topology, policy: Policy): RuleSet {
  const t = topo.team;
  const sources = {
    any: null,
    admin: topo.adminSources.map((s) => fill(s, t)),
    scope: topo.scope.map((s) => fill(s, t)),
  };

  const allows: Allow[] = [];
  const add = (svc: Box["scored"][number], scored: boolean) => {
    const ports = svc.proto === "icmp" ? [] : parsePorts(svc.ports);
    if (typeof ports === "string") return; // guardrails report it
    // Scored services are always open to everyone: the scoring engine's IPs aren't known.
    allows.push({ label: svc.label, proto: svc.proto, ports, from: scored ? null : sources[svc.from], scored });
  };
  box.scored.forEach((s) => add(s, true));
  box.extra.forEach((s) => add(s, false));

  // Rule 14.vi: all traffic from barrier to timing on 514 must be allowed.
  if (topo.syslog && topo.syslog.to === box.name) {
    const from = topo.boxes.find((b) => b.name === topo.syslog!.from);
    const ports = parsePorts(topo.syslog.ports);
    if (from && typeof ports !== "string") {
      const src = [fill(from.addr, t)];
      const label = `syslog from ${from.name} (rule 14)`;
      allows.push({ label, proto: "tcp", ports, from: src, forced: true });
      allows.push({ label, proto: "udp", ports, from: src, forced: true });
    }
  }

  return {
    box: resolveBox(box, t),
    policy,
    trusted: topo.trusted.map((tr) => ({ cidr: fill(tr.cidr, t), why: tr.why })),
    datadog: DATADOG.ipv4,
    allows,
  };
}
