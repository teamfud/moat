import type { Box, Policy, Target, Topology } from "../model";
import { buildRules, resolveBox } from "../plan";
import type { BlocksOutput, RulesOutput } from "./common";
import { fwdBlocks, fwdRules } from "./firewalld";
import { iptBlocks, iptRules } from "./iptables";
import { nftBlocks, nftRules } from "./nftables";
import { pfBlocks, pfRules } from "./pfsense";
import { psBlocks, psRules } from "./powershell";
import { ufwBlocks, ufwRules } from "./ufw";

export type { BlocksOutput, RulesOutput } from "./common";

/** Call checkTopology/checkBox first: this assumes the inputs passed. */
export function renderRules(box: Box, topo: Topology, policy: Policy, target: Target): RulesOutput {
  const rs = buildRules(box, topo, policy);
  switch (target) {
    case "powershell":
      return psRules(rs);
    case "nftables":
      return nftRules(rs);
    case "iptables":
      return iptRules(rs);
    case "ufw":
      return ufwRules(rs);
    case "firewalld":
      return fwdRules(rs);
    case "pfsense":
      return pfRules(rs);
  }
}

/** Call checkBlock on every ip first: this assumes they passed. */
export function renderBlocks(box: Box, topo: Topology, target: Target, ips: string[]): BlocksOutput {
  const rb = resolveBox(box, topo.team);
  switch (target) {
    case "powershell":
      return psBlocks(rb, ips);
    case "nftables":
      return nftBlocks(rb, ips);
    case "iptables":
      return iptBlocks(rb, ips);
    case "ufw":
      return ufwBlocks(rb, ips);
    case "firewalld":
      return fwdBlocks(rb, ips);
    case "pfsense":
      return pfBlocks(rb, ips, topo);
  }
}
