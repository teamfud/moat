import { contains, fill, parseCidr } from "../ip";
import type { Topology } from "../model";
import type { ResolvedBox, RuleSet } from "../plan";
import { header, script, type BlocksOutput, type RulesOutput } from "./common";

/**
 * pfSense only gets a checklist for hardening. Its NAT and pass rules are the
 * scored topology (rule 10), so a script rewriting them is how u lose uptime.
 */
export function pfRules(rs: RuleSet, topo: Topology): RulesOutput {
  const syslogTo = topo.syslog && topo.syslog.from === rs.box.name ? topo.boxes.find((b) => b.name === topo.syslog!.to) : undefined;
  const apply = `${header(rs.box, "pfsense", "checklist")}# barrier doesn't get a rules script: its nat + pass rules are the scored topology (rule 10).
# go through this in the webgui instead. ip blocks are on the quick block page.

[ ] firewall > rules > wan: look for pass rules with source "any" that weren't there at the start.
    disable them (don't delete, so u can show white team). leave the port forward rules alone.
[ ] firewall > nat > port forward: compare against the packet. don't change anything scored, ask white team.
[ ] firewall > rules > lan: the anti-lockout rule and "default allow lan to any" should be the only defaults.
[ ] system > advanced > admin access: webgui and ssh not reachable from wan. ssh key-only if u keep it on.
[ ] system > user manager: unknown users or keys? check them (don't touch whiteteam, rule 6).
[ ] diagnostics > command prompt / ssh: \`pfctl -sr | head -50\` to see what's actually loaded.
${
  syslogTo
    ? `[ ] status > system logs > settings: remote logging to ${fill(syslogTo.addr, topo.team)}:${topo.syslog!.ports} stays on, and the syslog-ng service keeps running (rule 14.vi).\n`
    : ""
}[ ] trusted ranges must never be blocked: ${rs.trusted.map((t) => t.cidr).join(", ")}. neither can any datadog ip (rule 14.v).
`;
  return {
    apply: script(rs.box, "pfsense", "checklist", apply, "text"),
    notes: ["pfctl-only changes are wiped on the next filter reload, so blocks use easyrule, which writes them into config.xml"],
  };
}

/** easyrule blocks on the interface the traffic arrives on: lan for the lan range, wan for everything else. */
export function pfBlocks(box: ResolvedBox, ips: string[], topo: Topology): BlocksOutput {
  // barrier's own address tells us which scope range is behind its lan port
  const self = parseCidr(box.ip);
  const lan = topo.scope.map((s) => parseCidr(fill(s, topo.team))).find((c) => c && self && contains(c, self));
  const iface = (ip: string) => {
    const c = parseCidr(ip);
    return lan && c && contains(lan, c) ? "lan" : "wan";
  };
  const lines = (verb: "block" | "unblock") => ips.map((ip) => `easyrule ${verb} ${iface(ip)} ${ip}`).join("\n");
  const head = (action: string) => `${header(box, "pfsense", action)}# run from the pfsense shell (option 8) or diagnostics > command prompt.
`;
  return {
    block: script(box, "pfsense", "block", `${head("block")}${lines("block")}\n# kill their open states\n${ips.map((ip) => `pfctl -k ${ip}`).join("\n")}\n`),
    unblock: script(box, "pfsense", "unblock", `${head("unblock")}${lines("unblock")}\n`),
    notes: [
      "lan-range ips get blocked on lan, everything else on wan. if ur cloud range sits on another interface (opt1…), change the name",
      "easyrule writes to config.xml, so blocks survive reboots and filter reloads",
    ],
  };
}
