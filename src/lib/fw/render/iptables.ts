import { chunkPorts, formatRange } from "../ports";
import type { Allow, ResolvedBox, RuleSet } from "../plan";
import {
  blockPrelude,
  cancelTimer,
  DIR,
  editBlockList,
  installUnit,
  killSessions,
  READ_BLOCKED,
  safe,
  script,
  shPrelude,
  startTimer,
  writeFile,
  type BlocksOutput,
  type RulesOutput,
} from "./common";

const comment = (s: string) => `-m comment --comment "${safe(s)}"`;

export function iptAllow(a: Allow): string[] {
  const label = `${a.label}${a.scored ? " (scored)" : ""}`;
  const srcs = a.from ?? [null];
  const out: string[] = [];
  for (const src of srcs) {
    const s = src ? `-s ${src} ` : "";
    if (a.proto === "icmp") {
      out.push(`ipt -A FUD_IN ${s}-p icmp --icmp-type echo-request -j ACCEPT ${comment(label)}`);
      continue;
    }
    for (const chunk of chunkPorts(a.ports)) {
      const ports = chunk.map((r) => formatRange(r, ":")).join(",");
      const match = chunk.length === 1 && chunk[0][0] === chunk[0][1] ? `--dport ${ports}` : `-m multiport --dports ${ports}`;
      out.push(`ipt -A FUD_IN ${s}-p ${a.proto} ${match} -j ACCEPT ${comment(label)}`);
    }
  }
  return out;
}

export function iptRulesSh(rs: RuleSet) {
  return `#!/bin/sh
# fud moat rules for ${rs.box.name}: chain FUD_IN, jumped to first from INPUT
set -eu
ipt() { iptables -w "$@"; }
ipt -N FUD_IN 2>/dev/null || true
ipt -F FUD_IN
ipt -A FUD_IN -i lo -j ACCEPT
ipt -A FUD_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A FUD_IN -m conntrack --ctstate INVALID -j DROP
${rs.trusted.map((t) => `ipt -A FUD_IN -s ${t.cidr} -j ACCEPT ${comment(`trusted: ${t.why}`)}`).join("\n")}
${rs.allows.flatMap(iptAllow).join("\n")}
${rs.policy.logDrops ? `ipt -A FUD_IN -m limit --limit 10/s -j LOG --log-prefix "fud-moat drop: "\n` : ""}ipt -A FUD_IN -j DROP
while ipt -D INPUT -j FUD_IN 2>/dev/null; do :; done
ipt -I INPUT 1 -j FUD_IN
# blocks go back on top of FUD_IN
if [ -f ${DIR}/blocks.sh ]; then sh ${DIR}/blocks.sh; fi`;
}

const ROLLBACK = `#!/bin/sh
# fud moat rollback: removes FUD_IN. ip blocks (FUD_BLOCK) stay.
B=${DIR}
while iptables -w -D INPUT -j FUD_IN 2>/dev/null; do :; done
iptables -w -F FUD_IN 2>/dev/null || true
iptables -w -X FUD_IN 2>/dev/null || true
rm -f "$B/rules.sh" "$B/rules.pending.sh" "$B/rollback.pid"
echo "✓ rolled back fud moat rules on $(hostname)"`;

export function iptRules(rs: RuleSet): RulesOutput {
  const apply = `${shPrelude(rs, "iptables", `command -v iptables >/dev/null 2>&1 || { echo "✗ iptables not found"; exit 1; }`)}
${writeFile("$B/rollback.sh", ROLLBACK)}
${writeFile("$B/rules.pending.sh", iptRulesSh(rs))}
sh "$B/rules.pending.sh"
${startTimer(rs.policy.rollbackMinutes)}`;

  const keep = `#!/bin/sh
# fud moat · ${rs.box.name} · keep it: cancel the rollback and re-apply at boot
set -eu
${cancelTimer}if [ -f "$B/rules.pending.sh" ]; then mv "$B/rules.pending.sh" "$B/rules.sh"; fi
${installUnit}`;

  const undo = `#!/bin/sh
# fud moat · ${rs.box.name} · undo: remove fud moat rules now (ip blocks stay)
${cancelTimer}sh "$B/rollback.sh"
`;

  const notes = [
    "ipv4 only. ip6tables is untouched",
    "FUD_IN is jumped to first, so anything red team left lower in INPUT never sees traffic. check `iptables -S` for other tables (nat, mangle) though",
  ];
  if (rs.box.docker) notes.push("container ports go through FORWARD / DOCKER-USER, not INPUT, so they stay reachable. ip blocks cover DOCKER-USER too");
  return {
    apply: script(rs.box, "iptables", "rules", apply),
    keep: script(rs.box, "iptables", "keep", keep),
    undo: script(rs.box, "iptables", "undo", undo),
    notes,
  };
}

/** Rebuilds FUD_BLOCK from blocked.txt and pins it to the top of every chain that matters. */
export const IPT_BLOCKS_SH = (chains: string) => `#!/bin/sh
# fud moat ip blocks, rebuilt from ${DIR}/blocked.txt
set -eu
ipt() { iptables -w "$@"; }
ipt -N FUD_BLOCK 2>/dev/null || true
ipt -F FUD_BLOCK
for ip in $(${READ_BLOCKED}); do
  ipt -A FUD_BLOCK -s "$ip" -j DROP
  ipt -A FUD_BLOCK -d "$ip" -j DROP
done
for c in ${chains}; do
  ipt -n -L "$c" >/dev/null 2>&1 || continue
  while ipt -D "$c" -j FUD_BLOCK 2>/dev/null; do :; done
  ipt -I "$c" 1 -j FUD_BLOCK
done
echo "✓ $(${READ_BLOCKED} | grep -c . || true) ip(s) blocked on $(hostname)"`;

export function iptBlocks(box: ResolvedBox, ips: string[]): BlocksOutput {
  const body = (action: "block" | "unblock") => `${blockPrelude(box, "iptables", action, ips)}${editBlockList(ips, action)}${writeFile(
    "$B/blocks.sh",
    IPT_BLOCKS_SH("INPUT OUTPUT FORWARD DOCKER-USER"),
  )}sh "$B/blocks.sh"
${action === "block" ? killSessions(ips) : ""}`;
  return {
    block: script(box, "iptables", "block", body("block")),
    unblock: script(box, "iptables", "unblock", body("unblock")),
    notes: ["blocks live in chain FUD_BLOCK, separate from the hardening rules, so a rollback never unblocks anyone"],
  };
}
