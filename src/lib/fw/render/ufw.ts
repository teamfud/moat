import { chunkPorts, formatRange } from "../ports";
import type { Allow, ResolvedBox, RuleSet } from "../plan";
import {
  blockPrelude,
  cancelTimer,
  checkScript,
  DIR,
  editBlockList,
  installUnit,
  killSessions,
  openSessions,
  OUTBOUND_NOTES,
  safe,
  saveSnapshot,
  script,
  shPrelude,
  startTimer,
  writeFile,
  type BlocksOutput,
  type RulesOutput,
} from "./common";
import { IPT_BLOCKS_SH } from "./iptables";

export function ufwAllow(a: Allow): string[] {
  // ufw's before.rules already lets ping in.
  if (a.proto === "icmp") return [];
  const label = safe(`${a.label}${a.scored ? " (scored)" : ""}`);
  const out: string[] = [];
  for (const src of a.from ?? ["any"]) {
    for (const chunk of chunkPorts(a.ports)) {
      const ports = chunk.map((r) => formatRange(r, ":")).join(",");
      out.push(`ufw allow proto ${a.proto} from ${src} to any port ${ports} comment '${label}' >/dev/null`);
    }
  }
  return out;
}

/** One ufw rule per range, as a loop when it's long. `rule` gets "$n". */
const ufwEach = (cidrs: string[], why: string, rule: (n: string) => string) =>
  cidrs.length === 1
    ? `${rule(cidrs[0])} >/dev/null`
    : `echo "adding ${cidrs.length} ${safe(why)} ranges, takes a sec…"\nfor n in ${cidrs.join(" ")}; do\n  ${rule('"$n"')} >/dev/null\ndone`;

/** Outbound only to our own ranges, trusted ranges, dns and dhcp. */
const ufwOut = (rs: RuleSet) => `ufw default deny outgoing >/dev/null
${rs.trusted.map((t) => ufwEach(t.cidrs, t.why, (n) => `ufw allow out to ${n} comment 'trusted out: ${safe(t.why)}'`)).join("\n")}
${ufwEach(rs.own, "own", (n) => `ufw allow out to ${n} comment 'own ranges'`)}
ufw allow out 53 comment 'dns' >/dev/null
ufw allow out 67/udp comment 'dhcp' >/dev/null`;

const SNAP = `  ufw status verbose`;

const ROLLBACK = `#!/bin/sh
# fud moat rollback: puts ufw back how it was before fud moat, then re-adds ip blocks
B=${DIR}
P="$B/ufw.prev"
if [ -d "$P" ]; then
  ufw --force disable >/dev/null 2>&1 || true
  cp -a "$P/etc-ufw/." /etc/ufw/
  cp -a "$P/default-ufw" /etc/default/ufw
  if [ "$(cat "$P/state")" = active ]; then ufw --force enable >/dev/null; fi
  rm -rf "$P"
fi
rm -f "$B/rollback.pid" "$B/expected.txt"
if [ -f "$B/blocks.sh" ]; then sh "$B/blocks.sh"; fi
echo "✓ rolled back ufw on $(hostname)"`;

export function ufwRules(rs: RuleSet): RulesOutput {
  const apply = `${shPrelude(rs, "ufw", `command -v ufw >/dev/null 2>&1 || { echo "✗ ufw not found. apt install ufw"; exit 1; }`)}
# back up ufw the first time (a later run keeps the original backup)
if [ ! -d "$B/ufw.prev" ]; then
  mkdir -p "$B/ufw.prev/etc-ufw"
  cp -a /etc/ufw/. "$B/ufw.prev/etc-ufw/"
  cp -a /etc/default/ufw "$B/ufw.prev/default-ufw"
  if ufw status | grep -q "Status: active"; then echo active; else echo inactive; fi > "$B/ufw.prev/state"
fi
${writeFile("$B/rollback.sh", ROLLBACK)}
# start clean: this also throws out red team edits to before.rules
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
${rs.policy.restrictOutbound ? ufwOut(rs) : "ufw default allow outgoing >/dev/null"}
${rs.trusted.map((t) => ufwEach(t.cidrs, t.why, (n) => `ufw allow from ${n} comment 'trusted: ${safe(t.why)}'`)).join("\n")}
${rs.allows.flatMap(ufwAllow).join("\n")}
ufw logging ${rs.policy.logDrops ? "low" : "off"} >/dev/null
ufw --force enable >/dev/null
if [ -f "$B/blocks.sh" ]; then sh "$B/blocks.sh"; fi
${saveSnapshot(SNAP)}${startTimer(rs.policy.rollbackMinutes)}${openSessions(rs)}`;

  const keep = `#!/bin/sh
# fud moat · ${rs.box.name} · keep it: cancel the rollback (ufw keeps its rules across reboots)
set -eu
${cancelTimer}${installUnit}`;

  const undo = `#!/bin/sh
# fud moat · ${rs.box.name} · undo: put ufw back how it was before fud moat (ip blocks stay)
${cancelTimer}sh "$B/rollback.sh"
`;

  const notes = [
    "ufw --force reset wipes every ufw rule, including before.rules edits. the rollback restores the copy from before the first run",
    "ping stays allowed (ufw's before.rules)",
  ];
  if (rs.box.docker) notes.push("container ports skip ufw entirely (docker writes its own iptables rules). ip blocks also go in DOCKER-USER");
  if (rs.policy.restrictOutbound) notes.push(...OUTBOUND_NOTES, "ufw has no outbound ping rule, so pinging out fails too");
  return {
    apply: script(rs.box, "ufw", "rules", apply),
    keep: script(rs.box, "ufw", "keep", keep),
    undo: script(rs.box, "ufw", "undo", undo),
    check: checkScript(rs, "ufw", SNAP),
    notes,
  };
}

export function ufwBlocks(box: ResolvedBox, ips: string[]): BlocksOutput {
  // Not ufw deny rules: those do nothing while ufw is off, and docker skips them anyway.
  const body = (action: "block" | "unblock") => `${blockPrelude(box, "ufw", action, ips)}${editBlockList(ips, action)}${writeFile(
    "$B/blocks.sh",
    IPT_BLOCKS_SH("INPUT OUTPUT FORWARD DOCKER-USER"),
  )}sh "$B/blocks.sh"
${installUnit}${action === "block" ? killSessions(ips) : ""}`;
  return {
    block: script(box, "ufw", "block", body("block")),
    unblock: script(box, "ufw", "unblock", body("unblock")),
    notes: ["blocks use an iptables chain (FUD_BLOCK) above ufw's, so they work with ufw on or off, and reach docker containers too"],
  };
}
