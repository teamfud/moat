import { chunkPorts, formatRange } from "../ports";
import type { Allow, ResolvedBox, RuleSet } from "../plan";
import {
  blockPrelude,
  cancelTimer,
  DIR,
  editBlockList,
  installUnit,
  killSessions,
  safe,
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
rm -f "$B/rollback.pid"
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
ufw default allow outgoing >/dev/null
${rs.trusted.map((t) => `ufw allow from ${t.cidr} comment 'trusted: ${safe(t.why)}' >/dev/null`).join("\n")}
${rs.allows.flatMap(ufwAllow).join("\n")}
ufw logging ${rs.policy.logDrops ? "low" : "off"} >/dev/null
ufw --force enable >/dev/null
if [ -f "$B/blocks.sh" ]; then sh "$B/blocks.sh"; fi
${startTimer(rs.policy.rollbackMinutes)}`;

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
  return {
    apply: script(rs.box, "ufw", "rules", apply),
    keep: script(rs.box, "ufw", "keep", keep),
    undo: script(rs.box, "ufw", "undo", undo),
    notes,
  };
}

export function ufwBlocks(box: ResolvedBox, ips: string[]): BlocksOutput {
  // Not ufw deny rules: those do nothing while ufw is off, and docker skips them anyway.
  const body = (action: "block" | "unblock") => `${blockPrelude(box, "ufw", action, ips)}${editBlockList(ips, action)}${writeFile(
    "$B/blocks.sh",
    IPT_BLOCKS_SH("INPUT OUTPUT FORWARD DOCKER-USER"),
  )}sh "$B/blocks.sh"
${action === "block" ? killSessions(ips) : ""}`;
  return {
    block: script(box, "ufw", "block", body("block")),
    unblock: script(box, "ufw", "unblock", body("unblock")),
    notes: ["blocks use an iptables chain (FUD_BLOCK) above ufw's, so they work with ufw on or off, and reach docker containers too"],
  };
}
