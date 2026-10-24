import { formatRange } from "../ports";
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

const set = (items: string[]) => {
  const lines: string[] = [];
  for (let i = 0; i < items.length; i += 6) lines.push(items.slice(i, i + 6).join(", "));
  return lines.length > 1 ? `{\n      ${lines.join(",\n      ")}\n    }` : `{ ${lines[0]} }`;
};

export function nftAllow(a: Allow) {
  const src = a.from ? `ip saddr ${set(a.from)} ` : "";
  const comment = `comment "${safe(a.label)}${a.scored ? " (scored)" : ""}"`;
  if (a.proto === "icmp") return `${src}icmp type echo-request accept ${comment}`;
  return `${src}${a.proto} dport ${set(a.ports.map((r) => formatRange(r)))} accept ${comment}`;
}

export function nftRuleset(rs: RuleSet) {
  const trusted = rs.trusted.map((t) => `ip saddr ${t.cidr} accept comment "trusted: ${safe(t.why)}"`);
  return `add table inet fud_moat
delete table inet fud_moat
table inet fud_moat {
  chain input {
    type filter hook input priority -10; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    ${trusted.join("\n    ")}
    ${rs.allows.map(nftAllow).join("\n    ")}
${rs.policy.logDrops ? `    limit rate 10/second log prefix "fud-moat drop: "\n` : ""}  }
}`;
}

const ROLLBACK = `#!/bin/sh
# fud moat rollback: drops the fud_moat table. ip blocks (fud_moat_block) stay.
B=${DIR}
nft delete table inet fud_moat 2>/dev/null || true
rm -f "$B/rules.sh" "$B/rules.pending.sh" "$B/rollback.pid"
echo "✓ rolled back fud moat rules on $(hostname)"`;

export function nftRules(rs: RuleSet): RulesOutput {
  const apply = `${shPrelude(rs, "nftables", `command -v nft >/dev/null 2>&1 || { echo "✗ nft not found. apt install nftables (or dnf install nftables)"; exit 1; }`)}
${writeFile("$B/rollback.sh", ROLLBACK)}
# the rules, as a script so "keep it" can re-run it at boot
cat > "$B/rules.pending.sh" <<'FUDMOAT'
nft -f - <<'NFT'
${nftRuleset(rs)}
NFT
if [ -f ${DIR}/blocks.sh ]; then sh ${DIR}/blocks.sh; fi
FUDMOAT

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
    "lives in its own table (inet fud_moat), so docker's and anyone else's tables still run too. a drop in any of them still drops. check `nft list tables` for leftovers from red team",
    "ipv6 is dropped except neighbor discovery",
  ];
  if (rs.box.docker) notes.push("container ports go through forward, not input, so they stay reachable. ip blocks cover forward too");
  return {
    apply: script(rs.box, "nftables", "rules", apply),
    keep: script(rs.box, "nftables", "keep", keep),
    undo: script(rs.box, "nftables", "undo", undo),
    notes,
  };
}

/** Rebuilds the fud_moat_block table from blocked.txt. */
const BLOCKS_SH = `#!/bin/sh
# fud moat ip blocks, rebuilt from ${DIR}/blocked.txt. priority -20 runs before everything else.
set -eu
IPS=$(${READ_BLOCKED} | tr '\\n' ',' | sed 's/,$//')
ELEMS=""
if [ -n "$IPS" ]; then ELEMS="elements = { $IPS }"; fi
nft -f - <<NFT
add table inet fud_moat_block
delete table inet fud_moat_block
table inet fud_moat_block {
  set blocked {
    type ipv4_addr
    \$ELEMS
  }
  chain input {
    type filter hook input priority -20; policy accept;
    ip saddr @blocked drop
  }
  chain forward {
    type filter hook forward priority -20; policy accept;
    ip saddr @blocked drop
    ip daddr @blocked drop
  }
  chain output {
    type filter hook output priority -20; policy accept;
    ip daddr @blocked drop
  }
}
NFT
echo "✓ $(echo "$IPS" | tr ',' '\\n' | grep -c . || true) ip(s) blocked on $(hostname)"`;

export function nftBlocks(box: ResolvedBox, ips: string[]): BlocksOutput {
  const body = (action: "block" | "unblock") => `${blockPrelude(box, "nftables", action, ips)}${editBlockList(ips, action)}${writeFile("$B/blocks.sh", BLOCKS_SH)}sh "$B/blocks.sh"
${action === "block" ? killSessions(ips) : ""}`;
  return {
    block: script(box, "nftables", "block", body("block")),
    unblock: script(box, "nftables", "unblock", body("unblock")),
    notes: ["blocks live in table inet fud_moat_block, separate from the hardening rules, so a rollback never unblocks anyone"],
  };
}
