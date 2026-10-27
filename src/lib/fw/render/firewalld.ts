import { formatRange } from "../ports";
import type { Allow, ResolvedBox, RuleSet } from "../plan";
import { nftBlocks, nftOutChain, nftTrustedSets } from "./nftables";
import {
  cancelTimer,
  checkScript,
  DIR,
  installUnit,
  openSessions,
  OUTBOUND_NOTES,
  saveSnapshot,
  script,
  shPrelude,
  startTimer,
  writeFile,
  type BlocksOutput,
  type RulesOutput,
} from "./common";

export function fwdAllow(a: Allow): string[] {
  if (a.proto === "icmp") return [`fw --zone="$Z" --remove-icmp-block=echo-request 2>/dev/null || true`];
  const out: string[] = [];
  for (const r of a.ports) {
    const port = formatRange(r);
    if (!a.from) {
      out.push(`fw --zone="$Z" --add-port=${port}/${a.proto}`);
      continue;
    }
    for (const src of a.from) {
      out.push(`fw --zone="$Z" --add-rich-rule='rule family="ipv4" source address="${src}" port port="${port}" protocol="${a.proto}" accept'`);
    }
  }
  return out;
}

/**
 * Outbound goes in its own nft table: firewalld policies can't be added at
 * runtime, and the rollback (a reload) would leave them behind anyway.
 * firewalld leaves other nft tables alone, like the block table.
 */
const outTable = (rs: RuleSet) => `nft -f - <<'NFT'
add table inet fud_moat_out
delete table inet fud_moat_out
table inet fud_moat_out {
${nftTrustedSets(rs)}${nftOutChain(rs)}}
NFT`;

const ZONE = `IF=$(ip route show default | awk '{print $5; exit}')
Z=$(firewall-cmd --get-zone-of-interface="$IF" 2>/dev/null || firewall-cmd --get-default-zone)`;

/** The zone, its rules, the trusted sources and any direct rules (red team's favourite way around zones). */
const snap = (rs: RuleSet) => `  ${ZONE.replace("\n", "\n  ")}
  echo "zone $Z on $IF"
  firewall-cmd --zone="$Z" --list-all
  echo "trusted sources: $(firewall-cmd --zone=trusted --list-sources)"
  echo "direct rules: $(firewall-cmd --direct --get-all-rules)"${rs.policy.restrictOutbound ? "\n  nft list table inet fud_moat_out" : ""}`;

const ROLLBACK = `#!/bin/sh
# fud moat rollback: puts /etc/firewalld back how it was before fud moat, reloads, re-adds ip blocks
B=${DIR}
P="$B/firewalld.prev"
if [ -d "$P" ]; then
  rm -rf /etc/firewalld.fud-moat-old
  mv /etc/firewalld /etc/firewalld.fud-moat-old
  if cp -a "$P" /etc/firewalld; then rm -rf /etc/firewalld.fud-moat-old "$P"; else mv /etc/firewalld.fud-moat-old /etc/firewalld; fi
fi
firewall-cmd --reload >/dev/null
nft delete table inet fud_moat_out 2>/dev/null || true
rm -f "$B/rollback.pid" "$B/expected.txt" "$B/rules.sh" "$B/rules.pending.sh"
if [ -f "$B/blocks.sh" ]; then sh "$B/blocks.sh"; fi
echo "✓ rolled back firewalld on $(hostname)"`;

export function fwdRules(rs: RuleSet): RulesOutput {
  const apply = `${shPrelude(
    rs,
    "firewalld",
    `systemctl is-active --quiet firewalld || { echo "✗ firewalld isn't running. systemctl enable --now firewalld, then run this again"; exit 1; }`,
  )}fw() { firewall-cmd -q "$@"; }

# the zone our main interface is in
${ZONE}
if [ "$Z" = trusted ]; then
  echo "⚠ $IF was in the trusted zone (lets everything in). moving it to public"
  fw --zone=public --change-interface="$IF"
  Z=public
fi
echo "using zone $Z on $IF"

# back up the first time (a later run keeps the original backup)
if [ ! -d "$B/firewalld.prev" ]; then cp -a /etc/firewalld "$B/firewalld.prev"; fi
${writeFile("$B/rollback.sh", ROLLBACK)}
# a zone target of ACCEPT lets everything in. that's permanent-only, so fix it first
T=$(firewall-cmd --permanent --zone="$Z" --get-target)
if [ "$T" = ACCEPT ]; then
  echo "⚠ zone $Z had target ACCEPT, setting it back to default"
  fw --permanent --zone="$Z" --set-target=default
  firewall-cmd --reload >/dev/null
fi

# runtime only from here on: firewall-cmd --reload (the rollback) throws it all away
for s in $(firewall-cmd --zone="$Z" --list-services); do fw --zone="$Z" --remove-service="$s"; done
for p in $(firewall-cmd --zone="$Z" --list-ports); do fw --zone="$Z" --remove-port="$p"; done
for p in $(firewall-cmd --zone="$Z" --list-source-ports); do fw --zone="$Z" --remove-source-port="$p"; done
firewall-cmd --zone="$Z" --list-rich-rules | while IFS= read -r r; do
  if [ -n "$r" ]; then fw --zone="$Z" --remove-rich-rule="$r"; fi
done

${rs.trusted
  .map((t) => `# trusted: ${t.why}\nfor n in ${t.cidrs.join(" ")}; do\n  fw --zone=trusted --add-source="$n" || echo "  couldn't trust $n (in another zone?)"\ndone`)
  .join("\n")}
${rs.allows.flatMap(fwdAllow).join("\n")}

# outbound, in its own nft table. a script so "keep it" can re-run it at boot
cat > "$B/rules.pending.sh" <<'FUDMOAT'
nft delete table inet fud_moat_out 2>/dev/null || true
${rs.policy.restrictOutbound ? outTable(rs) : "# outbound isn't restricted"}
FUDMOAT
sh "$B/rules.pending.sh"
${saveSnapshot(snap(rs))}${startTimer(rs.policy.rollbackMinutes)}${openSessions(rs)}`;

  const keep = `#!/bin/sh
# fud moat · ${rs.box.name} · keep it: cancel the rollback and save the runtime rules
set -eu
${cancelTimer}firewall-cmd --runtime-to-permanent && echo "✓ saved, survives reboots"
if [ -f "$B/rules.pending.sh" ]; then mv "$B/rules.pending.sh" "$B/rules.sh"; fi
${installUnit}`;

  const undo = `#!/bin/sh
# fud moat · ${rs.box.name} · undo: put firewalld back how it was before fud moat (ip blocks stay)
${cancelTimer}sh "$B/rollback.sh"
`;

  const notes = [
    "changes are runtime only until keep it. the rollback restores /etc/firewalld from the backup made on the first run and reloads",
    "trusted ranges go in the trusted zone, which accepts everything from them",
    "forward ports and masquerade aren't touched, so port forwards for scored services keep working",
    `logging denied packets needs a reload, so it's left out. after keep it: firewall-cmd --set-log-denied=unicast`,
  ];
  if (rs.policy.restrictOutbound) notes.push(...OUTBOUND_NOTES, "outbound lives in nft table inet fud_moat_out, since firewalld policies can't be added at runtime");
  return {
    apply: script(rs.box, "firewalld", "rules", apply),
    keep: script(rs.box, "firewalld", "keep", keep),
    undo: script(rs.box, "firewalld", "undo", undo),
    check: checkScript(rs, "firewalld", snap(rs)),
    notes,
  };
}

/** Blocks go in their own nft table, see nftBlocks. */
export const fwdBlocks = (box: ResolvedBox, ips: string[]): BlocksOutput => nftBlocks(box, ips, "firewalld");
