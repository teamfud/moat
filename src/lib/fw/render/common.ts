import { TARGETS, type Script, type Target } from "../model";
import { tcpPorts, type ResolvedBox, type RuleSet } from "../plan";
import { formatRange } from "../ports";

export type RulesOutput = {
  /** Backs up, applies, and starts the rollback timer. */
  apply: Script;
  /** Cancels the rollback and makes the rules survive a reboot. */
  keep?: Script;
  /** Puts the firewall back to how it was before fud moat. IP blocks stay. */
  undo?: Script;
  /** Shows what changed since apply, and the open sessions. Changes nothing. */
  check?: Script;
  notes: string[];
};

export type BlocksOutput = { block: Script; unblock: Script; notes: string[] };

export const DIR = "/etc/fud-moat";

/** Labels end up inside quotes in scripts, so keep them boring. */
export const safe = (s: string) => s.toLowerCase().replace(/[^a-z0-9 ._+/()-]/g, "").slice(0, 60);

export const script = (box: ResolvedBox, target: Target, kind: string, body: string, lang?: Script["lang"]): Script => ({
  filename: `${box.name}-${kind}.${lang === "text" ? "txt" : TARGETS[target].ext}`,
  lang: lang ?? (target === "powershell" ? "powershell" : "sh"),
  body: body.trimStart(),
});

export const header = (box: ResolvedBox, target: Target, what: string) =>
  `# fud moat · ${box.name} (${box.ip}) · ${target} · ${what}\n`;

/** Shell heredoc that writes `body` to `path` without expanding anything. */
export const writeFile = (path: string, body: string) => `cat > "${path}" <<'FUDMOAT'\n${body.trim()}\nFUDMOAT\n`;

export const shPrelude = (rs: RuleSet, target: Target, need: string) => `#!/bin/sh
${header(rs.box, target, "allowlist")}# paste into a root shell. rolls back in ${rs.policy.rollbackMinutes} min unless u run "keep it".
set -eu
B=${DIR}
${need}
mkdir -p "$B" && chmod 700 "$B"

# a rollback from an earlier run is still pending? stop it, this run replaces it
if [ -f "$B/rollback.pid" ]; then kill "$(cat "$B/rollback.pid")" 2>/dev/null || true; rm -f "$B/rollback.pid"; fi
`;

export const startTimer = (minutes: number) => `
# lockout insurance: roll back unless "keep it" runs first
nohup sh -c "sleep ${minutes * 60}; sh $B/rollback.sh" >/dev/null 2>&1 &
echo $! > "$B/rollback.pid"
echo "✓ rules up. rolling back in ${minutes} min unless u run keep it from a NEW session"
`;

export const cancelTimer = `B=${DIR}
if [ -f "$B/rollback.pid" ] && kill "$(cat "$B/rollback.pid")" 2>/dev/null; then echo "✓ rollback cancelled"; else echo "no rollback pending (did it already fire?)"; fi
rm -f "$B/rollback.pid"
`;

/** Boot-time re-apply for firewalls that forget everything on reboot. */
export const installUnit = `
${writeFile(
  "$B/boot.sh",
  `#!/bin/sh
# re-applies fud moat at boot. rules.sh only exists after "keep it".
B=${DIR}
if [ -f "$B/rules.sh" ]; then sh "$B/rules.sh"; fi
if [ -f "$B/blocks.sh" ]; then sh "$B/blocks.sh"; fi
exit 0`,
)}if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
${writeFile(
  "/etc/systemd/system/fud-moat.service",
  `[Unit]
Description=fud moat firewall rules
After=network-pre.target docker.service firewalld.service ufw.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh ${DIR}/boot.sh

[Install]
WantedBy=multi-user.target`,
)}  systemctl daemon-reload && systemctl enable --quiet fud-moat.service && echo "✓ survives reboots"
else
  echo "no systemd here. run sh ${DIR}/boot.sh at boot some other way"
fi
`;

/** Shell snippet that adds/removes IPs in the block list file. */
export const editBlockList = (ips: string[], action: "block" | "unblock") => {
  const list = ips.join(" ");
  return action === "block"
    ? `touch "$B/blocked.txt"
for ip in ${list}; do grep -qxF "$ip" "$B/blocked.txt" || echo "$ip" >> "$B/blocked.txt"; done
`
    : `touch "$B/blocked.txt"
for ip in ${list}; do grep -vxF "$ip" "$B/blocked.txt" > "$B/blocked.tmp" || true; mv "$B/blocked.tmp" "$B/blocked.txt"; done
`;
};

export const blockPrelude = (box: ResolvedBox, target: Target, action: "block" | "unblock", ips: string[]) => `#!/bin/sh
${header(box, target, action)}# ${action === "block" ? "blocks" : "unblocks"} ${ips.join(", ")}. paste into a root shell.
set -eu
B=${DIR}
mkdir -p "$B" && chmod 700 "$B"
`;

/** Lines of `blocked.txt` that look like an IPv4 address, for reconcile scripts. */
export const READ_BLOCKED = `{ grep -E '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$' ${DIR}/blocked.txt 2>/dev/null || true; }`;

/** Drop already-open connections to/from freshly blocked IPs (needs ss with kernel sock_destroy). */
export const killSessions = (ips: string[]) => `
# also kill their open sessions
if command -v ss >/dev/null 2>&1; then
  for ip in ${ips.join(" ")}; do ss -K dst "$ip" >/dev/null 2>&1 || true; done
fi
`;

/**
 * Established tcp sessions keep working under new rules, so list them. A
 * session on a listening port is inbound, ⚠ when the rules don't allow that
 * port. Anything else is this box connecting out.
 */
export const openSessions = (rs: RuleSet) => `
# sessions that were already open keep working (established traffic is let through), so look at each one
if command -v ss >/dev/null 2>&1; then
  echo "open tcp sessions. ⚠ in = someone came in on a port the rules don't allow. out = this box connected out, check where to"
  L=$(ss -Htln 2>/dev/null | awk '{ p = $4; sub(/.*:/, "", p); print p }' | sort -u | tr '\\n' ' ')
  ss -Htnp state established 2>/dev/null | awk -v ok="${tcpPorts(rs).map((r) => formatRange(r)).join(" ")}" -v listen="$L" '
    BEGIN { n = split(listen, l, " "); for (i = 1; i <= n; i++) lis[l[i]] = 1; n = split(ok, a, " ") }
    {
      lp = $3; sub(/.*:/, "", lp); peer = $4; sub(/:[^:]*$/, "", peer)
      if (peer ~ /^(127\\.|\\[::1\\]|\\[::ffff:127\\.)/) next
      dir = "out"; flag = " "
      if (lp in lis) {
        dir = "in"; flag = "⚠"
        for (i = 1; i <= n; i++) { split(a[i], r, "-"); if (r[2] == "") r[2] = r[1]; if (lp + 0 >= r[1] + 0 && lp + 0 <= r[2] + 0) flag = " " }
      }
      proc = $5; sub(/^users:\\(\\("/, "", proc); sub(/".*pid=/, " pid ", proc); sub(/,.*/, "", proc)
      printf "  %s %-3s %-24s %-24s %s\\n", flag, dir, $4, $3, proc
    }'
fi
`;

/**
 * Drift detection: apply saves `snap`'s output, check compares it to now.
 * `snap` is a shell function body that prints the loaded rules.
 */
export const saveSnapshot = (snap: string) => `
# remember what got loaded, for the check script
snap() {
${snap}
}
snap > "$B/expected.txt" 2>&1 || true
`;

export const checkScript = (rs: RuleSet, target: Target, snap: string, extra = "") =>
  script(
    rs.box,
    target,
    "check",
    `#!/bin/sh
${header(rs.box, target, "check")}# compares the live firewall to what apply loaded. run it whenever, it changes nothing.
B=${DIR}
snap() {
${snap}
}
if [ ! -f "$B/expected.txt" ]; then
  echo "✗ no fud moat snapshot on $(hostname): never applied, rolled back, undone, or someone deleted $B"
else
  if [ -f "$B/rollback.pid" ] && kill -0 "$(cat "$B/rollback.pid")" 2>/dev/null; then echo "⚠ rollback still pending. run keep it"; fi
  snap > "$B/now.txt" 2>&1 || true
  if cmp -s "$B/expected.txt" "$B/now.txt" 2>/dev/null || [ "$(cat "$B/expected.txt")" = "$(cat "$B/now.txt")" ]; then
    echo "✓ fud moat rules on $(hostname) match what apply loaded"
  else
    echo "✗ rules changed since apply. - was loaded, + is live now:"
    if command -v diff >/dev/null 2>&1; then diff "$B/expected.txt" "$B/now.txt" | grep '^[<>]' | sed 's/^</  -/; s/^>/  +/'; else echo "  (no diff here) now:"; cat "$B/now.txt"; fi
  fi
fi
${extra}${openSessions(rs)}`,
  );

export const OUTBOUND_NOTES = [
  "outbound only reaches ur own ranges, trusted ranges, dns and dhcp. apt / dnf / curl to the internet fail until u undo",
  "connections that were already open keep working both ways, so kill shells listed under open sessions",
];
