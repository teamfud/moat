import { TARGETS, type Script, type Target } from "../model";
import type { ResolvedBox, RuleSet } from "../plan";

export type RulesOutput = {
  /** Backs up, applies, and starts the rollback timer. */
  apply: Script;
  /** Cancels the rollback and makes the rules survive a reboot. */
  keep?: Script;
  /** Puts the firewall back to how it was before fud moat. IP blocks stay. */
  undo?: Script;
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
