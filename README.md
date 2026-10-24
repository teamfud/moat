# fud moat

Firewall rule generator for [team fud](https://fud.team) in Red vs Blue competitions. Describe your boxes, pick one, and paste the script it gives you. Guardrails stop it from producing scripts that lock out scoring, white team or your own teammates.

Write addresses as templates like `10.{x}.1.4` and set the team number in the header to fill them in. Pick a preset to start from (just IRSeC 2026 for now). Everything is saved in your browser's localStorage. Use export / import to share a topology with teammates.

## What it does

- **Boxes**: the topology as an editable table: boxes, addresses, OS, scored services and extras (admin access, ping, …). Import/export as JSON to share with teammates.
- **Firewall**: one allowlist script per box. Scored services are open to anyone, extras to the admin sources or the scope ranges, and trusted ranges always get in. Everything else inbound is dropped and outbound stays open. Targets:
  | OS | Firewall |
  | --- | --- |
  | Windows | PowerShell (`New-NetFirewallRule`, group `fud-moat`) |
  | Debian | nftables (own table `inet fud_moat`), iptables |
  | Ubuntu | ufw, nftables, iptables |
  | Rocky / RHEL | firewalld (runtime until kept), nftables, iptables |
  | pfSense | a checklist, not a script: its NAT and pass rules carry the scored services |
- **Quick block**: paste red team IPs and get block/unblock commands for every box, including `easyrule` on pfSense. Blocks live apart from the hardening rules (`fud_moat_block`, `FUD_BLOCK`, `fud-moat-block`), so a rollback never unblocks anyone.
- **Guardrails**: what moat won't let you do, and why.

## Presets

Presets live in `src/lib/fw/presets/`. Add one to `PRESETS` in `index.ts` and it shows up in the picker. Loading a preset replaces the whole topology except the team number.

The IRSeC 2026 preset includes its management network and DataDog's ranges as trusted, since that comp requires both to stay reachable. Refresh the DataDog list before the comp, then commit:

```bash
npm run update-datadog
```

## Lockout insurance

Every hardening script backs up first, applies, and then **rolls itself back after N minutes** (5 by default). To stop it, open a new session, check that you still get in, then paste **keep it**. Keep it also makes the rules survive a reboot: through a `fud-moat.service` systemd unit for nftables and iptables, natively for the rest. **Undo** puts the firewall back to how it was before fud moat touched it. IP blocks stay.

## Guardrails

- **Single IPs only**: quick block refuses subnets.
- **Trusted ranges** (management, scoring, monitoring networks, …) are allowed in on every box and can never be blocked. They start empty, so add your comp's on the boxes page. You can paste a plain list.
- **Your own boxes** can't be blocked.
- **Out-of-scope IPs** are held back until you tick that white team said ok.
- **Scored ports** are open to anyone. Routers get a checklist, so NAT and port forwards are never scripted.

> ⚠️ **Read your comp's rules before running the hardening scripts.** Some comps treat default-deny inbound as blocking subnets, or require specific traffic (logging, monitoring agents) to stay open. If default-deny isn't allowed, use quick block only.

## Development

```bash
npm install
npm run dev
npm test           # guardrails, renderers (snapshots), ip/port parsing
npm run typecheck
npm run lint
npm run test:live  # runs the linux scripts for real in docker (~3 min)
```

`test:live` builds Debian, Ubuntu and Rocky (systemd) containers. For each of nftables, iptables, ufw and firewalld it checks: the scored port stays open, an unlisted port gets dropped, the rollback fires, keep it cancels it, blocking and unblocking a real client works, and undo leaves blocks in place. **The Windows and pfSense output isn't covered by it.** Run those on your own VMs before the competition.

## Deploying on Railway

It's a static export (`out/`) served by `serve`, with security headers from `public/serve.json`.

1. Create a service from this repo. Railpack's Node defaults run `npm run build` and `npm start`, which is `serve out -l $PORT`.
2. Generate a domain. No variables, database or volume needed.
