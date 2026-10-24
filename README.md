# fud moat

Firewall rule generator for [team fud](https://fud.team) in Red vs Blue competitions. Load the topology, pick a box, and paste the script it gives you. It knows the competition rules, so it won't produce a script that breaks one.

Ships with the IRSeC 2026 topology as a preset. Set the team number in the header and every `{x}` fills in.

## What it does

- **Boxes**: the topology as an editable table: boxes, addresses, OS, scored services and extras (admin access, ping, …). Import/export as JSON to share with teammates.
- **Firewall**: one allowlist script per box. Scored services are open to anyone, extras to the admin sources or the scope ranges, and trusted ranges and DataDog always get in. Everything else inbound is dropped and outbound stays open. Targets:
  | OS | Firewall |
  | --- | --- |
  | Windows | PowerShell (`New-NetFirewallRule`, group `fud-moat`) |
  | Debian | nftables (own table `inet fud_moat`), iptables |
  | Ubuntu | ufw, nftables, iptables |
  | Rocky / RHEL | firewalld (runtime until kept), nftables, iptables |
  | pfSense | a checklist, not a script: its NAT and pass rules are the scored topology |
- **Quick block**: paste red team IPs and get block/unblock commands for every box, including `easyrule` on barrier. Blocks live apart from the hardening rules (`fud_moat_block`, `FUD_BLOCK`, `fud-moat-block`), so a rollback never unblocks anyone.
- **Guardrails**: the packet rules, and what moat does about each one.

## Lockout insurance

Every hardening script backs up first, applies, and then **rolls itself back after N minutes** (5 by default). To stop it, open a new session, check that you still get in, then paste **keep it**. Keep it also makes the rules survive a reboot: through a `fud-moat.service` systemd unit for nftables and iptables, natively for the rest. **Undo** puts the firewall back to how it was before fud moat touched it. IP blocks stay.

## Guardrails (IRSeC 2026)

- **Rule 15**: blocks are single IPs only. Out-of-scope IPs need a white team ok, which is a checkbox.
- **Rule 14**: blocks on the management network (`172.16.1.0/24`), on any DataDog IP or on our own boxes are refused. The mgmt net and DataDog are allowed in everywhere, and timing always accepts 514 from barrier.
- **Rule 10**: scored ports are open to anyone. Barrier's NAT and port forwards are never scripted.
- **Rule 20**: it's a static site with no login, so the URL can go straight to white team.
- **Rule 23**: no AI runs anywhere. The scripts are plain text and humans paste them.

> ⚠️ **Ask white team before the hardening scripts.** Default-deny inbound could be read as "blocking subnets" under rule 15. If the answer is no, use quick block only.

The DataDog ranges are a snapshot in `src/lib/fw/datadog.json`, because the browser can't fetch the list cross-origin. **Refresh it the morning of the competition**, then redeploy:

```bash
npm run update-datadog
```

## Development

```bash
npm install
npm run dev
npm test           # guardrails, renderers (snapshots), ip/port parsing
npm run typecheck
npm run lint
npm run test:live  # runs the linux scripts for real in docker (~3 min)
```

`test:live` builds Debian, Ubuntu and Rocky (systemd) containers. For each of nftables, iptables, ufw and firewalld it checks: the scored port stays open, an unlisted port gets dropped, the rollback fires, keep it cancels it, blocking and unblocking a real client works, and undo leaves blocks in place. **The Windows and pfSense output isn't covered by it.** Run those on your own VMs before the competition (rule 18).

## Deploying on Railway

It's a static export (`out/`) served by `serve`, with security headers from `public/serve.json`.

1. Create a service from this repo. Railpack's Node defaults run `npm run build` and `npm start`, which is `serve out -l $PORT`.
2. Generate a domain. No variables, database or volume needed.
