import { formatRange } from "../ports";
import { tcpPorts, type Allow, type ResolvedBox, type RuleSet } from "../plan";
import { header, OUTBOUND_NOTES, safe, script, type BlocksOutput, type RulesOutput } from "./common";

const DIR = "C:\\fud-moat";
const TASK = "fud-moat-rollback";

const list = (items: string[]) => `@(${items.map((i) => `'${i}'`).join(", ")})`;

export function psAllow(a: Allow) {
  const name = `fud-moat ${safe(a.label)}${a.proto === "icmp" ? "" : ` ${a.proto}`}${a.scored ? " (scored)" : ""}`;
  const params: string[] = [];
  if (a.proto === "icmp") params.push("Protocol = 'ICMPv4'", "IcmpType = 8");
  else params.push(`Protocol = '${a.proto.toUpperCase()}'`, `LocalPort = ${list(a.ports.map((r) => formatRange(r)))}`);
  if (a.from) params.push(`RemoteAddress = ${list(a.from)}`);
  return `Allow '${name}' @{ ${params.join("; ")} }`;
}

/** The other allow rules that apply turns off: inbound, plus outbound when it's restricted. Core networking stays. */
const others = (rs: RuleSet) =>
  `Get-NetFirewallRule -PolicyStore ActiveStore -Action Allow -Enabled True | Where-Object { $_.Group -ne 'fud-moat' -and $_.DisplayGroup -ne 'Core Networking'${
    rs.policy.restrictOutbound ? "" : " -and $_.Direction -eq 'Inbound'"
  } }`;

/**
 * What apply loaded, one line per thing, for the check script to compare:
 * the effective profiles (group policy included), our rules, and any other
 * allow rule, which apply turned off so a new one stands out.
 */
const snap = (rs: RuleSet) => `function Snap {
  Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name | ForEach-Object { "profile $($_.Name) enabled=$($_.Enabled) in=$($_.DefaultInboundAction) out=$($_.DefaultOutboundAction)" }
  Get-NetFirewallRule -Group 'fud-moat' -ErrorAction SilentlyContinue | Sort-Object DisplayName | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    $af = $_ | Get-NetFirewallAddressFilter
    "rule $($_.DisplayName) $($_.Direction) $($_.Action) enabled=$($_.Enabled) ports=$($pf.LocalPort -join ',')/$($pf.RemotePort -join ',') remote=$($af.RemoteAddress -join ',')"
  }
  ${others(rs)} | Sort-Object DisplayName | ForEach-Object { "other allow $($_.Direction) $($_.DisplayName) [$($_.PolicyStoreSourceType)]" }
}`;

/** Like the linux one: a session on a listening port is inbound, ! when the rules don't allow that port. */
const openSessions = (rs: RuleSet) => `
# sessions that were already open keep working (established traffic is let through), so look at each one
$ok = @(${tcpPorts(rs).map(([lo, hi]) => `'${lo}-${hi}'`).join(", ")})
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object LocalPort)
Write-Host "open tcp sessions. ! in = someone came in on a port the rules don't allow. out = this box connected out, check where to"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1$|::ffff:127\\.)' } | ForEach-Object {
  $p = $_.LocalPort
  $dir = 'out'; $flag = ' '
  if ($listen -contains $p) {
    $dir = 'in'; $flag = '!'
    foreach ($r in $ok) { $lo, $hi = $r.Split('-'); if ($p -ge [int]$lo -and $p -le [int]$hi) { $flag = ' ' } }
  }
  $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  '  {0} {1,-3} {2,-24} {3,-24} {4} pid {5}' -f $flag, $dir, "$($_.RemoteAddress):$($_.RemotePort)", "$($_.LocalAddress):$($_.LocalPort)", $proc, $_.OwningProcess
} | Write-Host
`;

/** Outbound only to our own ranges, trusted ranges, dns and dhcp. */
const outbound = (rs: RuleSet) => `
# outbound: only ur own ranges, trusted ranges, dns and dhcp
function AllowOut([string]$Name, [hashtable]$P) {
  New-NetFirewallRule -Group $G -DisplayName $Name -Direction Outbound -Action Allow -Profile Any @P | Out-Null
}
${rs.trusted.map((t) => `AllowOut 'fud-moat out trusted: ${safe(t.why)}' @{ RemoteAddress = ${list(t.cidrs)} }`).join("\n")}
AllowOut 'fud-moat out own ranges' @{ RemoteAddress = ${list(rs.own)} }
AllowOut 'fud-moat out dns udp' @{ Protocol = 'UDP'; RemotePort = 53 }
AllowOut 'fud-moat out dns tcp' @{ Protocol = 'TCP'; RemotePort = 53 }
AllowOut 'fud-moat out dhcp' @{ Protocol = 'UDP'; RemotePort = 67 }
AllowOut 'fud-moat out ping' @{ Protocol = 'ICMPv4'; IcmpType = 8 }
`;

const ROLLBACK = `# fud moat rollback: puts windows firewall back how it was before fud moat. ip blocks stay.
$B = '${DIR}'
Get-NetFirewallRule -Group 'fud-moat' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if (Test-Path "$B\\disabled.txt") {
  Get-Content "$B\\disabled.txt" | Where-Object { $_ } | ForEach-Object { Enable-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue }
  Remove-Item "$B\\disabled.txt"
}
if (Test-Path "$B\\profiles.xml") {
  Import-Clixml "$B\\profiles.xml" | ForEach-Object {
    Set-NetFirewallProfile -Name $_.Name -Enabled $_.Enabled -DefaultInboundAction $_.DefaultInboundAction -DefaultOutboundAction $_.DefaultOutboundAction -LogBlocked $_.LogBlocked
  }
  Remove-Item "$B\\profiles.xml"
}
Unregister-ScheduledTask -TaskName '${TASK}' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "$B\\expected.txt" -ErrorAction SilentlyContinue
Write-Host "rolled back fud moat rules on $env:COMPUTERNAME"`;

export function psRules(rs: RuleSet): RulesOutput {
  const m = rs.policy.rollbackMinutes;
  const apply = `${header(rs.box, "powershell", "allowlist")}# paste into an elevated powershell. rolls back in ${m} min unless u run "keep it".
$ErrorActionPreference = 'Stop'
$B = '${DIR}'
$G = 'fud-moat'
New-Item -ItemType Directory -Force -Path $B | Out-Null

# a rollback from an earlier run is still pending? stop it, this run replaces it
Unregister-ScheduledTask -TaskName '${TASK}' -Confirm:$false -ErrorAction SilentlyContinue

# back up the first time (a later run keeps the original backup)
if (-not (Test-Path "$B\\profiles.xml")) {
  netsh advfirewall export "$B\\before.wfw" | Out-Null
  Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked | Export-Clixml "$B\\profiles.xml"
}
@'
${ROLLBACK}
'@ | Set-Content "$B\\rollback.ps1"

try { Start-Service mpssvc } catch { Write-Warning "couldn't start the firewall service (mpssvc). check it isn't disabled" }

Get-NetFirewallRule -Group $G -ErrorAction SilentlyContinue | Remove-NetFirewallRule
function Allow([string]$Name, [hashtable]$P) {
  New-NetFirewallRule -Group $G -DisplayName $Name -Direction Inbound -Action Allow -Profile Any @P | Out-Null
}
${rs.trusted.map((t) => `Allow 'fud-moat trusted: ${safe(t.why)}' @{ RemoteAddress = ${list(t.cidrs)} }`).join("\n")}
${rs.allows.map(psAllow).join("\n")}
${rs.policy.restrictOutbound ? outbound(rs) : ""}
# turn off every other ${rs.policy.restrictOutbound ? "" : "inbound "}allow rule (core networking stays), and remember them for the rollback
$off = Get-NetFirewallRule -Action Allow -Enabled True | Where-Object { $_.Group -ne $G -and $_.DisplayGroup -ne 'Core Networking'${
    rs.policy.restrictOutbound ? "" : " -and $_.Direction -eq 'Inbound'"
  } }
$off | ForEach-Object { Add-Content "$B\\disabled.txt" $_.Name }
$off | Disable-NetFirewallRule
Write-Host "disabled $(@($off).Count) other allow rule(s)"

Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction ${rs.policy.restrictOutbound ? "Block" : "Allow"}${
    rs.policy.logDrops ? " -LogBlocked True -LogMaxSizeKilobytes 16384" : ""
  }

# remember what got loaded, for the check script
${snap(rs)}
Snap | Set-Content "$B\\expected.txt"

# lockout insurance: roll back unless "keep it" runs first
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File \`"$B\\rollback.ps1\`""
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(${m})
Register-ScheduledTask -TaskName '${TASK}' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Host "rules up. rolling back in ${m} min unless u run keep it from a NEW session"
$other = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True | Where-Object { $_.Group -notlike 'fud-moat*' }
if ($other) { Write-Warning "other inbound block rules exist, they beat allow rules. check them:"; $other | Format-Table DisplayName, Group }
${openSessions(rs)}`;

  const check = `${header(rs.box, "powershell", "check")}# compares the live firewall to what apply loaded. run it whenever, it changes nothing.
$B = '${DIR}'
${snap(rs)}
if (-not (Test-Path "$B\\expected.txt")) {
  Write-Warning "no fud moat snapshot on $env:COMPUTERNAME: never applied, rolled back, undone, or someone deleted $B"
} else {
  if (Get-ScheduledTask -TaskName '${TASK}' -ErrorAction SilentlyContinue) { Write-Warning "rollback still pending. run keep it" }
  $diff = Compare-Object @(Get-Content "$B\\expected.txt") @(Snap)
  if (-not $diff) { Write-Host "fud moat rules on $env:COMPUTERNAME match what apply loaded" }
  else {
    Write-Warning "rules changed since apply. - was loaded, + is live now:"
    $diff | ForEach-Object { "  $(if ($_.SideIndicator -eq '<=') { '-' } else { '+' }) $($_.InputObject)" } | Write-Host
  }
}
${openSessions(rs)}`;

  const keep = `# fud moat · ${rs.box.name} · keep it: cancel the rollback (windows keeps firewall rules across reboots)
if (Get-ScheduledTask -TaskName '${TASK}' -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName '${TASK}' -Confirm:$false
  Write-Host "rollback cancelled"
} else { Write-Host "no rollback pending (did it already fire?)" }
`;

  const undo = `# fud moat · ${rs.box.name} · undo: put windows firewall back how it was before fud moat (ip blocks stay)
& '${DIR}\\rollback.ps1'
`;

  return {
    apply: script(rs.box, "powershell", "rules", apply),
    keep: script(rs.box, "powershell", "keep", keep),
    undo: script(rs.box, "powershell", "undo", undo),
    check: script(rs.box, "powershell", "check", check),
    notes: [
      `every other ${rs.policy.restrictOutbound ? "" : "inbound "}allow rule gets disabled (core networking stays). the rollback turns them back on`,
      "rules pushed by group policy can't be changed locally. check gpresult /h or the domain's gpos. check shows them as other allow rules",
      `a full export from before the first run is at ${DIR}\\before.wfw (netsh advfirewall import to restore everything)`,
      ...(rs.policy.restrictOutbound ? [...OUTBOUND_NOTES, "windows update, defender cloud lookups and the store stop working"] : []),
    ],
  };
}

export function psBlocks(box: ResolvedBox, ips: string[]): BlocksOutput {
  const head = (action: string) => `${header(box, "powershell", action)}# paste into an elevated powershell.
$ErrorActionPreference = 'Stop'
foreach ($ip in ${list(ips)}) {
  Get-NetFirewallRule -DisplayName "fud-moat block $ip *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
`;
  const block = `${head("block")}  New-NetFirewallRule -Group 'fud-moat-block' -DisplayName "fud-moat block $ip in" -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
  New-NetFirewallRule -Group 'fud-moat-block' -DisplayName "fud-moat block $ip out" -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
  Get-NetTCPConnection -RemoteAddress $ip -ErrorAction SilentlyContinue | Format-Table LocalPort, RemotePort, State, OwningProcess
}
Write-Host "blocked ${ips.length} ip(s). any connections listed above were already open: kill the OwningProcess if it's theirs"
`;
  const unblock = `${head("unblock")}}
Write-Host "unblocked ${ips.length} ip(s)"
`;
  return {
    block: script(box, "powershell", "block", block),
    unblock: script(box, "powershell", "unblock", unblock),
    notes: ["block rules beat allow rules on windows, so these win over the hardening rules"],
  };
}
