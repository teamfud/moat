export type Os = "windows" | "debian" | "ubuntu" | "rocky" | "pfsense";
export type Proto = "tcp" | "udp" | "icmp";

/**
 * Who may reach a service: anyone (scored checks come from the scoring
 * engine, whose IPs we don't know), the admin sources, or anything in scope
 * (admin sources count as in scope here, so nat'd traffic from ur lan works).
 */
export type From = "any" | "admin" | "scope";

export type Service = {
  label: string;
  proto: Proto;
  /** "22", "80,443", "49152-65535". Ignored for icmp (always echo). */
  ports: string;
  from: From;
};

export type Box = {
  id: string;
  name: string;
  /** Address template, "{x}" is the team number. */
  addr: string;
  os: Os;
  /** Scored services, always allowed from anywhere. */
  scored: Service[];
  /** Admin access and anything else that should stay reachable. */
  extra: Service[];
  docker: boolean;
  notes: string;
};

export type Trusted = { cidr: string; why: string };

export type Topology = {
  name: string;
  team: number;
  /** In-scope ranges (ur team's networks), as templates. */
  scope: string[];
  /** Never blocked, always allowed in (mgmt network, monitoring, …), as templates. */
  trusted: Trusted[];
  /** Where admin access ("admin" services) is allowed from. */
  adminSources: string[];
  /** "never" when the comp bans blocking out-of-scope ips outright, "ask" to allow it once white team says ok. */
  blockOutOfScope: "ask" | "never";
  boxes: Box[];
};

export type Policy = {
  logDrops: boolean;
  /** Auto-restore the old rules after this many minutes unless "keep it" runs. */
  rollbackMinutes: number;
  /** Drop outbound too, except to ur own ranges, trusted ranges, dns and dhcp. */
  restrictOutbound: boolean;
};

export type Target = "powershell" | "nftables" | "ufw" | "firewalld" | "iptables" | "pfsense";

export const TARGETS: Record<Target, { label: string; ext: string }> = {
  powershell: { label: "powershell", ext: "ps1" },
  nftables: { label: "nftables", ext: "sh" },
  ufw: { label: "ufw", ext: "sh" },
  firewalld: { label: "firewalld", ext: "sh" },
  iptables: { label: "iptables", ext: "sh" },
  pfsense: { label: "pfsense", ext: "sh" },
};

/** Targets that work on each OS, best first. */
export const OS_TARGETS: Record<Os, Target[]> = {
  windows: ["powershell"],
  debian: ["nftables", "iptables"],
  ubuntu: ["ufw", "nftables", "iptables"],
  rocky: ["firewalld", "nftables", "iptables"],
  pfsense: ["pfsense"],
};

export const OS_LABELS: Record<Os, string> = {
  windows: "windows",
  debian: "debian",
  ubuntu: "ubuntu",
  rocky: "rocky / rhel",
  pfsense: "pfsense",
};

export const DEFAULT_POLICY: Policy = { logDrops: true, rollbackMinutes: 1, restrictOutbound: false };

export type Script = { filename: string; lang: "sh" | "powershell" | "text"; body: string };
