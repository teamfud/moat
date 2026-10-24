import type { Box, Service, Topology } from "../model";

// From the IRSeC 2026 blue team packet ("network topology" and rule 14).

const tcp = (label: string, ports: string, from: Service["from"] = "any"): Service => ({ label, proto: "tcp", ports, from });
const udp = (label: string, ports: string, from: Service["from"] = "any"): Service => ({ label, proto: "udp", ports, from });
const ping: Service = { label: "ping", proto: "icmp", ports: "", from: "any" };

const winAdmin = [tcp("rdp", "3389", "admin"), tcp("winrm", "5985-5986", "admin"), ping];
const linuxAdmin = [tcp("ssh", "22", "admin"), ping];

const box = (b: Omit<Box, "id" | "docker" | "notes"> & Partial<Pick<Box, "docker" | "notes">>): Box => ({
  id: b.name,
  docker: false,
  notes: "",
  ...b,
});

export const IRSEC_2026: Topology = {
  name: "irsec 2026",
  team: 1,
  scope: ["10.{x}.1.0/24", "192.168.{x}.0/24"],
  trusted: [{ cidr: "172.16.1.0/24", why: "management network (rule 14.b.i)" }],
  adminSources: ["10.{x}.1.0/24"],
  syslog: { from: "barrier", to: "timing", ports: "514" },
  boxes: [
    box({
      name: "barrier",
      addr: "10.{x}.1.254",
      os: "pfsense",
      scored: [],
      extra: [],
      notes: "external 172.20.1.{x}. keep syslog-ng to timing:514 running (rule 14)",
    }),
    box({
      name: "pitwall",
      addr: "10.{x}.1.1",
      os: "windows",
      scored: [
        tcp("dns", "53"),
        udp("dns", "53"),
        tcp("kerberos", "88,464"),
        udp("kerberos", "88,464"),
        udp("ntp", "123"),
        tcp("rpc + netbios", "135,139"),
        udp("netbios", "137-138"),
        tcp("ldap", "389,636,3268-3269"),
        udp("ldap", "389"),
        tcp("smb", "445"),
        tcp("adws", "9389"),
        tcp("rpc dynamic", "49152-65535"),
      ],
      extra: winAdmin,
      notes: "ad + dns, scored separately",
    }),
    box({ name: "teamradio", addr: "10.{x}.1.2", os: "windows", scored: [tcp("winrm", "5985-5986")], extra: [tcp("rdp", "3389", "admin"), ping] }),
    box({
      name: "safetycar",
      addr: "10.{x}.1.3",
      os: "windows",
      scored: [ping, tcp("telnet", "23")],
      extra: [tcp("rdp", "3389", "admin"), tcp("winrm", "5985-5986", "admin")],
      notes: "icmp and telnet scored separately",
    }),
    box({ name: "pitlane", addr: "10.{x}.1.4", os: "debian", scored: [tcp("ssh", "22")], extra: [ping] }),
    box({
      name: "garage",
      addr: "10.{x}.1.5",
      os: "ubuntu",
      scored: [tcp("ftp", "21"), tcp("ftp passive", "40000-50000")],
      extra: linuxAdmin,
      notes: "check pasv_min_port / pasv_max_port in vsftpd.conf and fix the passive range",
    }),
    box({
      name: "grandstand",
      addr: "10.{x}.1.6",
      os: "ubuntu",
      scored: [tcp("irc", "6667,6697")],
      extra: linuxAdmin,
      docker: true,
      notes: "irc server + bot in docker compose. check `docker compose ps` for the real ports",
    }),
    box({ name: "transporters", addr: "192.168.{x}.1", os: "windows", scored: [tcp("smb", "445")], extra: winAdmin }),
    box({ name: "stewards", addr: "192.168.{x}.2", os: "windows", scored: [tcp("iis", "80,443")], extra: winAdmin }),
    box({ name: "scrutineering", addr: "192.168.{x}.3", os: "rocky", scored: [tcp("mariadb", "3306")], extra: linuxAdmin }),
    box({
      name: "timing",
      addr: "192.168.{x}.4",
      os: "ubuntu",
      scored: [],
      extra: [
        tcp("syslog", "514", "scope"),
        udp("syslog", "514", "scope"),
        tcp("wazuh agents", "1514-1515", "scope"),
        tcp("wazuh dashboard", "443", "admin"),
        tcp("wazuh api", "55000", "admin"),
        ...linuxAdmin,
      ],
      notes: "wazuh. logging infra is out of scope, port 514 must stay open (rule 14.vi)",
    }),
  ],
};
