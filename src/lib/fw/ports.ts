/** Port lists like "53", "80,443" or "49152-65535". */

export type PortRange = [number, number];

export function parsePorts(s: string): PortRange[] | string {
  const parts = s.split(",").map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return "no ports";
  const out: PortRange[] = [];
  for (const p of parts) {
    const m = /^(\d{1,5})(?:\s*[-:]\s*(\d{1,5}))?$/.exec(p);
    if (!m) return `"${p}" isn't a port`;
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo < 1 || hi > 65535) return `${p} is out of range (1-65535)`;
    if (lo > hi) return `${p} is backwards`;
    out.push([lo, hi]);
  }
  return out;
}

/** "80", "1000-2000" style, with a custom range separator. */
export function formatRange([lo, hi]: PortRange, sep = "-") {
  return lo === hi ? String(lo) : `${lo}${sep}${hi}`;
}

/**
 * Split for tools with a 15-slot limit on port lists (iptables multiport,
 * ufw). A range takes two slots.
 */
export function chunkPorts(ranges: PortRange[], slots = 15): PortRange[][] {
  const chunks: PortRange[][] = [];
  let cur: PortRange[] = [];
  let used = 0;
  for (const r of ranges) {
    const cost = r[0] === r[1] ? 1 : 2;
    if (used + cost > slots) {
      chunks.push(cur);
      cur = [];
      used = 0;
    }
    cur.push(r);
    used += cost;
  }
  if (cur.length) chunks.push(cur);
  return chunks;
}
