/** IPv4 + CIDR helpers. Addresses are unsigned 32-bit numbers. */

export type Cidr = { base: number; prefix: number };

export function parseIp(s: string): number | null {
  const parts = s.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

export function formatIp(n: number) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

const mask = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);

/** "1.2.3.4" is a /32. Host bits must be zero ("10.0.0.1/24" is rejected), since that's almost always a typo. */
export function parseCidr(s: string): Cidr | null {
  const [ip, len, ...rest] = s.trim().split("/");
  if (rest.length) return null;
  const base = parseIp(ip);
  if (base === null) return null;
  if (len === undefined) return { base, prefix: 32 };
  if (!/^\d{1,2}$/.test(len)) return null;
  const prefix = Number(len);
  if (prefix > 32) return null;
  if ((base & mask(prefix)) >>> 0 !== base) return null;
  return { base, prefix };
}

export function cidrToString(c: Cidr) {
  return c.prefix === 32 ? formatIp(c.base) : `${formatIp(c.base)}/${c.prefix}`;
}

/** Does `outer` fully contain `inner`? */
export function contains(outer: Cidr, inner: Cidr) {
  return inner.prefix >= outer.prefix && (inner.base & mask(outer.prefix)) >>> 0 === outer.base;
}

export function overlaps(a: Cidr, b: Cidr) {
  return contains(a, b) || contains(b, a);
}

/** Fill the team number into a template like "10.{x}.1.4". */
export function fill(template: string, team: number) {
  return template.replaceAll("{x}", String(team));
}
