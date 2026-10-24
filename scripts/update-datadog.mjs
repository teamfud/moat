// Refreshes the DataDog ranges in the IRSeC 2026 preset from DataDog's official
// list (that comp requires traffic to and from them to stay open). Bundled at
// build time because the browser can't fetch it cross-origin.
import { writeFile } from "node:fs/promises";

const SOURCE = process.env.DATADOG_RANGES_URL ?? "https://ip-ranges.us5.datadoghq.com/";

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`${SOURCE} returned ${res.status}`);
const body = await res.json();

const ipv4 = new Set();
for (const [key, value] of Object.entries(body)) {
  if (value && typeof value === "object" && Array.isArray(value.prefixes_ipv4)) {
    for (const p of value.prefixes_ipv4) ipv4.add(p);
  } else if (key === "prefixes_ipv4" && Array.isArray(value)) {
    for (const p of value) ipv4.add(p);
  }
}
if (ipv4.size === 0) throw new Error("no ipv4 prefixes found, did the format change?");

const out = {
  source: SOURCE,
  fetched: new Date().toISOString().slice(0, 10),
  modified: body.modified ?? null,
  ipv4: [...ipv4].sort(),
};
await writeFile(new URL("../src/lib/fw/presets/irsec2026-datadog.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${out.ipv4.length} ipv4 prefixes (modified ${out.modified})`);
