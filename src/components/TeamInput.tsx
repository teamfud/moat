"use client";

import { setTopo, useStore } from "@/lib/store";

/** Team number in the header: it fills every {x} in the topology. */
export function TeamInput() {
  const { topo } = useStore();
  return (
    <label className="flex items-center gap-2 text-xs text-muted">
      team
      <input
        type="number"
        min={0}
        max={255}
        value={topo.team}
        onChange={(e) => setTopo((t) => ({ ...t, team: e.target.valueAsNumber || 0 }))}
        className="h-7 w-16 rounded-md border-2 border-border bg-panel px-2 text-[13px] text-fg focus:outline-none focus:shadow-sticker focus:bg-accent/10"
        aria-label="team number"
      />
    </label>
  );
}
