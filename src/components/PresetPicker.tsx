"use client";

import { useState } from "react";
import { PRESETS, type Preset } from "@/lib/fw/presets";
import { Badge, Button } from "@/components/ui";

/** Pick a preset, see what's in it, then load it. Loading replaces the whole topology. */
export function PresetPicker({ replacing, onLoad, onCancel }: { replacing: number; onLoad: (p: Preset) => void; onCancel: () => void }) {
  const [id, setId] = useState(PRESETS[0]?.id);
  const picked = PRESETS.find((p) => p.id === id);
  const trusted = picked ? new Set(picked.topology.trusted.map((t) => t.why)) : new Set<string>();

  return (
    <div className="flex flex-col gap-4">
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">preset</legend>
        {PRESETS.map((p) => (
          <label
            key={p.id}
            className={`flex cursor-pointer flex-col gap-1 rounded-md border-2 px-3 py-2.5 ${p.id === id ? "border-border bg-accent/10 shadow-sticker" : "border-border/30 hover:border-border"}`}
          >
            <span className="flex items-center gap-2">
              <input type="radio" name="preset" value={p.id} checked={p.id === id} onChange={() => setId(p.id)} className="accent-[var(--accent)]" />
              <span className="font-display text-base">{p.name}</span>
              <Badge>{p.topology.boxes.length} boxes</Badge>
            </span>
            <span className="text-xs text-muted">{p.description}</span>
          </label>
        ))}
      </fieldset>

      {picked && (
        <div className="flex flex-col gap-1.5 text-xs text-muted">
          <p>
            <span className="font-semibold text-fg">boxes:</span> {picked.topology.boxes.map((b) => b.name).join(" · ")}
          </p>
          <p>
            <span className="font-semibold text-fg">trusted:</span> {trusted.size ? [...trusted].join(" · ") : "—"}
          </p>
          <p>ur team number stays as it is.</p>
        </div>
      )}

      {replacing > 0 && (
        <p className="text-xs text-danger">
          ✗ this replaces ur {replacing} box{replacing > 1 ? "es" : ""} and all ranges. export first if u want to keep them.
        </p>
      )}

      <div className="flex justify-end gap-2">
        <Button type="button" variant="secondary" autoFocus data-autofocus onClick={onCancel}>
          nvm
        </Button>
        <Button type="button" variant={replacing ? "danger" : "primary"} disabled={!picked} onClick={() => picked && onLoad(picked)}>
          {replacing ? `replace with ${picked?.name}` : `load ${picked?.name}`}
        </Button>
      </div>
    </div>
  );
}
