"use client";

import { useState } from "react";
import { OS_LABELS, type Box, type From, type Os, type Proto, type Service } from "@/lib/fw/model";
import { Button, Input, Label, Select, Textarea } from "@/components/ui";

const FROM_LABELS: Record<From, string> = { any: "anyone", admin: "admin sources", scope: "in-scope ranges" };

function ServiceRows({
  title,
  hint,
  services,
  onChange,
  fixedFrom,
}: {
  title: string;
  hint: string;
  services: Service[];
  onChange: (s: Service[]) => void;
  /** Scored services are open to anyone, no choice. */
  fixedFrom?: boolean;
}) {
  const set = (i: number, patch: Partial<Service>) => onChange(services.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1 font-display text-sm">{title}</legend>
      <p className="-mt-1 text-xs text-muted">{hint}</p>
      {services.map((s, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <Input aria-label="label" value={s.label} onChange={(e) => set(i, { label: e.target.value })} className="w-32" placeholder="ssh" />
          <Select aria-label="protocol" value={s.proto} onChange={(e) => set(i, { proto: e.target.value as Proto })} className="w-20">
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">ping</option>
          </Select>
          <Input
            aria-label="ports"
            value={s.proto === "icmp" ? "" : s.ports}
            disabled={s.proto === "icmp"}
            onChange={(e) => set(i, { ports: e.target.value })}
            className="w-36 font-mono"
            placeholder={s.proto === "icmp" ? "—" : "22 or 80,443"}
          />
          {!fixedFrom && (
            <Select aria-label="allowed from" value={s.from} onChange={(e) => set(i, { from: e.target.value as From })} className="w-40">
              {(Object.keys(FROM_LABELS) as From[]).map((f) => (
                <option key={f} value={f}>
                  from {FROM_LABELS[f]}
                </option>
              ))}
            </Select>
          )}
          <button
            type="button"
            onClick={() => onChange(services.filter((_, j) => j !== i))}
            className="text-muted hover:text-danger cursor-pointer"
            aria-label={`remove ${s.label || "service"}`}
          >
            ✕
          </button>
        </div>
      ))}
      <div>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={() => onChange([...services, { label: "", proto: "tcp", ports: "", from: fixedFrom ? "any" : "admin" }])}
        >
          + add service
        </Button>
      </div>
    </fieldset>
  );
}

export function BoxEditor({ initial, onSave, onCancel }: { initial: Box; onSave: (b: Box) => void; onCancel: () => void }) {
  const [b, setB] = useState(initial);
  const patch = (p: Partial<Box>) => setB((x) => ({ ...x, ...p }));
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        onSave({ ...b, name: b.name.trim(), addr: b.addr.trim() });
      }}
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <Label>
          name
          <Input value={b.name} onChange={(e) => patch({ name: e.target.value })} required autoFocus data-autofocus placeholder="pitlane" />
        </Label>
        <Label>
          address ({"{x}"} = team)
          <Input value={b.addr} onChange={(e) => patch({ addr: e.target.value })} required className="font-mono" placeholder="10.{x}.1.4" />
        </Label>
        <Label>
          os
          <Select value={b.os} onChange={(e) => patch({ os: e.target.value as Os })}>
            {(Object.keys(OS_LABELS) as Os[]).map((o) => (
              <option key={o} value={o}>
                {OS_LABELS[o]}
              </option>
            ))}
          </Select>
        </Label>
      </div>
      <ServiceRows
        title="scored services"
        hint="always open to anyone, since the scoring engine's ips aren't known."
        services={b.scored}
        onChange={(scored) => patch({ scored })}
        fixedFrom
      />
      <ServiceRows
        title="extras"
        hint="admin access and anything else that has to stay reachable."
        services={b.extra}
        onChange={(extra) => patch({ extra })}
      />
      <label className="flex items-center gap-2 text-xs text-muted">
        <input type="checkbox" checked={b.docker} onChange={(e) => patch({ docker: e.target.checked })} className="accent-[var(--accent)]" />
        runs docker (published container ports skip the host firewall)
      </label>
      <Label>
        notes
        <Textarea value={b.notes} onChange={(e) => patch({ notes: e.target.value })} placeholder="anything a teammate should know" />
      </Label>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="secondary" onClick={onCancel}>
          nvm
        </Button>
        <Button type="submit">save box</Button>
      </div>
    </form>
  );
}
