"use client";

import { useState } from "react";
import { checkBox, checkTopology } from "@/lib/fw/guardrails";
import { fill } from "@/lib/fw/ip";
import { OS_LABELS, OS_TARGETS, TARGETS, type Box, type Policy, type Target, type Topology } from "@/lib/fw/model";
import { renderRules } from "@/lib/fw/render";
import { update, useHydrated, useStore } from "@/lib/store";
import { Findings } from "@/components/Findings";
import { ScriptView } from "@/components/ScriptView";
import { Badge, Card, Input, Label, PageHeader, Select } from "@/components/ui";

const pill = (active: boolean) =>
  `whitespace-nowrap rounded-md border-2 px-2.5 py-0.5 font-display text-sm cursor-pointer ${active ? "border-border bg-accent text-accent-fg" : "border-transparent text-muted hover:text-fg"}`;

function BoxRules({ box, topo, policy, target, blocked }: { box: Box; topo: Topology; policy: Policy; target: Target; blocked: boolean }) {
  const findings = checkBox(box, topo, target, policy);
  const errors = blocked || findings.some((f) => f.level === "error");
  const out = errors ? null : renderRules(box, topo, policy, target);
  const m = policy.rollbackMinutes;

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-t-lg border-b-2 border-border bg-panel-2 px-5 py-3">
        <h2 className="font-display text-xl">{box.name}</h2>
        <span className="font-mono text-muted">{fill(box.addr, topo.team)}</span>
        <Badge>{OS_LABELS[box.os]}</Badge>
        <Label className="ml-auto flex-row items-center gap-2">
          firewall
          <Select
            value={target}
            onChange={(e) => update((s) => ({ ...s, targets: { ...s.targets, [box.id]: e.target.value as Target } }))}
            className="h-7 w-32"
          >
            {OS_TARGETS[box.os].map((t) => (
              <option key={t} value={t}>
                {TARGETS[t].label}
              </option>
            ))}
          </Select>
        </Label>
      </div>
      <div className="flex flex-col gap-4 p-5">
        <Findings findings={findings} />
        {blocked && <p className="text-xs text-danger">✗ fix the topology errors up top first</p>}
        {out && (
          <>
            {out.keep ? (
              <ol className="list-inside list-decimal text-xs text-muted">
                <li>paste <span className="font-semibold text-fg">apply</span> on {box.name}.</li>
                <li>
                  open a <span className="font-semibold text-fg">new</span> session (ssh / rdp / console) and check u still get in, and the
                  scored service still works.
                </li>
                <li>
                  paste <span className="font-semibold text-fg">keep it</span> within {m} min. otherwise it rolls itself back, which is the point.
                </li>
              </ol>
            ) : (
              <p className="text-xs text-muted">a checklist, not a script. ip blocks for {box.name} are on quick block.</p>
            )}
            <ScriptView title={out.keep ? "1 · apply" : "checklist"} script={out.apply} />
            {out.keep && <ScriptView title="2 · keep it" script={out.keep} />}
            {out.check && <ScriptView title="check" script={out.check} hint="run any time: shows what changed since apply (red team loves turning firewalls off) and every open session. changes nothing." />}
            {out.undo && <ScriptView title="undo" script={out.undo} hint="back to how it was before fud moat. ip blocks stay." />}
            {out.notes.length > 0 && (
              <ul className="flex flex-col gap-1 text-xs text-muted">
                {out.notes.map((n, i) => (
                  <li key={i}>· {n}</li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

export default function FirewallPage() {
  const { topo, policy, targets } = useStore();
  const hydrated = useHydrated();
  const [pick, setPick] = useState<string | "all">("");
  const topoFindings = checkTopology(topo);
  const blocked = topoFindings.some((f) => f.level === "error");
  const selected = topo.boxes.find((b) => b.id === pick) ?? (pick === "all" ? null : topo.boxes[0]);
  const shown = pick === "all" ? topo.boxes : selected ? [selected] : [];
  const setPolicy = (p: Partial<Policy>) => update((s) => ({ ...s, policy: { ...s.policy, ...p } }));

  return (
    <>
      <PageHeader title="firewall rules" sub="allowlist per box: scored, extras and trusted ranges stay open, everything else inbound (and optionally outbound) gets dropped" />
      {!hydrated ? null : topo.boxes.length === 0 ? (
        <Card className="p-10 text-center text-muted">no boxes yet. add some on the boxes page</Card>
      ) : (
        <div className="flex flex-col gap-5">
          <Findings findings={topoFindings} />
          <Card className="flex flex-col gap-4 p-5">
            <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="box">
              <button role="tab" aria-selected={pick === "all"} className={pill(pick === "all")} onClick={() => setPick("all")}>
                all boxes
              </button>
              {topo.boxes.map((b) => (
                <button key={b.id} role="tab" aria-selected={selected?.id === b.id && pick !== "all"} className={pill(selected?.id === b.id && pick !== "all")} onClick={() => setPick(b.id)}>
                  {b.name}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-end gap-4">
              <Label>
                rollback after (min)
                <Input
                  type="number"
                  min={1}
                  max={60}
                  value={policy.rollbackMinutes}
                  onChange={(e) => setPolicy({ rollbackMinutes: e.target.valueAsNumber || 0 })}
                  className="w-24"
                />
              </Label>
              <label className="flex h-9 items-center gap-2 text-xs text-muted">
                <input type="checkbox" checked={policy.logDrops} onChange={(e) => setPolicy({ logDrops: e.target.checked })} className="accent-[var(--accent)]" />
                log dropped packets (great evidence for the ir report)
              </label>
              <label className="flex h-9 items-center gap-2 text-xs text-muted">
                <input type="checkbox" checked={policy.restrictOutbound} onChange={(e) => setPolicy({ restrictOutbound: e.target.checked })} className="accent-[var(--accent)]" />
                restrict outbound too (only ur ranges, trusted, dns, dhcp. kills callbacks, breaks apt)
              </label>
            </div>
          </Card>
          {shown.map((b) => (
            <BoxRules key={b.id} box={b} topo={topo} policy={policy} target={targets[b.id] && OS_TARGETS[b.os].includes(targets[b.id]) ? targets[b.id] : OS_TARGETS[b.os][0]} blocked={blocked} />
          ))}
        </div>
      )}
    </>
  );
}
