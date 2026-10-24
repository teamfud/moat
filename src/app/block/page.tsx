"use client";

import { useState } from "react";
import { checkBlock, checkTopology } from "@/lib/fw/guardrails";
import { fill } from "@/lib/fw/ip";
import { OS_TARGETS, type Box } from "@/lib/fw/model";
import { renderBlocks } from "@/lib/fw/render";
import { update, useHydrated, useStore } from "@/lib/store";
import { Findings } from "@/components/Findings";
import { ScriptView } from "@/components/ScriptView";
import { Badge, Card, Label, PageHeader, Textarea, Th, theadClass } from "@/components/ui";

const pill = (active: boolean) =>
  `whitespace-nowrap rounded-md border-2 px-2.5 py-0.5 font-display text-sm cursor-pointer ${active ? "border-border bg-accent text-accent-fg" : "border-transparent text-muted hover:text-fg"}`;

export default function BlockPage() {
  const { topo, targets, blockInput, whiteTeamOk } = useStore();
  const hydrated = useHydrated();
  const [action, setAction] = useState<"block" | "unblock">("block");
  const [pick, setPick] = useState<string>("all");

  const inputs = [...new Set(blockInput.split(/[\s,;]+/).filter(Boolean))];
  const verdicts = inputs.map((i) => checkBlock(i, topo));
  const ips = [
    ...new Set(verdicts.filter((v) => v.ip && (v.level === "ok" || (v.level === "warn" && whiteTeamOk))).map((v) => v.ip!)),
  ];
  const warned = verdicts.filter((v) => v.level === "warn").length;
  const topoFindings = checkTopology(topo).filter((f) => f.level === "error");
  const shown = pick === "all" ? topo.boxes : topo.boxes.filter((b) => b.id === pick);
  const targetFor = (b: Box) => (targets[b.id] && OS_TARGETS[b.os].includes(targets[b.id]) ? targets[b.id] : OS_TARGETS[b.os][0]);

  return (
    <>
      <PageHeader title="quick block" sub="paste red team ips, get block commands for every box. single ips only (rule 15)" />
      {!hydrated ? null : (
        <div className="flex flex-col gap-5">
          <Findings findings={topoFindings} />
          <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
            <Card className="flex h-fit flex-col gap-4 p-5">
              <Label>
                ips, one per line (or spaces / commas)
                <Textarea
                  value={blockInput}
                  onChange={(e) => update((s) => ({ ...s, blockInput: e.target.value }))}
                  className="min-h-40 font-mono"
                  placeholder={"10." + topo.team + ".1.66\n203.0.113.7"}
                  spellCheck={false}
                />
              </Label>
              <div className="flex gap-1" role="tablist" aria-label="action">
                {(["block", "unblock"] as const).map((a) => (
                  <button key={a} role="tab" aria-selected={action === a} className={pill(action === a)} onClick={() => setAction(a)}>
                    {a}
                  </button>
                ))}
              </div>
              {warned > 0 && (
                <label className="flex items-start gap-2 text-xs text-fg">
                  <input
                    type="checkbox"
                    checked={whiteTeamOk}
                    onChange={(e) => update((s) => ({ ...s, whiteTeamOk: e.target.checked }))}
                    className="mt-0.5 accent-[var(--accent)]"
                  />
                  <span>
                    <Badge tone="warn">heads up</Badge> white team confirmed the {warned} out-of-scope ip{warned > 1 ? "s are" : " is"} ok to block. include{" "}
                    {warned > 1 ? "them" : "it"}.
                  </span>
                </label>
              )}
            </Card>

            <Card className="h-fit overflow-x-auto">
              {verdicts.length === 0 ? (
                <p className="p-10 text-center text-muted">no ips yet. paste some on the left</p>
              ) : (
                <table className="w-full min-w-[480px] text-left">
                  <thead className={theadClass}>
                    <tr>
                      <Th>ip</Th>
                      <Th>verdict</Th>
                      <Th>why</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/20">
                    {verdicts.map((v) => (
                      <tr key={v.input}>
                        <td className="px-4 py-2.5 font-mono">{v.input}</td>
                        <td className="whitespace-nowrap px-4 py-2.5">
                          {v.level === "ok" ? (
                            <Badge tone="ok">✓ ok</Badge>
                          ) : v.level === "warn" ? (
                            <Badge tone="warn">{whiteTeamOk ? "✓ white team ok" : "ask white team"}</Badge>
                          ) : (
                            <Badge tone="danger">✗ nope</Badge>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-muted">{v.msg}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>

          {ips.length > 0 && topoFindings.length === 0 && (
            <>
              <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="box">
                <button role="tab" aria-selected={pick === "all"} className={pill(pick === "all")} onClick={() => setPick("all")}>
                  all boxes
                </button>
                {topo.boxes.map((b) => (
                  <button key={b.id} role="tab" aria-selected={pick === b.id} className={pill(pick === b.id)} onClick={() => setPick(b.id)}>
                    {b.name}
                  </button>
                ))}
              </div>
              {shown.map((b) => {
                const t = targetFor(b);
                const out = renderBlocks(b, topo, t, ips);
                return (
                  <Card key={b.id}>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-t-lg border-b-2 border-border bg-panel-2 px-5 py-3">
                      <h2 className="font-display text-xl">{b.name}</h2>
                      <span className="font-mono text-muted">{fill(b.addr, topo.team)}</span>
                      <Badge>{t}</Badge>
                      <span className="text-xs text-muted">· change the firewall on the firewall page</span>
                    </div>
                    <div className="flex flex-col gap-3 p-5">
                      <ScriptView title={`${action} ${ips.length} ip${ips.length > 1 ? "s" : ""}`} script={action === "block" ? out.block : out.unblock} />
                      <ul className="flex flex-col gap-1 text-xs text-muted">
                        {out.notes.map((n, i) => (
                          <li key={i}>· {n}</li>
                        ))}
                      </ul>
                    </div>
                  </Card>
                );
              })}
            </>
          )}
        </div>
      )}
    </>
  );
}
