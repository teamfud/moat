"use client";

import { useRef, useState } from "react";
import { checkTopology } from "@/lib/fw/guardrails";
import { fill } from "@/lib/fw/ip";
import { OS_LABELS, type Box, type Service, type Topology } from "@/lib/fw/model";
import { parseTopology } from "@/lib/fw/serialize";
import { download } from "@/lib/download";
import { setTopo, useHydrated, useStore } from "@/lib/store";
import { BoxEditor } from "@/components/BoxEditor";
import { Findings } from "@/components/Findings";
import { Modal } from "@/components/Modal";
import { PresetPicker } from "@/components/PresetPicker";
import { useConfirm } from "@/components/useConfirm";
import { Badge, Button, Card, FormMessage, Label, PageHeader, Textarea, Th, theadClass } from "@/components/ui";

const svc = (s: Service) => (s.proto === "icmp" ? "ping" : `${s.label} ${s.ports}${s.proto === "udp" ? "/udp" : ""}`);

const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);

function Ranges({ topo }: { topo: Topology }) {
  // Edit as text, parse on blur, so half-typed lines don't get thrown away.
  const [scope, setScope] = useState(topo.scope.join("\n"));
  const [admin, setAdmin] = useState(topo.adminSources.join("\n"));
  const [trusted, setTrusted] = useState(topo.trusted.map((t) => `${t.cidr} ${t.why}`).join("\n"));
  return (
    <div className="grid gap-4 p-5 md:grid-cols-3">
      <Label>
        in-scope ranges (ur team&apos;s networks)
        <Textarea value={scope} onChange={(e) => setScope(e.target.value)} onBlur={() => setTopo((t) => ({ ...t, scope: lines(scope) }))} className="font-mono" />
      </Label>
      <Label>
        admin sources (rdp, ssh, … allowed from)
        <Textarea value={admin} onChange={(e) => setAdmin(e.target.value)} onBlur={() => setTopo((t) => ({ ...t, adminSources: lines(admin) }))} className="font-mono" />
      </Label>
      <Label>
        trusted: never blocked, always let in (mgmt, scoring, monitoring). &quot;cidr why&quot; per line, or paste a plain list
        <Textarea
          value={trusted}
          onChange={(e) => setTrusted(e.target.value)}
          onBlur={() =>
            setTopo((t) => ({
              ...t,
              trusted: lines(trusted).map((l) => {
                const [cidr, ...why] = l.split(/\s+/);
                return { cidr, why: why.join(" ") || "trusted" };
              }),
            }))
          }
          className="font-mono"
        />
      </Label>
    </div>
  );
}

export default function BoxesPage() {
  const { topo } = useStore();
  const [editing, setEditing] = useState<Box | null>(null);
  const [picking, setPicking] = useState(false);
  const [msg, setMsg] = useState<{ ok?: string; error?: string } | null>(null);
  const [confirm, confirmDialog] = useConfirm();
  const file = useRef<HTMLInputElement>(null);
  // Remounts the range editors when the whole topology is swapped out.
  const [gen, setGen] = useState(0);
  const hydrated = useHydrated();
  const findings = checkTopology(topo);

  const replace = async (next: Topology, what: string) => {
    if (topo.boxes.length && !(await confirm({ title: `replace ur topology?`, message: `this swaps all ${topo.boxes.length} boxes for ${what}. export first if u want to keep them.`, confirmLabel: "replace it", danger: true }))) return;
    setTopo(() => next);
    setGen((g) => g + 1);
    setMsg({ ok: `loaded ${what} :)` });
  };

  const save = (b: Box) => {
    setTopo((t) => ({ ...t, boxes: t.boxes.some((x) => x.id === b.id) ? t.boxes.map((x) => (x.id === b.id ? b : x)) : [...t.boxes, b] }));
    setEditing(null);
    setMsg({ ok: `${b.name} saved` });
  };

  const yeet = async (b: Box) => {
    if (await confirm({ title: `yeet ${b.name}?`, message: `${b.name} and its services leave the topology. no take-backs (unless u exported).`, confirmLabel: "yeet", danger: true })) {
      setTopo((t) => ({ ...t, boxes: t.boxes.filter((x) => x.id !== b.id) }));
      setMsg({ ok: `${b.name} yeeted` });
    }
  };

  return (
    <>
      <PageHeader title="boxes" sub={`${topo.name} · team ${topo.team} · {x} in an address is the team number`}>
        <Button variant="secondary" onClick={() => setPicking(true)}>
          load preset
        </Button>
        <Button variant="secondary" onClick={() => file.current?.click()}>
          import
        </Button>
        <Button variant="secondary" onClick={() => download(`fud-moat-${topo.name.replace(/\W+/g, "-")}.json`, JSON.stringify(topo, null, 2), "application/json")}>
          export
        </Button>
        <Button onClick={() => setEditing({ id: crypto.randomUUID(), name: "", addr: "10.{x}.1.", os: "debian", scored: [], extra: [{ label: "ssh", proto: "tcp", ports: "22", from: "admin" }], docker: false, notes: "" })}>
          add box
        </Button>
        <input
          ref={file}
          type="file"
          accept="application/json,.json"
          hidden
          onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (!f) return;
            try {
              await replace(parseTopology(JSON.parse(await f.text())), f.name);
            } catch (err) {
              setMsg({ error: `couldn't read ${f.name}: ${err instanceof Error ? err.message : "not json"}. check the file and try again` });
            }
          }}
        />
      </PageHeader>

      <div className="flex flex-col gap-5">
        <FormMessage state={msg} />
        <Findings findings={findings} />

        <Card className="overflow-x-auto">
          {topo.boxes.length === 0 ? (
            <p className="p-10 text-center text-muted">no boxes yet. load a preset?</p>
          ) : (
            <table className="w-full min-w-[760px] text-left">
              <thead className={theadClass}>
                <tr>
                  <Th>box</Th>
                  <Th>ip</Th>
                  <Th>os</Th>
                  <Th>scored</Th>
                  <Th>extras</Th>
                  <Th aria-label="actions" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20">
                {topo.boxes.map((b) => (
                  <tr key={b.id} className="align-top">
                    <td className="w-64 px-4 py-3">
                      <div className="font-semibold">{b.name}</div>
                      {b.notes && <div className="mt-0.5 text-xs text-muted">{fill(b.notes, topo.team)}</div>}
                    </td>
                    <td className="px-4 py-3 font-mono">{fill(b.addr, topo.team)}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        <Badge>{OS_LABELS[b.os]}</Badge>
                        {b.docker && <Badge tone="warn">docker</Badge>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs">{b.scored.length ? b.scored.map(svc).join(" · ") : <span className="text-muted">—</span>}</td>
                    <td className="px-4 py-3 text-xs text-muted">{b.extra.length ? b.extra.map(svc).join(" · ") : "—"}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="secondary" onClick={() => setEditing(b)}>
                          edit
                        </Button>
                        <Button size="sm" variant="ghost" className="hover:text-danger hover:border-danger" onClick={() => yeet(b)}>
                          yeet
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card>
          <h2 className="border-b-2 border-border bg-panel-2 px-5 py-2.5 font-display text-lg rounded-t-lg">ranges</h2>
          {hydrated && <Ranges key={gen} topo={topo} />}
        </Card>
      </div>

      <Modal open={picking} onClose={() => setPicking(false)} title="load a preset">
        <PresetPicker
          replacing={topo.boxes.length}
          onCancel={() => setPicking(false)}
          onLoad={(p) => {
            setTopo(() => ({ ...p.topology, team: topo.team }));
            setGen((g) => g + 1);
            setPicking(false);
            setMsg({ ok: `loaded ${p.name} :)` });
          }}
        />
      </Modal>
      <Modal open={!!editing} onClose={() => setEditing(null)} title={editing?.name ? `edit ${editing.name}` : "new box"} wide>
        {editing && <BoxEditor initial={editing} onSave={save} onCancel={() => setEditing(null)} />}
      </Modal>
      {confirmDialog}
    </>
  );
}
