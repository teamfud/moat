import { Badge, Card, PageHeader, Th, theadClass } from "@/components/ui";

// Plain wording on purpose: these are the things that cost uptime or points.
const RULES: { what: string; why: string; moat: string }[] = [
  {
    what: "single ips only",
    why: "a subnet block takes out scoring, white team and ur own teammates along with red team, and most comps ban it.",
    moat: "quick block refuses anything wider than a /32.",
  },
  {
    what: "trusted ranges",
    why: "management, scoring and monitoring networks have to keep working no matter what.",
    moat: "trusted ranges are allowed in on every box, and quick block refuses to block them. add them on the boxes page.",
  },
  {
    what: "ur own boxes",
    why: "blocking a teammate box breaks everything that talks to it.",
    moat: "quick block refuses any address in the topology.",
  },
  {
    what: "out-of-scope ips",
    why: "lots of comps only let u act on ur own ranges.",
    moat: "ips outside the scope ranges are held back until u tick that white team said ok.",
  },
  {
    what: "scored services",
    why: "the scoring engine's ips usually aren't known, and a check that can't connect is lost uptime.",
    moat: "scored ports are open to anyone. routers get a checklist, not a script, so nat and port forwards stay untouched.",
  },
  {
    what: "lockouts",
    why: "a bad rule over ssh or rdp can cut u off from the box.",
    moat: "every hardening script rolls itself back after a few minutes unless u paste keep it from a new session.",
  },
];

export default function GuardrailsPage() {
  return (
    <>
      <PageHeader title="guardrails" sub="what fud moat won't let u do, and why" />
      <div className="flex flex-col gap-5">
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left">
            <thead className={theadClass}>
              <tr>
                <Th>guardrail</Th>
                <Th>why</Th>
                <Th>fud moat</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20">
              {RULES.map((r) => (
                <tr key={r.what} className="align-top">
                  <td className="whitespace-nowrap px-4 py-3 font-display">{r.what}</td>
                  <td className="px-4 py-3 text-muted">{r.why}</td>
                  <td className="px-4 py-3">{r.moat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="p-5">
          <h2 className="mb-2 flex items-center gap-2 font-display text-lg">
            read ur comp&apos;s rules first <Badge tone="warn">heads up</Badge>
          </h2>
          <p className="text-muted">
            the firewall page drops all inbound traffic that isn&apos;t scored, an extra or trusted. some comps treat a default-deny policy like that as
            blocking subnets, or require specific traffic (logging, monitoring agents) to stay open.{" "}
            <span className="font-semibold text-fg">check the rules or ask white team before running the hardening scripts</span>, and add anything
            that must stay reachable as a trusted range. if default-deny isn&apos;t allowed, stick to quick block.
          </p>
        </Card>
      </div>
    </>
  );
}
