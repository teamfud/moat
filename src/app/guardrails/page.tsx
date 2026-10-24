import { DATADOG } from "@/lib/fw/plan";
import { Badge, Card, PageHeader, Th, theadClass } from "@/components/ui";

// Plain wording on purpose: these are the rules that cost points or get a team disqualified.
const RULES: { rule: string; says: string; moat: string }[] = [
  {
    rule: "15",
    says: "do not block subnets. individual ip blocking is permitted. out of scope ips may not be blocked.",
    moat: "quick block refuses anything wider than a /32. ips outside the scope ranges need a white team ok before they're included.",
  },
  {
    rule: "14.b.i",
    says: "172.16.1.0/24 (management network) is out of scope.",
    moat: "it's a trusted range: always allowed in on every box, and quick block refuses to block it.",
  },
  {
    rule: "14.b.v",
    says: "traffic to and from datadog's official ip list must not be blocked.",
    moat: "every datadog range is allowed in on every box, outbound stays open, and quick block refuses them.",
  },
  {
    rule: "14.b.vi",
    says: "all traffic from barrier to timing on port 514 must be allowed.",
    moat: "timing always allows 514 tcp + udp from barrier, and barrier's checklist covers the syslog-ng service.",
  },
  {
    rule: "10",
    says: "do not change the scored topology or how a check is scored.",
    moat: "scored services are allowed from anywhere. barrier gets a checklist, not a script, so nat and port forwards stay untouched.",
  },
  {
    rule: "6",
    says: "do not disable, remove or restrict the whiteteam user.",
    moat: "moat never touches users. remote access from the management network stays open.",
  },
  {
    rule: "18",
    says: "tools must be tested in good faith before the competition, outside ritsec infrastructure.",
    moat: "the scripts are tested against debian, ubuntu and rocky containers. test the windows and pfsense output on ur own vms before the day.",
  },
  {
    rule: "20",
    says: "tools must be publicly accessible with an unauthenticated link.",
    moat: "moat is a static site with no login. hand white team the url.",
  },
  {
    rule: "23",
    says: "no ai agents or ai-powered tools on competition infrastructure.",
    moat: "moat generates plain scripts in ur browser, with no ai involved. a human pastes them.",
  },
];

export default function GuardrailsPage() {
  return (
    <>
      <PageHeader title="guardrails" sub="what the irsec 2026 packet says, and what fud moat does about it" />
      <div className="flex flex-col gap-5">
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left">
            <thead className={theadClass}>
              <tr>
                <Th>rule</Th>
                <Th>packet says</Th>
                <Th>fud moat</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20">
              {RULES.map((r) => (
                <tr key={r.rule} className="align-top">
                  <td className="px-4 py-3 font-display">{r.rule}</td>
                  <td className="px-4 py-3 text-muted">{r.says}</td>
                  <td className="px-4 py-3">{r.moat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <div className="grid gap-5 md:grid-cols-2">
          <Card className="p-5">
            <h2 className="mb-2 flex items-center gap-2 font-display text-lg">
              ask white team first <Badge tone="warn">open question</Badge>
            </h2>
            <p className="text-muted">
              the firewall page drops all inbound traffic that isn&apos;t scored, an extra or trusted. rule 15 bans blocking subnets, and a
              default-deny policy could be read as exactly that. <span className="font-semibold text-fg">get a yes from white team before
              running the hardening scripts.</span> if the answer is no, only use quick block.
            </p>
          </Card>
          <Card className="p-5">
            <h2 className="mb-2 font-display text-lg">datadog ranges</h2>
            <p className="text-muted">
              {DATADOG.ipv4.length} ipv4 ranges, fetched {DATADOG.fetched}
              {DATADOG.modified ? ` (list updated ${DATADOG.modified.slice(0, 10)})` : ""} from{" "}
              <span className="font-mono text-fg">{DATADOG.source}</span>. refresh with <span className="font-mono text-fg">npm run update-datadog</span>{" "}
              and redeploy the morning of the competition.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
