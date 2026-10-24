import type { Finding } from "@/lib/fw/guardrails";
import { Badge } from "@/components/ui";

/** Errors stop the script. Warnings are a heads-up. Both carry a word or glyph, not just color. */
export function Findings({ findings }: { findings: Finding[] }) {
  if (!findings.length) return null;
  return (
    <ul className="flex flex-col gap-1.5">
      {findings.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-xs">
          {f.level === "error" ? (
            <span className="text-danger">✗ {f.msg}</span>
          ) : (
            <>
              <Badge tone="warn" className="shrink-0">
                heads up
              </Badge>
              <span className="text-fg">{f.msg}</span>
            </>
          )}
        </li>
      ))}
    </ul>
  );
}
