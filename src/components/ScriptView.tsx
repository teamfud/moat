"use client";

import type { Script } from "@/lib/fw/model";
import { download } from "@/lib/download";
import { CopyButton } from "@/components/CopyButton";
import { Badge, Button } from "@/components/ui";

export function ScriptView({ title, script, hint }: { title: string; script: Script; hint?: string }) {
  return (
    <div className="overflow-hidden rounded-md border-2 border-border">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b-2 border-border bg-panel-2 px-3 py-1.5">
        <span className="font-display text-sm">{title}</span>
        <span className="font-mono text-xs text-muted">{script.filename}</span>
        <Badge>{script.body.split("\n").length} lines</Badge>
        <span className="ml-auto flex items-center gap-1">
          <CopyButton getText={() => script.body} />
          <Button size="sm" variant="ghost" onClick={() => download(script.filename, script.body)}>
            download
          </Button>
        </span>
      </div>
      {hint && <p className="border-b border-border/20 px-3 py-1.5 text-xs text-muted">{hint}</p>}
      <pre className="max-h-80 overflow-auto bg-panel px-3 py-2 font-mono text-xs leading-relaxed">{script.body}</pre>
    </div>
  );
}
