"use client";

import { useEffect, useState, useTransition } from "react";

/**
 * "copy" link that writes `getText()` to the clipboard, then flashes "got it!"
 * or "oops" (clipboard blocked, http page, or getText failed).
 */
export function CopyButton({ getText, disabled }: { getText: () => string | Promise<string>; disabled?: boolean }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  const [pending, start] = useTransition();

  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 1500);
    return () => clearTimeout(t);
  }, [state]);

  return (
    <button
      type="button"
      disabled={disabled || pending}
      onClick={() =>
        start(async () => {
          try {
            await navigator.clipboard.writeText(await getText());
            setState("copied");
          } catch {
            setState("error");
          }
        })
      }
      className={`w-12 shrink-0 text-xs cursor-pointer ${
        state === "copied" ? "text-ok" : state === "error" ? "text-danger" : "text-fg underline decoration-accent decoration-2 underline-offset-2"
      }`}
    >
      {state === "copied" ? "got it!" : state === "error" ? "oops" : "copy"}
    </button>
  );
}
