"use client";

import { useEffect, useRef } from "react";

export function Modal({
  open,
  onClose,
  title,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      // showModal() focuses the first control (the ✕), and React's autoFocus
      // already fired while the dialog was closed. Put focus where it belongs.
      d.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    }
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      className={`m-auto w-[calc(100%-2rem)] ${wide ? "max-w-2xl" : "max-w-md"} rounded-lg border-2 border-border bg-panel p-0 text-fg shadow-sticker-lg`}
    >
      <div className="flex items-center justify-between border-b-2 border-border bg-panel-2 px-5 py-3">
        <h2 className="font-display text-lg">{title}</h2>
        <button onClick={onClose} className="text-muted hover:text-fg cursor-pointer" aria-label="close">
          ✕
        </button>
      </div>
      <div className="p-5">{open && children}</div>
    </dialog>
  );
}
