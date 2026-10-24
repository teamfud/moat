import type { ComponentProps } from "react";

const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

const buttonVariants = {
  primary: "bg-accent text-accent-fg border-2 border-border shadow-sticker",
  secondary: "bg-panel text-fg border-2 border-border shadow-sticker",
  ghost: "text-muted border-2 border-transparent hover:text-fg hover:border-border",
  danger: "bg-panel text-danger border-2 border-danger shadow-[3px_3px_0_0_var(--danger)]",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  ...props
}: ComponentProps<"button"> & { variant?: keyof typeof buttonVariants; size?: "sm" | "md" }) {
  return (
    <button
      {...props}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-display transition-[transform,box-shadow] duration-75 cursor-pointer",
        "active:translate-x-[3px] active:translate-y-[3px] active:shadow-none",
        "disabled:opacity-50 disabled:pointer-events-none",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-4 text-sm",
        variant !== "ghost" && "hover:-translate-x-px hover:-translate-y-px",
        buttonVariants[variant],
        className,
      )}
    />
  );
}

export const inputClass =
  "h-9 rounded-md border-2 border-border bg-panel px-3 text-[13px] text-fg placeholder:text-muted/70 focus:outline-none focus:shadow-sticker focus:bg-accent/10";

// Full width unless the caller picks a width of its own.
const width = (className?: string) => (/(^|\s)w-/.test(className ?? "") ? "" : "w-full");

export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input {...props} className={cx(inputClass, width(className), className)} />;
}

export function Select({ className, ...props }: ComponentProps<"select">) {
  return <select {...props} className={cx(inputClass, width(className), "pr-8", className)} />;
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea {...props} className={cx(inputClass, width(className), "h-auto min-h-20 py-2", className)} />;
}

export function Label({ className, ...props }: ComponentProps<"label">) {
  return <label {...props} className={cx("flex flex-col gap-1.5 text-xs text-muted", className)} />;
}

export function Card({ className, ...props }: ComponentProps<"div">) {
  return <div {...props} className={cx("rounded-lg border-2 border-border bg-panel shadow-sticker-lg", className)} />;
}

export function Badge({
  tone = "neutral",
  className,
  ...props
}: ComponentProps<"span"> & { tone?: "neutral" | "accent" | "danger" | "ok" | "warn" }) {
  const tones = {
    neutral: "border-muted/60 text-muted",
    accent: "border-border bg-accent text-accent-fg",
    danger: "border-danger text-danger",
    ok: "border-ok text-ok",
    warn: "border-warn text-warn",
  };
  return (
    <span
      {...props}
      className={cx("inline-flex items-center rounded-full border px-1.5 text-[11px] leading-[18px] lowercase", tones[tone], className)}
    />
  );
}

export function FormMessage({ state }: { state?: { error?: string; ok?: string } | null }) {
  if (!state) return null;
  if (state.error) return <p className="text-xs text-danger">✗ {state.error}</p>;
  if (state.ok) return <p className="text-xs text-ok">✓ {state.ok}</p>;
  return null;
}

export function PageHeader({ title, sub, children }: { title: string; sub?: string; children?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="font-display text-3xl leading-none">{title}</h1>
        {sub && <p className="mt-1.5 text-xs text-muted">{sub}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

/** Table header cell, shared by every table so they look the same. */
export function Th({ className, ...props }: ComponentProps<"th">) {
  return <th {...props} className={cx("px-4 py-2.5 text-left font-display text-xs font-normal text-muted", className)} />;
}

export const theadClass = "border-b-2 border-border bg-panel-2";

/** Client components should pass `now` from useNow() to avoid hydration mismatches. */
export function timeAgo(d: Date, now = Date.now()) {
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export { cx };
