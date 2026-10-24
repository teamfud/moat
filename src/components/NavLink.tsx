"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  const path = usePathname();
  const active = href === "/" ? path === "/" || path.startsWith("/boxes") : path.startsWith(href);
  return (
    <Link
      href={href}
      className={`whitespace-nowrap rounded-md border-2 px-2.5 py-0.5 font-display ${active ? "border-border bg-accent text-accent-fg" : "border-transparent text-muted hover:text-fg"}`}
    >
      {children}
    </Link>
  );
}
