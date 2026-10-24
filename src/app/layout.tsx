import type { Metadata } from "next";
import Link from "next/link";
import { Geist_Mono, Pixelify_Sans } from "next/font/google";
import "./globals.css";
import { BRAND } from "@/lib/brand";
import { Logo } from "@/components/Logo";
import { NavLink } from "@/components/NavLink";
import { TeamInput } from "@/components/TeamInput";

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const pixel = Pixelify_Sans({
  variable: "--font-pixel",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: BRAND.name,
  description: `firewall rule generator for ${BRAND.team}`,
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistMono.variable} ${pixel.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col font-sans text-[13px]">
        <header className="sticky top-0 z-20 border-b-2 border-border bg-panel">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:h-14 sm:flex-nowrap sm:py-0">
            <Link href="/" className="flex items-center gap-2">
              <span className="hover-wobble">
                <Logo size={30} />
              </span>
              <span className="hidden font-display text-lg sm:inline">{BRAND.name}</span>
            </Link>
            <nav className="order-last -mx-1 flex w-full items-center gap-1 overflow-x-auto px-1 text-sm sm:order-none sm:mx-0 sm:w-auto sm:flex-1 sm:px-0">
              <NavLink href="/">boxes</NavLink>
              <NavLink href="/firewall">firewall</NavLink>
              <NavLink href="/block">quick block</NavLink>
              <NavLink href="/guardrails">guardrails</NavLink>
            </nav>
            <div className="ml-auto sm:ml-0">
              <TeamInput />
            </div>
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">{children}</main>
        <footer className="py-6 text-center text-[11px] text-muted">made with fear, uncertainty and doubt by {BRAND.team} :)</footer>
      </body>
    </html>
  );
}
