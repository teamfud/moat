import Link from "next/link";
import { Logo } from "@/components/Logo";

export default function NotFound() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-4 text-center">
      <div className="rotate-12">
        <Logo size={72} />
      </div>
      <h1 className="font-display text-5xl">404</h1>
      <p className="text-muted">nothing here but fud :)</p>
      <Link href="/" className="underline decoration-accent decoration-2 underline-offset-2">
        take me home
      </Link>
    </div>
  );
}
