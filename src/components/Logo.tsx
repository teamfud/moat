import Image from "next/image";
import { BRAND } from "@/lib/brand";

export function Logo({ size = 32 }: { size?: number }) {
  return (
    <Image
      src={BRAND.logo}
      alt={BRAND.team}
      width={size}
      height={size}
      priority
      className="rounded-md ring-1 ring-border [image-rendering:pixelated]"
    />
  );
}
