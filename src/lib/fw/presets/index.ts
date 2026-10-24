import type { Topology } from "../model";
import { IRSEC_2026 } from "./irsec2026";

export type Preset = { id: string; name: string; description: string; topology: Topology };

/** Add a preset here and it shows up in the picker on the boxes page. */
export const PRESETS: Preset[] = [
  {
    id: "irsec-2026",
    name: "irsec 2026",
    description: "11 boxes across a lan and a cloud range, plus the management network and datadog's ranges as trusted. some ports are guesses, see the box notes.",
    topology: IRSEC_2026,
  },
];
