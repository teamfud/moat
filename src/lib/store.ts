"use client";

import { useSyncExternalStore } from "react";
import { DEFAULT_POLICY, type Policy, type Target, type Topology } from "@/lib/fw/model";
import { parseTopology } from "@/lib/fw/serialize";

/**
 * Everything lives in this browser's localStorage: there's no server. Share a
 * topology with teammates through export / import.
 */
export type State = {
  topo: Topology;
  policy: Policy;
  /** Firewall picked per box id, when it isn't the OS default. */
  targets: Record<string, Target>;
  blockInput: string;
  whiteTeamOk: boolean;
};

const KEY = "fud-moat:v1";
const EMPTY: Topology = { name: "untitled", team: 1, scope: [], trusted: [], adminSources: [], boxes: [] };
const initial: State = { topo: EMPTY, policy: DEFAULT_POLICY, targets: {}, blockInput: "", whiteTeamOk: false };

let state: State | null = null;
const listeners = new Set<() => void>();

function load(): State {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return initial;
    const s = JSON.parse(raw) as Partial<State>;
    return {
      topo: parseTopology(s.topo),
      policy: { ...DEFAULT_POLICY, ...s.policy },
      targets: s.targets ?? {},
      blockInput: typeof s.blockInput === "string" ? s.blockInput : "",
      whiteTeamOk: s.whiteTeamOk === true,
    };
  } catch {
    return initial;
  }
}

function get() {
  return (state ??= load());
}

export function update(fn: (s: State) => State) {
  state = fn(get());
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    // private window or storage blocked: still works, just forgets on reload
  }
  listeners.forEach((l) => l());
}

const subscribe = (l: () => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

export function useStore() {
  return useSyncExternalStore(subscribe, get, () => initial);
}

export const setTopo = (fn: (t: Topology) => Topology) => update((s) => ({ ...s, topo: fn(s.topo) }));

const noop = () => () => {};

/** False during the static prerender and hydration, true after. Pages wait for it so they never flash the preset over saved state. */
export function useHydrated() {
  return useSyncExternalStore(
    noop,
    () => true,
    () => false,
  );
}
