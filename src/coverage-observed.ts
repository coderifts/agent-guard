/**
 * Coverage attestation — what the guard MEASURED about tool traffic, not what it
 * assumed at registration time.
 *
 * Half A (always): counts execute() through the returned table (governed_calls / tools).
 * Half B (optional host report): total_calls / ungoverned_* — OMITTED when the host
 * never reported, never zero. Absence ≠ zero.
 *
 * Observation only. Not a verdict input. Not a preimage field.
 *
 * Run scope: one withCodeRifts instance (same lifetime as receipt_thread). There is
 * no process-wide session; this is the smallest honest run.
 */
'use strict';

export type CoverageObservedClass =
  | 'UNKNOWN_OUTSIDE_SCOPE'
  | 'INCOMPLETE_OBSERVED'
  | 'COMPLETE_OBSERVED';

export type CoverageDispatch = {
  name: string;
  /** Host timestamp if they have one. Accepted and discarded — the snapshot is counts, not a trail. */
  at?: string;
};

type CoverageObservedBase = {
  governed_calls: number;
  tools: readonly string[];
};

export type CoverageObservedUnknown = CoverageObservedBase & {
  class: 'UNKNOWN_OUTSIDE_SCOPE';
};

export type CoverageObservedIncomplete = CoverageObservedBase & {
  class: 'INCOMPLETE_OBSERVED';
  total_calls: number;
  ungoverned_calls: number;
  ungoverned_tools: readonly string[];
};

export type CoverageObservedComplete = CoverageObservedBase & {
  class: 'COMPLETE_OBSERVED';
  total_calls: number;
  ungoverned_calls: number;
  ungoverned_tools: readonly string[];
};

export type CoverageObserved =
  | CoverageObservedUnknown
  | CoverageObservedIncomplete
  | CoverageObservedComplete;

export type CoverageObservedHandle = {
  snapshot: () => CoverageObserved;
  reportToolDispatch: (ev: CoverageDispatch) => void;
  reportToolDispatchBatch: (evs: readonly CoverageDispatch[]) => void;
};

export type CoverageObserver = {
  setTableNames: (names: readonly string[]) => void;
  recordGoverned: (name: string) => void;
  snapshot: () => CoverageObserved;
  handle: CoverageObservedHandle;
};

function uniqueInOrder(names: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const n of names) {
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

export function createCoverageObserver(): CoverageObserver {
  const table = new Set<string>();
  const governed: string[] = [];
  const host: string[] = [];
  let hostReported = false;

  function snapshot(): CoverageObserved {
    const tools = uniqueInOrder(governed);
    if (!hostReported) {
      return freezeCoverageObserved({
        class: 'UNKNOWN_OUTSIDE_SCOPE',
        governed_calls: governed.length,
        tools,
      });
    }
    const ungovernedList = host.filter((n) => !table.has(n));
    if (ungovernedList.length > 0) {
      return freezeCoverageObserved({
        class: 'INCOMPLETE_OBSERVED',
        governed_calls: governed.length,
        tools,
        total_calls: host.length,
        ungoverned_calls: ungovernedList.length,
        ungoverned_tools: uniqueInOrder(ungovernedList),
      });
    }
    return freezeCoverageObserved({
      class: 'COMPLETE_OBSERVED',
      governed_calls: governed.length,
      tools,
      total_calls: host.length,
      ungoverned_calls: 0,
      ungoverned_tools: [],
    });
  }

  function reportOne(ev: CoverageDispatch | null | undefined): boolean {
    if (!ev || typeof ev.name !== 'string') return false;
    const name = ev.name.trim();
    if (!name) return false;
    host.push(name);
    return true;
  }

  const handle: CoverageObservedHandle = {
    snapshot,
    reportToolDispatch(ev) {
      if (reportOne(ev)) hostReported = true;
    },
    reportToolDispatchBatch(evs) {
      // An actual array (including []) is a supplied report. A non-array is not.
      if (!Array.isArray(evs)) return;
      hostReported = true;
      for (const ev of evs) reportOne(ev);
    },
  };

  return {
    setTableNames(names) {
      table.clear();
      if (!Array.isArray(names) && !names) return;
      for (const n of names) {
        if (typeof n === 'string' && n) table.add(n);
      }
    },
    recordGoverned(name) {
      if (typeof name === 'string' && name) governed.push(name);
    },
    snapshot,
    handle,
  };
}

export function freezeCoverageObserved(obs: CoverageObserved): CoverageObserved {
  const tools = Object.freeze(obs.tools.slice());
  if (obs.class === 'UNKNOWN_OUTSIDE_SCOPE') {
    return Object.freeze({
      class: 'UNKNOWN_OUTSIDE_SCOPE',
      governed_calls: obs.governed_calls,
      tools,
    });
  }
  return Object.freeze({
    class: obs.class,
    governed_calls: obs.governed_calls,
    tools,
    total_calls: obs.total_calls,
    ungoverned_calls: obs.ungoverned_calls,
    ungoverned_tools: Object.freeze((obs.ungoverned_tools || []).slice()),
  });
}

/**
 * Proof / T3 human line. Half B absent vs named ungoverned vs complete host report.
 */
export function formatCoverageObservedLine(obs: CoverageObserved): string {
  const n = obs.governed_calls;
  const callWord = n === 1 ? 'call' : 'calls';
  if (obs.class === 'UNKNOWN_OUTSIDE_SCOPE') {
    return `governed ${n} ${callWord}; traffic outside the guarded table not observable from here`;
  }
  if (obs.class === 'INCOMPLETE_OBSERVED') {
    const names = obs.ungoverned_tools.join(', ');
    return (
      `governed ${n}/${obs.total_calls} dispatched calls; `
      + `${obs.ungoverned_calls} outside the guarded table: ${names}`
    );
  }
  return `governed ${n}/${obs.total_calls} dispatched calls; 0 outside the guarded table`;
}
