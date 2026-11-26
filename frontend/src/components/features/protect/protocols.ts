/**
 * Pure presentation helpers for the IoT/OT protocol registry.
 * Kept free of React so they can be unit-tested without providers.
 */

export interface ProtocolGroup<T> {
  key: string;
  items: T[];
}

/** Group registry rows by a stable key while preserving the API ordering. */
export function groupProtocols<T>(items: T[], keyOf: (item: T) => string): ProtocolGroup<T>[] {
  const groups: ProtocolGroup<T>[] = [];
  const index = new Map<string, ProtocolGroup<T>>();
  for (const item of items) {
    const raw = keyOf(item);
    const key = raw && raw.trim() ? raw.trim() : "unknown";
    let group = index.get(key);
    if (!group) {
      group = { key, items: [] };
      index.set(key, group);
      groups.push(group);
    }
    group.items.push(item);
  }
  return groups;
}

/** Render protocol ports, tolerating registries that expose no TCP/UDP port. */
export function formatPorts(ports: number[]): string {
  if (!ports || ports.length === 0) return "—";
  return ports.join(", ");
}

/** Normalise a comma or newline separated token list (protocols, tags, IPs). */
export function splitTokens(value: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const token of value.split(/[,\n;]+/)) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    const lower = trimmed.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);
    result.push(trimmed);
  }
  return result;
}
