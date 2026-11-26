import { describe, expect, it } from "vitest";
import { formatPorts, groupProtocols, splitTokens } from "../../components/features/protect/protocols";

interface Entry {
  name: string;
  family: string;
}

const entries: Entry[] = [
  { name: "MQTT", family: "mqtt" },
  { name: "Modbus TCP", family: "modbus" },
  { name: "MQTT/TLS", family: "mqtt" },
  { name: "DNP3", family: "dnp3" },
];

describe("IoT/OT protocol registry helpers", () => {
  it("groups registry entries by family while preserving API order", () => {
    const groups = groupProtocols(entries, (entry) => entry.family);
    expect(groups.map((group) => group.key)).toEqual(["mqtt", "modbus", "dnp3"]);
    expect(groups[0].items.map((entry) => entry.name)).toEqual(["MQTT", "MQTT/TLS"]);
    expect(groups[1].items).toHaveLength(1);
  });

  it("groups entries with a blank key under a stable fallback", () => {
    const groups = groupProtocols([{ name: "Unknown", family: " " }], (entry) => entry.family);
    expect(groups).toHaveLength(1);
    expect(groups[0].key).toBe("unknown");
  });

  it("splits comma separated tokens, trims them and removes case-insensitive duplicates", () => {
    expect(splitTokens(" MQTT, CoAP ,mqtt,\nModbus TCP ;; ")).toEqual(["MQTT", "CoAP", "Modbus TCP"]);
    expect(splitTokens("   ")).toEqual([]);
  });

  it("renders protocol ports without inventing a default port", () => {
    expect(formatPorts([1883, 8883])).toBe("1883, 8883");
    expect(formatPorts([])).toBe("—");
  });
});
