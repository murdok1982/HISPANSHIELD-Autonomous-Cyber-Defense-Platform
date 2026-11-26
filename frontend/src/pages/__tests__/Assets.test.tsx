import { describe, expect, it } from "vitest";
import {
  buildAssetPayload,
  emptyAssetDraft,
  parseAssetImportText,
  validateAssetDraft,
  type AssetDraft,
} from "../Assets";
import { isIpAddress, parseCommaList } from "../../components/features/detect/shared";

function draft(overrides: Partial<AssetDraft> = {}): AssetDraft {
  return {
    ...emptyAssetDraft(),
    name: "Core switch",
    asset_key: "net.core-sw01",
    kind: "network",
    criticality: "4",
    environment: "production",
    ips: "10.0.0.1, 10.0.0.2",
    owner: "Network team",
    tags: "core, dc1",
    ...overrides,
  };
}

describe("asset draft validation", () => {
  it("requires a name and a valid asset key", () => {
    const errors = validateAssetDraft(emptyAssetDraft());
    expect(errors.name).toBeTruthy();
    expect(errors.asset_key).toBe("required");

    expect(validateAssetDraft(draft({ asset_key: "invalid key!" })).asset_key).toBe("pattern");
  });

  it("rejects out-of-range criticality and malformed IP addresses", () => {
    expect(validateAssetDraft(draft({ criticality: "9" })).criticality).toBe("range:1-5");
    expect(validateAssetDraft(draft({ ips: "10.0.0.1, not-an-ip" })).ip_addresses).toBe("ip");
  });

  it("accepts a complete draft", () => {
    expect(validateAssetDraft(draft())).toEqual({});
    expect(validateAssetDraft(draft({ ips: "2001:db8::1" }))).toEqual({});
  });
});

describe("buildAssetPayload", () => {
  it("trims fields, splits lists and sends null for empty optionals", () => {
    const payload = buildAssetPayload(draft({ owner: "  ", subtype: "  ", zone_id: "", tags: "core, core, dc1" }));
    expect(payload.name).toBe("Core switch");
    expect(payload.asset_key).toBe("net.core-sw01");
    expect(payload.criticality).toBe(4);
    expect(payload.ip_addresses).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(payload.owner).toBeNull();
    expect(payload.subtype).toBeNull();
    expect(payload.zone_id).toBeNull();
    expect(payload.tags).toEqual(["core", "dc1"]);
  });

  it("keeps a provided zone identifier", () => {
    const zone = "5d6a1f8e-2b8f-4d3b-9a12-3c4d5e6f7a8b";
    expect(buildAssetPayload(draft({ zone_id: zone })).zone_id).toBe(zone);
  });
});

describe("parseAssetImportText", () => {
  it("accepts an array and an items wrapper", () => {
    const row = { asset_key: "a-1", name: "A", kind: "host" };
    expect(parseAssetImportText(JSON.stringify([row]))).toEqual({ items: [row] });
    expect(parseAssetImportText(JSON.stringify({ items: [row] }))).toEqual({ items: [row] });
  });

  it("reports malformed input without throwing", () => {
    expect(parseAssetImportText("")).toEqual({ error: "empty" });
    expect(parseAssetImportText("{oops")).toEqual({ error: "json" });
    expect(parseAssetImportText(JSON.stringify({ nope: true }))).toEqual({ error: "shape" });
    expect(parseAssetImportText(JSON.stringify([1, 2]))).toEqual({ error: "shape" });
  });

  it("caps the batch at 500 rows", () => {
    const rows = Array.from({ length: 501 }, (_, index) => ({ asset_key: `a-${index}` }));
    expect(parseAssetImportText(JSON.stringify(rows))).toEqual({ error: "tooMany" });
  });
});

describe("list helpers", () => {
  it("de-duplicates comma lists case-insensitively", () => {
    expect(parseCommaList("A, a, b ,,")).toEqual(["A", "b"]);
  });

  it("validates IPv4 and IPv6 literals", () => {
    expect(isIpAddress("10.0.0.1")).toBe(true);
    expect(isIpAddress("256.1.1.1")).toBe(false);
    expect(isIpAddress("2001:db8::1")).toBe(true);
    expect(isIpAddress("not-an-ip")).toBe(false);
  });
});
