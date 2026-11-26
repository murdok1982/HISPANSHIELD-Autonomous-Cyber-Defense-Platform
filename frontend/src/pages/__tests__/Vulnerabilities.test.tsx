import { describe, expect, it } from "vitest";
import {
  allowedStatusTargets,
  parseCveImport,
  parseEpssImport,
  parseKevImport,
  priorityBand,
  toCveItems,
  toEpssItems,
} from "../Vulnerabilities";

describe("vulnerability status transitions", () => {
  it("mirrors the server matrix for open findings", () => {
    const targets = allowedStatusTargets("open");
    expect(targets).toEqual(expect.arrayContaining(["mitigated", "accepted", "false_positive", "reopened"]));
    expect(targets).not.toContain("open");
  });

  it("only allows reopening once mitigated", () => {
    expect(allowedStatusTargets("mitigated")).toEqual(["open", "reopened"]);
    expect(allowedStatusTargets("false_positive")).toEqual(["open", "reopened"]);
  });

  it("returns no targets for an unknown status", () => {
    expect(allowedStatusTargets("archived")).toEqual([]);
  });
});

describe("priority bands", () => {
  it("buckets the 0-100 score", () => {
    expect(priorityBand(0)).toBe("low");
    expect(priorityBand(29.9)).toBe("low");
    expect(priorityBand(30)).toBe("medium");
    expect(priorityBand(50)).toBe("high");
    expect(priorityBand(69.9)).toBe("high");
    expect(priorityBand(70)).toBe("critical");
    expect(priorityBand(100)).toBe("critical");
  });
});

describe("CVE import parsing", () => {
  it("accepts a bounded array of CVE records", () => {
    const parsed = parseCveImport(
      JSON.stringify([{ cve_id: "CVE-2024-1234", description: "RCE", cvss_score: 9.8 }]),
    );
    expect("rows" in parsed).toBe(true);
    if ("rows" in parsed) {
      expect(parsed.rows).toHaveLength(1);
      expect(parsed.rows[0].cve_id).toBe("CVE-2024-1234");
    }
  });

  it("rejects malformed identifiers and missing descriptions with a row index", () => {
    expect(parseCveImport(JSON.stringify([{ cve_id: "not-a-cve", description: "x" }]))).toEqual({
      error: "invalidRow",
      row: 0,
    });
    expect(parseCveImport(JSON.stringify([{ cve_id: "CVE-2024-1234", description: "  " }]))).toEqual({
      error: "invalidRow",
      row: 0,
    });
    expect(parseCveImport("[")).toEqual({ error: "json" });
    expect(parseCveImport("[]")).toEqual({ error: "empty" });
  });

  it("keeps only contract fields so the strict API does not reject the batch", () => {
    const items = toCveItems([
      { cve_id: "CVE-2024-1234", description: "RCE", cvss_score: 9.8, kev: true, severity: "critical", junk: 1 },
    ]);
    expect(items).toEqual([{ cve_id: "CVE-2024-1234", description: "RCE", cvss_score: 9.8, kev: true }]);
  });

  it("caps imports at 500 rows", () => {
    const rows = Array.from({ length: 501 }, (_, index) => ({
      cve_id: `CVE-2024-${String(index + 1000)}`,
      description: "x",
    }));
    expect(parseCveImport(JSON.stringify(rows))).toEqual({ error: "tooMany" });
  });
});

describe("KEV import parsing", () => {
  it("accepts bare CVE identifiers", () => {
    expect(parseKevImport(JSON.stringify(["CVE-2023-1111", "CVE-2023-2222"]))).toEqual({
      cves: ["CVE-2023-1111", "CVE-2023-2222"],
    });
  });

  it("accepts CISA KEV entries with cveID", () => {
    const parsed = parseKevImport(JSON.stringify([{ cveID: "CVE-2023-1111", vendorProject: "Acme" }]));
    expect("rows" in parsed).toBe(true);
    if ("rows" in parsed) expect(parsed.rows[0].cveID).toBe("CVE-2023-1111");
  });

  it("flags invalid identifiers", () => {
    expect(parseKevImport(JSON.stringify(["CVE-XX"]))).toEqual({ error: "invalidRow", row: 0 });
    expect(parseKevImport(JSON.stringify([{ cveID: "" }]))).toEqual({ error: "invalidRow", row: 0 });
  });
});

describe("EPSS import parsing", () => {
  it("keeps CSV payloads for the server parser", () => {
    expect(parseEpssImport("CVE-2024-1234,0.97\nCVE-2024-5678,0.42")).toEqual({
      csv: "CVE-2024-1234,0.97\nCVE-2024-5678,0.42",
    });
  });

  it("normalises JSON rows", () => {
    const parsed = parseEpssImport(JSON.stringify([{ cve: "CVE-2024-1234", epss: 0.5 }]));
    expect("rows" in parsed).toBe(true);
    if ("rows" in parsed) expect(parsed.rows).toHaveLength(1);
  });

  it("drops non-numeric EPSS values before sending", () => {
    expect(toEpssItems([{ cve: "CVE-2024-1234", epss: 0.5, percentile: 0.9, extra: "x" }])).toEqual([
      { cve: "CVE-2024-1234", epss: 0.5, percentile: 0.9 },
    ]);
  });

  it("rejects out-of-range probabilities and malformed rows", () => {
    expect(parseEpssImport("CVE-2024-1234,1.5")).toEqual({ error: "invalidRow", row: 0 });
    expect(parseEpssImport("nope,0.2")).toEqual({ error: "invalidRow", row: 0 });
    expect(parseEpssImport(JSON.stringify([{ cve: "CVE-2024-1234" }]))).toEqual({ error: "invalidRow", row: 0 });
    expect(parseEpssImport("   ")).toEqual({ error: "empty" });
  });
});
