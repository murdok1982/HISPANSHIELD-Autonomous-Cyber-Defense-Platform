import { describe, expect, it } from "vitest";
import {
  ALLOWED_TRANSITIONS,
  allowedTransitions,
  formatBytes,
  isOpenStatus,
  isTransitionAllowed,
  shortSha,
  slaRemainingMinutes,
  slaState,
  transitionNeedsCloseOut,
  transitionNeedsReason,
} from "../../components/features/respond/incidents";

describe("incident lifecycle helpers", () => {
  it("mirrors the server state machine and rejects shortcuts", () => {
    expect(ALLOWED_TRANSITIONS.new).toEqual(["triage"]);
    expect(allowedTransitions("triage")).toEqual(["investigating"]);
    expect(isTransitionAllowed("new", "triage")).toBe(true);
    expect(isTransitionAllowed("new", "contained")).toBe(false);
    expect(isTransitionAllowed("recovered", "closed")).toBe(true);
    expect(isTransitionAllowed("closed", "new")).toBe(false);
    expect(allowedTransitions("closed")).toEqual([]);
  });

  it("requires a reason and close-out fields only for the documented transitions", () => {
    expect(transitionNeedsReason("contained")).toBe(true);
    expect(transitionNeedsReason("closed")).toBe(true);
    expect(transitionNeedsReason("triage")).toBe(false);
    expect(transitionNeedsCloseOut("closed")).toBe(true);
    expect(transitionNeedsCloseOut("contained")).toBe(false);
    expect(isOpenStatus("investigating")).toBe(true);
    expect(isOpenStatus("closed")).toBe(false);
  });
});

describe("incident SLA helpers", () => {
  const now = Date.parse("2026-11-26T12:00:00Z");

  it("classifies breached, at-risk, on-time and missing deadlines", () => {
    expect(slaState(null, now)).toBe("none");
    expect(slaState("2026-11-26T11:30:00Z", now)).toBe("breached");
    expect(slaState("2026-11-26T13:00:00Z", now)).toBe("at_risk");
    expect(slaState("2026-11-26T18:00:00Z", now)).toBe("ok");
    expect(slaRemainingMinutes("2026-11-26T13:00:00Z", now)).toBe(60);
    expect(slaRemainingMinutes("2026-11-26T11:30:00Z", now)).toBe(-30);
    expect(slaRemainingMinutes(null, now)).toBeNull();
  });

  it("formats evidence sizes and hashes for dense tables", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(25 * 1024 * 1024)).toBe("25 MB");
    expect(formatBytes(null)).toBe("—");
    expect(shortSha("a".repeat(64))).toBe(`${"a".repeat(12)}…${"a".repeat(4)}`);
    expect(shortSha(null)).toBe("—");
  });
});
