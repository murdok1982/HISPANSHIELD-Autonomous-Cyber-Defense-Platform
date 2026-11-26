# ADR-014 — Parse untrusted scanner XML with defusedxml

- **Status:** Accepted (2026-11-26)
- **Context:** The Nessus and OpenVAS importers accept XML produced by external
  scanners. `xml.etree.ElementTree` is not hardened against entity-expansion
  bombs, and static analysis (Bandit B314) correctly flags it. The project needs
  an offline-capable, audited parser without a large dependency footprint.

## Decision

Add `defusedxml==0.7.1` (pure Python, MPL-2.0) and use its `ElementTree`
wrapper. Defense in depth also rejects any input containing `<!DOCTYPE` or
`<!ENTITY` before parsing and caps report size at 20 MB in the request schema.

## Alternatives rejected

- **Silence Bandit with `# nosec`:** hides a real class of parser risk and would
  not survive an independent review.
- **lxml:** heavier native dependency, larger image, no additional requirement
  for the subset needed here.
- **Hand-written XML parser:** higher risk and maintenance cost.

## Consequences

- XML entity attacks are rejected with a 422 `validation_error`, not a 500.
- The dependency is test/import-path only; it is not exposed in the browser
  bundle and is recorded in the CycloneDX SBOM.
