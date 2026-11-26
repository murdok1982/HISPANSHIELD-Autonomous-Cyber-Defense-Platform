"""Scanner parsers: Nessus XML, OpenVAS XML and Trivy JSON."""

from __future__ import annotations

import json

import pytest

from app.core.errors import ValidationFailure
from app.modules.vulnerabilities.importers import parse_nessus, parse_openvas, parse_trivy

NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="10.0.0.10">
      <ReportItem port="443" protocol="tcp" severity="3" pluginID="12345" pluginName="Weak TLS cipher">
        <cve>CVE-2024-1234</cve>
        <cvss3_base_score>7.5</cvss3_base_score>
        <description>The service negotiates a weak cipher.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

OPENVAS = """<report>
  <results>
    <result>
      <host>10.0.0.10</host>
      <port>22/tcp</port>
      <threat>High</threat>
      <severity>8.1</severity>
      <description>SSH configuration issue</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.100001">
        <name>SSH weak configuration</name>
        <cvss_base>8.1</cvss_base>
        <refs><ref type="cve" id="CVE-2023-9999"/></refs>
      </nvt>
    </result>
  </results>
</report>
"""


def _trivy() -> str:
    return json.dumps(
        {
            "ArtifactName": "10.0.0.10",
            "Results": [
                {
                    "Target": "10.0.0.10",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.1",
                            "FixedVersion": "3.0.2",
                            "Severity": "HIGH",
                            "Title": "OpenSSL issue",
                            "Description": "Buffer overflow",
                            "CVSS": {"nvd": {"V3Score": 9.8}},
                        }
                    ],
                }
            ],
        }
    )


def test_parse_nessus_maps_cve_port_and_cvss() -> None:
    result = parse_nessus(NESSUS)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cve == "CVE-2024-1234"
    assert finding.port == 443
    assert finding.protocol == "tcp"
    assert finding.cvss == 7.5
    assert finding.severity == "high"
    assert finding.plugin_id == "12345"


def test_parse_openvas_maps_nvt_and_refs() -> None:
    result = parse_openvas(OPENVAS)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.host == "10.0.0.10"
    assert finding.cve == "CVE-2023-9999"
    assert finding.port == 22
    assert finding.cvss == 8.1
    assert finding.metadata["oid"].startswith("1.3.6.1")


def test_parse_trivy_picks_highest_cvss() -> None:
    result = parse_trivy(_trivy())
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cve == "CVE-2024-1234"
    assert finding.cvss == 9.8
    assert finding.severity == "critical"
    assert finding.package == "openssl"


def test_xml_with_entities_is_rejected() -> None:
    bomb = """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><report><results/></report>"""
    with pytest.raises(ValidationFailure):
        parse_nessus(bomb)
    with pytest.raises(ValidationFailure):
        parse_openvas(bomb)


def test_invalid_trivy_json_is_rejected() -> None:
    with pytest.raises(ValidationFailure):
        parse_trivy("{not json")
