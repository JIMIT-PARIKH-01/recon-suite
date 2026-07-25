"""Offline tests for the Recon Suite."""

from recon_suite import portscan, headers, subdomains, pipeline, report


def test_parse_ports_variants():
    assert portscan.parse_ports("top") == list(portscan.TOP_PORTS)
    assert len(portscan.parse_ports("1-100")) == 100
    assert portscan.parse_ports("22,80,443,8000-8002") == [22, 80, 443, 8000, 8001, 8002]


def test_parse_ports_clamps():
    assert all(0 < p <= 65535 for p in portscan.parse_ports("0,80,70000"))


def test_header_grade_bands():
    total = len(headers.SECURITY_HEADERS)
    assert headers._grade(total) == "A"      # all present -> A
    assert headers._grade(0) == "F"          # none present -> F
    assert total >= 9                         # now audits COOP/COEP/CORP too


def test_subdomain_parse_crtsh():
    mock = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "other.notexample.com"},
    ]
    subs = subdomains.parse_crtsh(mock, "example.com")
    assert "www.example.com" in subs and "api.example.com" in subs
    assert "other.notexample.com" not in subs


def test_report_markdown_renders():
    result = pipeline.ReconResult(domain="example.com")
    md = report.to_markdown(result)
    assert "example.com" in md and "Recon report" in md
