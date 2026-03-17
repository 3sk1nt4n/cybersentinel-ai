"""
Tests for app.core.intent - detect_intent() pattern matching.
"""
from app.core.intent import detect_intent


class TestNmapIntent:
    def test_nmap_scan_detected(self):
        """'nmap scan scanme.nmap.org' should detect nmap_scan with correct target."""
        result = detect_intent("nmap scan scanme.nmap.org")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "nmap_scan" in tools
        assert result["tools"][0]["args"]["target"] == "scanme.nmap.org"


class TestDnsReconIntent:
    def test_dns_recon_detected(self):
        """'dns recon on google.com' should detect dns_recon."""
        result = detect_intent("dns recon on google.com")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "dns_recon" in tools


class TestSslCheckIntent:
    def test_ssl_check_detected(self):
        """'check ssl for example.com' should detect ssl_check."""
        result = detect_intent("check ssl for example.com")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "ssl_check" in tools


class TestShodanIntent:
    def test_shodan_lookup_detected(self):
        """'shodan lookup 8.8.8.8' should detect shodan_lookup."""
        result = detect_intent("shodan lookup 8.8.8.8")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "shodan_lookup" in tools


class TestNoIntent:
    def test_hello_returns_none(self):
        """A plain greeting should not match any tool intent."""
        result = detect_intent("hello")
        assert result is None


class TestFullDomainScan:
    def test_full_scan_multi_tool(self):
        """'full scan on example.com' should produce multiple tools."""
        result = detect_intent("full scan on example.com")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert len(tools) > 1
        # Full domain scan triggers nmap, ssl, dns, headers
        assert "nmap_scan" in tools
        assert "ssl_check" in tools
        assert "dns_recon" in tools
        assert "http_headers" in tools


class TestElkIntent:
    def test_elk_failed_logins_detected(self):
        """'elk failed logins' should detect elk_failed_logins."""
        result = detect_intent("elk failed logins")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "elk_failed_logins" in tools


class TestCveLookupIntent:
    def test_cve_lookup_detected(self):
        """'check CVE-2024-1234' should detect nvd_cve_lookup."""
        result = detect_intent("check CVE-2024-1234")
        assert result is not None
        tools = [t["tool"] for t in result["tools"]]
        assert "nvd_cve_lookup" in tools
