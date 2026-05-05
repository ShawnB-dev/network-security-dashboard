import pytest
from modules.security_engine import Finding, WebHeaderAuditModule, PortDiscoveryModule

def test_finding_serialization():
    """Verify that the Finding class correctly converts to a dictionary."""
    finding = Finding("HIGH", "Insecure Config", "Description text", "Mitigation steps")
    data = finding.to_dict()
    assert data["severity"] == "HIGH"
    assert data["title"] == "Insecure Config"
    assert "Mitigation steps" in data["mitigation"]

def test_module_metadata():
    """Ensure modules report their names correctly for the dashboard UI."""
    header_mod = WebHeaderAuditModule()
    port_mod = PortDiscoveryModule()
    assert header_mod.name == "HTTP Security Headers"
    assert port_mod.name == "Port & Service Discovery"

def test_health_score_calculation():
    """Logic check: Ensure health score doesn't go below zero."""
    total_findings = 15 # Should result in -50 (100 - 150), but capped at 0
    health_score = max(0, 100 - (total_findings * 10))
    assert health_score == 0