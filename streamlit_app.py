
import streamlit as st
import os
import sys

import json
import time
try:
    from celery.result import AsyncResult
except ImportError:
    # Fallback for IDE resolution issues or environment mismatches
    import celery
    AsyncResult = celery.result.AsyncResult

import modules.security_engine as engine_mod
from modules.reporting import create_pdf_report

st.set_page_config(page_title="Network Security Dashboard", layout="wide")
st.title("Network Health & Vulnerability Scanner")

# --- Sidebar: Scan Configuration ---
st.sidebar.header("Scan Settings")
scan_mode = st.sidebar.selectbox("Execution Mode", ["Asynchronous (Celery)", "Synchronous (Direct)"])
es_host = st.sidebar.text_input("Elasticsearch Host", "http://localhost:9200")
webhook_url = st.sidebar.text_input("Webhook URL", "https://your-webhook-url.com")

st.sidebar.divider()
st.sidebar.subheader("Active Modules")

# Mapping display names to Module Classes
available_modules = {
    "HTTP Security Headers": engine_mod.WebHeaderAuditModule(),
    "Port & Service Discovery": engine_mod.PortDiscoveryModule(),
    "SSL/TLS Security Audit": engine_mod.SSLAuditModule(),
    "Cookie Security Audit": engine_mod.CookieSecurityModule(),
    "Subdomain Discovery": engine_mod.SubdomainDiscoveryModule(),
    "Sensitive File Probe": engine_mod.SensitiveFileModule(),
    "Service Fingerprinting": engine_mod.ServiceFingerprintModule(),
    "IP Reputation": engine_mod.IPReputationModule(),
    "WHOIS Lookup": engine_mod.WhoisLookupModule(),
    "DNS Health & Integrity": engine_mod.DNSIntegrityModule(),
    "Ping Reachability": engine_mod.PingModule(),
    "Traceroute Path": engine_mod.TracerouteModule()
}

selected_module_names = st.sidebar.multiselect(
    "Select Modules to Run",
    options=list(available_modules.keys()),
    default=list(available_modules.keys())
)

target = st.text_input("Enter Target Host (e.g., google.com)", "scanme.nmap.org")
run_btn = st.button("Start Security Audit", type="primary")

def render_report(report):
    """Helper function to render the scan results."""
    col1, col2, col3 = st.columns(3)
    score = report.get('overall_health_score', 0)
    score_delta = score - 100
    
    col1.metric("Health Score", f"{score}/100", delta=f"{score_delta}" if score_delta != 0 else None, delta_color="inverse")
    
    status_color = "normal" if report['status'] == "Healthy" else "inverse"
    col2.metric("Status", report['status'], delta="Action Required" if report['status'] != "Healthy" else "Secure", delta_color=status_color)
    col3.metric("Resolved IP", report.get('resolved_ip', 'N/A'))
    
    st.subheader("Detailed Findings")
    severity_colors = {"CRITICAL": "violet", "HIGH": "red", "MEDIUM": "orange", "LOW": "blue", "INFO": "green"}

    for module, findings in report['detailed_findings'].items():
        with st.expander(f"{module} ({len(findings)})"):
            for f in findings:
                sev = f['severity']
                color = severity_colors.get(sev, "grey")
                st.markdown(f"**:{color}[{sev}]** — {f['title']}")
                st.write(f['description'])
                st.info(f"**Mitigation:** {f['mitigation']}")

def _render_export_section(report, target):
    """Helper function to render the export buttons."""
    st.subheader("Export Scan Results")
    col_json, col_pdf = st.columns(2)
    
    report_json = json.dumps(report, indent=4)
    col_json.download_button(
        label="Download JSON Report",
        data=report_json,
        file_name=f"security_report_{target}.json",
        mime="application/json"
    )
    
    pdf_data = create_pdf_report(report)
    if pdf_data:
        col_pdf.download_button(
            label="Download PDF Report",
            data=pdf_data,
            file_name=f"security_report_{target}.pdf",
            mime="application/pdf"
        )

# Streamlit re-runs the entire script on every user interaction.
# We store the task_id in session_state to track progress across reruns.
if (run_btn or 'task_id' in st.session_state) and scan_mode == "Asynchronous (Celery)":
    if run_btn:
        st.info(f"Queuing asynchronous scan for {target}...")
        
        # Dispatch the task to the Celery worker
        task = engine_mod.run_async_scan.delay(
            target, 
            webhook_url=webhook_url,
            es_host=es_host,
            selected_modules=selected_module_names
        )
        st.session_state.task_id = task.id

    # Re-connect to the task using its ID and the Celery app instance
    result = AsyncResult(st.session_state.task_id, app=engine_mod.celery_app)
    
    status_placeholder = st.empty()
    
    if not result.ready():
        status_placeholder.text(f"Scanning in progress... (Task ID: {st.session_state.task_id})")
        time.sleep(2) # Polling interval
        st.rerun() # Refresh the UI to check status again
    else:
        status_placeholder.success("Scan Complete!")
        report = result.result
        
        # Safely clear the task ID to prevent infinite loops
        if 'task_id' in st.session_state: 
            st.session_state.pop('task_id', None)
        
        render_report(report)
        st.divider()
        _render_export_section(report, target)

elif run_btn and scan_mode == "Synchronous (Direct)":
    st.info(f"Running direct scan for {target}...")
    progress_bar = st.progress(0)
    status_text = st.empty()

    def update_progress(current, total, module_name):
        progress = (current + 1) / total
        progress_bar.progress(progress)
        status_text.text(f"Running: {module_name}...")

    selected_instances = [available_modules[name] for name in selected_module_names]
    engine = engine_mod.SecurityDashboardEngine(target, selected_modules=selected_instances)
    report = engine.run_assessment(progress_callback=update_progress)
    
    status_text.success("Scan Complete!")
    render_report(report)
    st.divider()
    _render_export_section(report, target)