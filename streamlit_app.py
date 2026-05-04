import streamlit as st
import os
import json
import time
from celery.result import AsyncResult
import modules.security_engine as engine_mod
from modules.reporting import create_pdf_report

st.set_page_config(page_title="Network Security Dashboard", layout="wide")
st.title("Network Health & Vulnerability Scanner")

target = st.text_input("Enter Target Host (e.g., google.com)", "google.com")
run_btn = st.button("Start Security Audit")

# Streamlit re-runs the entire script on every user interaction.
# We store the task_id in session_state to track progress across reruns.
if run_btn or 'task_id' in st.session_state:
    if run_btn:
        st.info(f"Queuing asynchronous scan for {target}...")
        
        # Dispatch the task to the Celery worker
        task = engine_mod.run_async_scan.delay(
            target, 
            webhook_url="https://your-webhook-url.com",
            es_host="http://localhost:9200"
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

        col1, col2, col3 = st.columns(3)
        score = report.get('overall_health_score', 0)
        # Calculate delta relative to a "perfect" score of 100
        score_delta = score - 100
        
        col1.metric("Health Score", f"{score}/100", delta=f"{score_delta}" if score_delta != 0 else None, delta_color="inverse")
        
        status_color = "normal" if report['status'] == "Healthy" else "inverse"
        col2.metric("Status", report['status'], delta="Action Required" if report['status'] != "Healthy" else "Secure", delta_color=status_color)
        col3.metric("Resolved IP", report.get('resolved_ip', 'N/A'))
        
        st.subheader("Detailed Findings")

        severity_colors = {
            "CRITICAL": "violet",
            "HIGH": "red",
            "MEDIUM": "orange",
            "LOW": "blue",
            "INFO": "green"
        }

        for module, findings in report['detailed_findings'].items():
            with st.expander(f"{module} ({len(findings)})"):
                for f in findings:
                    sev = f['severity']
                    color = severity_colors.get(sev, "grey")
                    st.markdown(f"**:{color}[{sev}]** — {f['title']}")
                    st.write(f['description'])
                    st.info(f"**Mitigation:** {f['mitigation']}")
        
        st.divider()
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

        if st.button("Start New Scan"):
            del st.session_state.task_id
            st.rerun()