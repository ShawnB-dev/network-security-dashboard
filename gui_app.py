import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import json
import ctypes

# Make the application DPI aware for sharper rendering on high-resolution screens (Windows)
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1) # Per monitor DPI awareness
except AttributeError:
    pass # Not on Windows or older Windows version
import modules.security_engine as engine_mod
import threading

# Simplified import using the new security_engine.py module name
stop_event = None

# Import ttkthemes for dark mode
try:
    from ttkthemes import ThemedTk
except ImportError:
    ThemedTk = tk.Tk # Fallback if ttkthemes is not installed
MODULE_OPTIONS = {
    "Port Discovery": engine_mod.PortDiscoveryModule,
    "SSL Audit": engine_mod.SSLAuditModule,
    "DNS Integrity": engine_mod.DNSIntegrityModule,
    "Web Header Audit": engine_mod.WebHeaderAuditModule,
    "Cookie Security": engine_mod.CookieSecurityModule,
    "Sensitive Files": engine_mod.SensitiveFileModule,
    "Fingerprinting": engine_mod.ServiceFingerprintModule,
    "IP Reputation": engine_mod.IPReputationModule,
    "WHOIS Lookup": engine_mod.WhoisLookupModule,
    "Subdomain Discovery": engine_mod.SubdomainDiscoveryModule,
    "Ping Reachability": engine_mod.PingModule,
    "Traceroute Path": engine_mod.TracerouteModule
}

def cancel_scan():
    global stop_event
    if stop_event:
        stop_event.set()
        log_area.insert(tk.END, "[!] Cancellation requested...\n")

def run_scan():
    global stop_event
    target = entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target")
        return

    selected_instances = [cls() for name, cls in MODULE_OPTIONS.items() if module_vars[name].get()]
    if not selected_instances:
        messagebox.showwarning("Warning", "Please select at least one module to run.")
        return
    
    stop_event = threading.Event()

    def update_progress(current, total, module_name):
        # Calculate percentage and schedule UI update on the main thread
        percent = (current / total) * 100
        def update_ui():
            progress_bar.config(value=percent)
            status_label.config(text=f"Executing: {module_name}")
        root.after(0, update_ui)

    def execute():
        btn.config(state=tk.DISABLED)
        cancel_btn.config(state=tk.NORMAL)
        progress_bar.config(value=0) # Reset progress bar
        
        def start_ui_log():
            # Capture the current end position so we can scroll it to the top
            start_pos = log_area.index(tk.END)
            log_area.insert(tk.END, f"[*] Scanning {target}...\n")
            log_area.yview(start_pos) # Move the focus so this new scan is at the top

        root.after(0, start_ui_log)
        
        engine = engine_mod.SecurityDashboardEngine(target, stop_event=stop_event, selected_modules=selected_instances)
        report = engine.run_assessment(progress_callback=update_progress)
        
        if report.get("status") == "Cancelled":
            root.after(0, lambda: log_area.insert(tk.END, "[!] Scan was cancelled by user.\n"))
            root.after(0, lambda: status_label.config(text="Status: Cancelled"))
        else:
            def finalize_ui():
                log_area.insert(tk.END, f"[!] Scan Complete. Score: {report['overall_health_score']}\n")
                
                for module_name, findings in report.get("detailed_findings", {}).items():
                    log_area.insert(tk.END, f"\n--- {module_name} ---\n")
                    if not findings:
                        log_area.insert(tk.END, "No findings detected.\n")
                        continue
                    for f in findings:
                        severity = f.get('severity', 'INFO')
                        log_area.insert(tk.END, f"[{severity}] ", severity)
                        log_area.insert(tk.END, f"{f['title']}\n")
                        log_area.insert(tk.END, f"   Description: {f['description']}\n")
                        log_area.insert(tk.END, f"   Mitigation: {f['mitigation']}\n")
                log_area.see(tk.END)
                log_area.insert(tk.END, "\n" + "="*40 + "\n")
                
                status_label.config(text="Status: Complete")
                btn.config(state=tk.NORMAL)
                cancel_btn.config(state=tk.DISABLED)
            root.after(0, finalize_ui)

    threading.Thread(target=execute, daemon=True).start()

try:
    root = ThemedTk(theme="black")
except Exception:
    root = tk.Tk()

root.title("Network Security Engine")
root.geometry("600x500")

# Force the root window and global styles to a dark palette
dark_bg = "#1e1e1e"
light_fg = "#ffffff"
root.configure(background=dark_bg)

style = ttk.Style(root)
style.configure("TFrame", background=dark_bg)
style.configure("TLabel", background=dark_bg, foreground=light_fg)
style.configure("TCheckbutton", background=dark_bg, foreground=light_fg)
style.configure("TEntry", fieldbackground="#333333", foreground=light_fg)

# Define a custom style for the progress bar to make the indicator white
style.configure("White.Horizontal.TProgressbar", 
                background="white", 
                troughcolor="#333333")

ttk.Label(root, text="Target Host:").pack(pady=5)
entry = ttk.Entry(root, width=50)
entry.insert(0, "scanme.nmap.org")
entry.pack(pady=5)

# Use ttk.Label for theme consistency
ttk.Label(root, text="Select Modules to Run:").pack(pady=2)
# Use ttk.Frame for theme consistency
module_frame = ttk.Frame(root)
module_frame.pack(pady=5)

# Create a grid for checkboxes to prevent them from running off-screen
module_vars = {}
for i, name in enumerate(MODULE_OPTIONS.keys()):
    var = tk.BooleanVar(value=True)
    module_vars[name] = var
    row = i // 3
    col = i % 3
    ttk.Checkbutton(module_frame, text=name, variable=var, style="TCheckbutton").grid(row=row, column=col, sticky="w", padx=5)

btn = ttk.Button(root, text="Run Assessment", command=run_scan, style="TButton") # Use ttk.Button for themed styling
btn.pack(pady=10)

cancel_btn = ttk.Button(root, text="Cancel Scan", command=cancel_scan, state=tk.DISABLED, style="TButton")
cancel_btn.pack(pady=5)

status_label = ttk.Label(root, text="Status: Ready", font=("Helvetica", 10))
status_label.pack(pady=2)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", style="White.Horizontal.TProgressbar")
progress_bar.pack(pady=5)

log_area = scrolledtext.ScrolledText(root, width=70, height=20, bg="#121212", fg=light_fg, insertbackground="white")
log_area.pack(pady=10)

log_area.tag_config("CRITICAL", foreground="purple", font=("Helvetica", 10, "bold"))
log_area.tag_config("HIGH", foreground="red", font=("Helvetica", 10, "bold"))
log_area.tag_config("MEDIUM", foreground="orange", font=("Helvetica", 10, "bold"))
log_area.tag_config("LOW", foreground="cyan")
log_area.tag_config("INFO", foreground="green")

root.mainloop()