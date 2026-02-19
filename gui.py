import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from datetime import datetime, timedelta
import json
import schedule
import time

from scanner import PortScanner
from config import Config
from nmap_integration import nmap_available, run_nmap

# matplotlib for 3D visualization
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from mpl_toolkits.mplot3d import Axes3D

import numpy as np

# try using ttkbootstrap for modern theme
try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import *
    USING_TTKBOOTSTRAP = True
except ImportError:
    USING_TTKBOOTSTRAP = False


class PortScannerApp(tk.Tk if not USING_TTKBOOTSTRAP else tb.Window):
    """Main application window with tabbed interface."""

    def __init__(self):
        if USING_TTKBOOTSTRAP:
            super().__init__(themename="darkly")
        else:
            super().__init__()
        
        self.title("Professional TCP Port Scanner v2.0")
        self.geometry("1400x850")
        self.resizable(True, True)
        self.state('zoomed')

        # styling
        if not USING_TTKBOOTSTRAP:
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("TButton", font=("Segoe UI", 10), padding=8)
            style.configure("TLabel", font=("Segoe UI", 10))
            style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"))
            style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
            style.configure("Stat.TLabel", font=("Segoe UI", 11))

        # Data structures
        self.scan_options = {}
        self.scan_results = None
        self.scan_start_time = None
        self.scan_end_time = None
        self.is_scanning = False

        # Top navigation bar
        self.create_top_bar()

        # Main content area with notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=0, pady=0)

        # Initialize all tabs
        self.init_tab = InitialScanTab(self.notebook, self)
        self.summary_tab = SummaryTab(self.notebook, self)
        self.results_tab = ResultsTab(self.notebook, self)
        self.params_tab = ScanParametersTab(self.notebook, self)
        self.visual_tab = Visual3DTab(self.notebook, self)
        self.schedule_tab = ScheduleScanTab(self.notebook, self)

        # Add tabs to notebook
        self.notebook.add(self.init_tab, text="Scan Targets")
        self.notebook.add(self.schedule_tab, text="Schedule 📅")
        self.notebook.add(self.summary_tab, text="Summary", state="disabled")
        self.notebook.add(self.results_tab, text="Results", state="disabled")
        self.notebook.add(self.params_tab, text="Scan Parameters", state="disabled")
        self.notebook.add(self.visual_tab, text="3D Visualization", state="disabled")

        # Color tags for results
        self.setup_colors()

    def create_top_bar(self):
        """Create top navigation bar with action buttons."""
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=15, pady=15)

        # Title on left
        ttk.Label(top_frame, text="Port Scanner Dashboard", 
                  font=("Segoe UI", 16, "bold")).pack(side="left", padx=10)

        # Right-aligned buttons
        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side="right", padx=10)

        self.download_btn = ttk.Button(btn_frame, text="📥 Download Report", 
                                       command=self.download_report)
        self.download_btn.pack(side="left", padx=5)
        self.download_btn.config(state="disabled")

        self.new_scan_btn = ttk.Button(btn_frame, text="➕ New Scan", 
                                       command=self.new_scan)
        self.new_scan_btn.pack(side="left", padx=5)

        self.rescan_btn = ttk.Button(btn_frame, text="🔄 Rescan", 
                                     command=self.rescan)
        self.rescan_btn.pack(side="left", padx=5)
        self.rescan_btn.config(state="disabled")

    def setup_colors(self):
        """Setup color styling for status indicators."""
        self.colors = {
            "open": "#28a745",      # green
            "closed": "#dc3545",    # red
            "timeout": "#fd7e14",   # orange
            "error": "#6f42c1",     # purple
            "text": "#ffffff"
        }

    def start_scan(self, target, ports, top_n, service_ver, protocol, use_nmap, 
                   aggressive=False, stealth=False, technique="tcp-connect", detect_os=False):
        """Start scan in background thread."""
        if self.is_scanning:
            messagebox.showwarning("Scanning", "A scan is already in progress!")
            return

        self.is_scanning = True
        self.scan_options = {
            "target": target,
            "ports": ports,
            "top_n": top_n,
            "service_version": service_ver,
            "protocol": protocol,
            "use_nmap": use_nmap,
            "aggressive": aggressive,
            "stealth": stealth,
            "technique": technique,
            "detect_os": detect_os
        }
        self.scan_start_time = datetime.now()

        def run():
            try:
                if protocol == "udp" and not nmap_available():
                    self.after(0, lambda: messagebox.showerror("Error", "UDP requires Nmap"))
                    self.is_scanning = False
                    return

                results = {}
                if use_nmap and nmap_available():
                    result = run_nmap(
                        target,
                        ports=ports,
                        top_ports=top_n,
                        service_version=service_ver,
                        protocol=protocol,
                    )
                    results = {"nmap": True, **result}
                else:
                    try:
                        # Adjust timeout and threads based on scan mode
                        timeout = Config.DEFAULT_TIMEOUT if not aggressive else 2
                        threads = Config.DEFAULT_THREADS if not aggressive else 20
                        
                        scanner = PortScanner(
                            target=target,
                            timeout=timeout,
                            threads=threads,
                            verbose=False,
                            output_file=None,
                        )
                        
                        # Apply stealth mode  (slower scanning)
                        if stealth:
                            scanner.timeout = max(scanner.timeout, 5)
                        
                        scan_result = scanner.scan(ports)
                        results = {"nmap": False, **scan_result}
                    except Exception as e:
                        print(f"[ERROR] Scan failed: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        results = {"nmap": False, "error": str(e)}

                self.scan_end_time = datetime.now()
                self.scan_results = results
                self.is_scanning = False
                
                # Enable result tabs
                self.after(0, self.enable_result_tabs)
                self.after(0, lambda: self.notebook.select(self.summary_tab))
                self.after(0, self.summary_tab.refresh)
                self.after(0, self.results_tab.refresh)
                self.after(0, self.params_tab.refresh)

            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
                self.is_scanning = False

        threading.Thread(target=run, daemon=True).start()

    def enable_result_tabs(self):
        """Enable all result tabs after scan."""
        self.notebook.tab(self.summary_tab, state="normal")
        self.notebook.tab(self.results_tab, state="normal")
        self.notebook.tab(self.params_tab, state="normal")
        self.notebook.tab(self.visual_tab, state="normal")
        self.download_btn.config(state="normal")
        self.rescan_btn.config(state="normal")

    def new_scan(self):
        """Start a new scan."""
        self.notebook.tab(self.summary_tab, state="disabled")
        self.notebook.tab(self.results_tab, state="disabled")
        self.notebook.tab(self.params_tab, state="disabled")
        self.notebook.tab(self.visual_tab, state="disabled")
        self.download_btn.config(state="disabled")
        self.rescan_btn.config(state="disabled")
        
        self.scan_results = None
        self.scan_options = {}
        self.notebook.select(self.init_tab)

    def rescan(self):
        """Perform a rescan with the same parameters."""
        if self.scan_options:
            self.start_scan(
                self.scan_options["target"],
                self.scan_options["ports"],
                self.scan_options["top_n"],
                self.scan_options["service_version"],
                self.scan_options["protocol"],
                self.scan_options["use_nmap"],
                aggressive=self.scan_options.get("aggressive", False),
                stealth=self.scan_options.get("stealth", False),
                technique=self.scan_options.get("technique", "tcp-connect"),
                detect_os=self.scan_options.get("detect_os", False)
            )

    def download_report(self):
        """Export scan results to file."""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to download")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )

        if file_path:
            if file_path.endswith(".json"):
                with open(file_path, "w") as f:
                    json.dump({
                        "scan_options": self.scan_options,
                        "results": self.scan_results,
                        "start_time": self.scan_start_time.isoformat() if self.scan_start_time else None,
                        "end_time": self.scan_end_time.isoformat() if self.scan_end_time else None
                    }, f, indent=2)
            else:
                with open(file_path, "w") as f:
                    f.write("=" * 60 + "\n")
                    f.write("PORT SCAN REPORT\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(f"Target: {self.scan_options.get('target', 'N/A')}\n")
                    f.write(f"Start: {self.scan_start_time}\n")
                    f.write(f"End: {self.scan_end_time}\n")
                    f.write(f"Duration: {(self.scan_end_time - self.scan_start_time).total_seconds():.2f}s\n\n")
                    
                    if self.scan_results.get("nmap"):
                        f.write("NMAP RESULTS:\n")
                        ports = self.scan_results.get("open_ports", [])
                        for port_info in ports:
                            if isinstance(port_info, (list, tuple)):
                                f.write(f"  Port {port_info[0]}: {port_info[1]} ({port_info[2] if len(port_info) > 2 else 'N/A'})\n")
                            else:
                                f.write(f"  Port {port_info.get('port')}: {port_info.get('service')} ({port_info.get('product', 'N/A')})\n")
                    else:
                        f.write("BUILT-IN SCANNER RESULTS:\n")
                        results_list = self.scan_results.get("results", [])
                        for item in results_list:
                            if isinstance(item, (list, tuple)) and len(item) >= 2:
                                port, status, service = item[0], item[1], item[2] if len(item) > 2 else "N/A"
                                f.write(f"  Port {port}: {status} - {service}\n")

                    f.write("\n" + "=" * 60 + "\n")

            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")


class InitialScanTab(ttk.Frame):
    """Tab for entering scan parameters."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Scrollable content
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Scan Type Selection
        scan_frame = ttk.LabelFrame(scrollable_frame, text="Scan Type", padding=20)
        scan_frame.pack(fill="x", padx=20, pady=15)

        self.scan_type = tk.StringVar(value="light")
        ttk.Radiobutton(scan_frame, text="Light Scan (Top 100 ports)", 
                       variable=self.scan_type, value="light").pack(anchor="w", pady=5)
        ttk.Radiobutton(scan_frame, text="Deep Scan (Custom ports)", 
                       variable=self.scan_type, value="deep").pack(anchor="w", pady=5)

        # Target
        target_frame = ttk.LabelFrame(scrollable_frame, text="Target", padding=20)
        target_frame.pack(fill="x", padx=20, pady=15)

        ttk.Label(target_frame, text="IP or Hostname").pack(anchor="w", pady=(0, 5))
        self.target_entry = ttk.Entry(target_frame, width=50, font=("Segoe UI", 11))
        self.target_entry.pack(fill="x", pady=10)

        ttk.Label(target_frame, text="Examples: 192.168.1.1, google.com, scanme.nmap.org", 
                  font=("Segoe UI", 9)).pack(anchor="w")

        # Scan Options
        options_frame = ttk.LabelFrame(scrollable_frame, text="Scan Options", padding=20)
        options_frame.pack(fill="x", padx=20, pady=15)

        self.service_version_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Detect Service Version",
                       variable=self.service_version_var).pack(anchor="w", pady=5)

        self.detect_os_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Detect Operating System",
                       variable=self.detect_os_var).pack(anchor="w", pady=5)

        # Advanced Options
        advanced_frame = ttk.LabelFrame(scrollable_frame, text="Advanced Options", padding=20)
        advanced_frame.pack(fill="x", padx=20, pady=15)

        self.aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="🔥 Aggressive Scan (Fast & Thorough)",
                       variable=self.aggressive_var).pack(anchor="w", pady=5)

        self.stealth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="🕷️  Stealth Mode (Slow scanning - bypass IDS)",
                       variable=self.stealth_var).pack(anchor="w", pady=5)

        # Scan technique selection
        ttk.Label(advanced_frame, text="Scan Technique:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 5))
        self.technique_var = tk.StringVar(value="tcp-connect")
        techniques = [
            ("TCP Connect Scan (Standard)", "tcp-connect"),
            ("TCP SYN Scan (Half-open)", "tcp-syn"),
            ("FIN Scan (Stealth)", "tcp-fin"),
            ("NULL Scan (Stealth)", "tcp-null"),
            ("XMAS Scan (Stealth)", "tcp-xmas"),
        ]
        for text, value in techniques:
            ttk.Radiobutton(advanced_frame, text=text, variable=self.technique_var, value=value).pack(anchor="w", padx=20, pady=2)

        # Protocol
        protocol_frame = ttk.LabelFrame(scrollable_frame, text="Protocol", padding=20)
        protocol_frame.pack(fill="x", padx=20, pady=15)

        self.protocol_var = tk.StringVar(value="tcp")
        ttk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, value="tcp").pack(anchor="w", pady=5)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, value="udp").pack(anchor="w", pady=5)

        # Port Selection
        port_frame = ttk.LabelFrame(scrollable_frame, text="Port Selection", padding=20)
        port_frame.pack(fill="x", padx=20, pady=15)

        self.port_mode_var = tk.StringVar(value="common")
        ttk.Radiobutton(port_frame, text="Common Ports (23 well-known ports)",
                       variable=self.port_mode_var, value="common").pack(anchor="w", pady=5)
        ttk.Radiobutton(port_frame, text="Top N Ports",
                       variable=self.port_mode_var, value="top").pack(anchor="w", pady=5)
        ttk.Radiobutton(port_frame, text="Custom Port List",
                       variable=self.port_mode_var, value="custom").pack(anchor="w", pady=5)

        # Port range input
        self.port_entry_var = tk.StringVar(value="80,443,22,21,25,3306,5432")
        ttk.Label(port_frame, text="Ports (comma-separated) or range (1-1000):")
        ttk.Entry(port_frame, textvariable=self.port_entry_var, width=50).pack(fill="x", pady=10)

        # Top N selector
        top_n_frame = ttk.Frame(port_frame)
        top_n_frame.pack(fill="x", pady=5)
        ttk.Label(top_n_frame, text="Top N ports:").pack(side="left", padx=5)
        self.top_n_var = tk.IntVar(value=100)
        top_n_combo = ttk.Combobox(top_n_frame, textvariable=self.top_n_var, 
                                   values=[10, 50, 100, 500, 1000], width=10)
        top_n_combo.pack(side="left", padx=5)

        # Nmap Option
        nmap_frame = ttk.LabelFrame(scrollable_frame, text="Scanner Selection", padding=20)
        nmap_frame.pack(fill="x", padx=20, pady=15)

        self.use_nmap_var = tk.BooleanVar(value=False)
        nmap_label = "Use Nmap (if available)" if nmap_available() else "Use Nmap (not installed)"
        ttk.Checkbutton(nmap_frame, text=nmap_label, variable=self.use_nmap_var,
                       state="normal" if nmap_available() else "disabled").pack(anchor="w")

        # Start Scan Button
        self.start_btn = ttk.Button(scrollable_frame, text="▶ Start Scan",
                                   command=self.start_scan)
        self.start_btn.pack(pady=30, ipady=10, ipadx=50)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def start_scan(self):
        """Validate input and start scan."""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target address")
            return

        # Remove common protocol prefixes
        for prefix in ["http://", "https://", "ftp://", "ftps://"]:
            if target.startswith(prefix):
                target = target[len(prefix):]

        port_mode = self.port_mode_var.get()
        protocol = self.protocol_var.get()
        service_ver = self.service_version_var.get()
        detect_os = self.detect_os_var.get()
        aggressive = self.aggressive_var.get()
        stealth = self.stealth_var.get()
        technique = self.technique_var.get()
        use_nmap = self.use_nmap_var.get() and nmap_available()

        ports = []
        top_n = None

        if port_mode == "common":
            ports = Config.COMMON_PORTS
        elif port_mode == "top":
            top_n = self.top_n_var.get()
        elif port_mode == "custom":
            port_str = self.port_entry_var.get()
            try:
                if "-" in port_str:
                    start, end = map(int, port_str.split("-"))
                    ports = list(range(start, end + 1))
                else:
                    ports = [int(p.strip()) for p in port_str.split(",")]
            except ValueError:
                messagebox.showerror("Error", "Invalid port format")
                return

        self.controller.start_scan(
            target, ports, top_n, service_ver, protocol, use_nmap,
            aggressive=aggressive, stealth=stealth, technique=technique, detect_os=detect_os
        )


class SummaryTab(ttk.Frame):
    """Summary tab showing scan statistics."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Summary stats frame
        stats_frame = ttk.LabelFrame(self, text="Summary", padding=30)
        stats_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Create stats grid
        self.stats_labels = {}

        # Open ports count
        open_frame = ttk.Frame(stats_frame)
        open_frame.pack(fill="x", pady=20)
        ttk.Label(open_frame, text="Open Ports:", font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
        self.stats_labels["open"] = ttk.Label(open_frame, text="0", 
                                             font=("Segoe UI", 20, "bold"), foreground="#28a745")
        self.stats_labels["open"].pack(side="left", padx=20)

        # Closed ports count
        closed_frame = ttk.Frame(stats_frame)
        closed_frame.pack(fill="x", pady=20)
        ttk.Label(closed_frame, text="Closed Ports:", font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
        self.stats_labels["closed"] = ttk.Label(closed_frame, text="0", 
                                               font=("Segoe UI", 20, "bold"), foreground="#dc3545")
        self.stats_labels["closed"].pack(side="left", padx=20)

        # Timing info
        timing_frame = ttk.Frame(stats_frame)
        timing_frame.pack(fill="x", pady=20)

        ttk.Label(timing_frame, text="Start Time:", font=("Segoe UI", 11, "bold")).pack(side="left", padx=10)
        self.stats_labels["start_time"] = ttk.Label(timing_frame, text="N/A")
        self.stats_labels["start_time"].pack(side="left", padx=20)

        ttk.Label(timing_frame, text="End Time:", font=("Segoe UI", 11, "bold")).pack(side="left", padx=10)
        self.stats_labels["end_time"] = ttk.Label(timing_frame, text="N/A")
        self.stats_labels["end_time"].pack(side="left", padx=20)

        ttk.Label(timing_frame, text="Duration:", font=("Segoe UI", 11, "bold")).pack(side="left", padx=10)
        self.stats_labels["duration"] = ttk.Label(timing_frame, text="N/A")
        self.stats_labels["duration"].pack(side="left", padx=20)

    def refresh(self):
        """Refresh summary statistics."""
        if not self.controller.scan_results:
            return

        results = self.controller.scan_results
        open_count = 0
        closed_count = 0

        if results.get("nmap"):
            open_ports = results.get("open_ports", [])
            open_count = len(open_ports)
        else:
            # Built-in scanner: results is a list of tuples (port, status, service)
            result_list = results.get("results", [])
            for item in result_list:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    status = item[1]
                    if status == "open":
                        open_count += 1
                    elif status == "closed":
                        closed_count += 1

        self.stats_labels["open"].config(text=str(open_count))
        self.stats_labels["closed"].config(text=str(closed_count))

        if self.controller.scan_start_time:
            self.stats_labels["start_time"].config(text=self.controller.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"))
        if self.controller.scan_end_time:
            self.stats_labels["end_time"].config(text=self.controller.scan_end_time.strftime("%Y-%m-%d %H:%M:%S"))
            duration = (self.controller.scan_end_time - self.controller.scan_start_time).total_seconds()
            self.stats_labels["duration"].config(text=f"{duration:.2f}s")


class ResultsTab(ttk.Frame):
    """Results tab showing detailed port information."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Create treeview
        columns = ("Port", "Status", "Service", "Product", "Version")
        self.tree = ttk.Treeview(self, columns=columns, height=20, show="headings")
        
        # Define headings
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("Port", anchor="w", width=100)
        self.tree.column("Status", anchor="center", width=120)
        self.tree.column("Service", anchor="w", width=150)
        self.tree.column("Product", anchor="w", width=250)
        self.tree.column("Version", anchor="w", width=150)

        self.tree.heading("#0", text="", anchor="w")
        self.tree.heading("Port", text="Port Number", anchor="w")
        self.tree.heading("Status", text="State", anchor="center")
        self.tree.heading("Service", text="Service", anchor="w")
        self.tree.heading("Product", text="Product", anchor="w")
        self.tree.heading("Version", text="Version", anchor="w")

        # Add scrollbars
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        # Grid layout
        self.tree.grid(column=0, row=0, sticky="nsew")
        vsb.grid(column=1, row=0, sticky="ns")
        hsb.grid(column=0, row=1, sticky="ew")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def refresh(self):
        """Refresh results display."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.controller.scan_results:
            print("[ResultsTab] No scan results available")
            return

        results = self.controller.scan_results
        
        # Check for error
        if "error" in results:
            print(f"[ResultsTab] Scan had error: {results['error']}")
            error_item = self.tree.insert("", "end", values=(
                "ERROR", 
                "Failed", 
                results["error"],
                "N/A",
                "N/A"
            ), tags=("error",))
            return

        print(f"[ResultsTab] Scan results keys: {results.keys()}")
        print(f"[ResultsTab] Nmap flag: {results.get('nmap')}")

        if results.get("nmap"):
            open_ports = results.get("open_ports", [])
            print(f"[ResultsTab] Processing Nmap results, open_ports count: {len(open_ports)}")
            for port_info in open_ports:
                # Handle both tuple/list and dict formats
                if isinstance(port_info, (list, tuple)):
                    port = port_info[0] if len(port_info) > 0 else "N/A"
                    status = "open"
                    service = port_info[1] if len(port_info) > 1 else "N/A"
                    product = port_info[2] if len(port_info) > 2 else "N/A"
                    version = port_info[3] if len(port_info) > 3 else "N/A"
                else:
                    # Dict format
                    port = port_info.get("port", "N/A")
                    status = port_info.get("state", "open")
                    service = port_info.get("service", "N/A")
                    product = port_info.get("product", "N/A")
                    version = port_info.get("version", "N/A")
                
                self.tree.insert("", "end", values=(port, status, service, product, version),
                                tags=(status,))
        else:
            # Built-in scanner results
            result_list = results.get("results", [])
            print(f"[ResultsTab] Processing built-in scanner results, count: {len(result_list)}")
            
            if not result_list:
                print("[ResultsTab] WARNING: No results found in scan_results")
                print(f"[ResultsTab] Available keys: {list(results.keys())}")
                # Display what we got
                for key in results.keys():
                    if key not in ('nmap', 'target', 'target_ip', 'total_ports', 'scan_duration'):
                        print(f"[ResultsTab] {key}: {results[key]}")
                return
            
            print(f"[ResultsTab] First few results: {result_list[:3]}")
            
            for i, item in enumerate(result_list):
                # Convert to tuple if needed
                if not isinstance(item, (list, tuple)):
                    print(f"[ResultsTab WARNING] Item {i} is not a tuple/list: {type(item)} = {item}")
                    continue
                    
                if len(item) < 2:
                    print(f"[ResultsTab WARNING] Item {i} has insufficient data: {item}")
                    continue
                
                port = str(item[0])
                status = item[1]
                service = item[2] if len(item) > 2 else "N/A"
                
                print(f"[ResultsTab] Inserting row {i}: port={port}, status={status}, service={service}")
                
                self.tree.insert("", "end", values=(port, status, service, "N/A", "N/A"),
                                tags=(status,))

        # Apply tag colors
        self.tree.tag_configure("open", background="#28a745", foreground="white")
        self.tree.tag_configure("closed", background="#dc3545", foreground="white")
        self.tree.tag_configure("timeout", background="#fd7e14", foreground="white")
        self.tree.tag_configure("error", background="#6f42c1", foreground="white")


class ScanParametersTab(ttk.Frame):
    """Scan parameters display tab."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Create parameter display
        self.param_frame = ttk.LabelFrame(self, text="Scan Configuration", padding=20)
        self.param_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.param_labels = {}

        params = [
            ("Host", "target"),
            ("Protocol", "protocol"),
            ("Scan Type", "scan_type"),
            ("Ports", "ports"),
            ("Detect Service Version", "service_version"),
            ("Detect OS", "detect_os"),
            ("Aggressive Mode", "aggressive"),
            ("Stealth Mode", "stealth"),
            ("Scan Technique", "technique"),
            ("Use Nmap", "use_nmap"),
        ]

        for label, key in params:
            frame = ttk.Frame(self.param_frame)
            frame.pack(fill="x", pady=15)
            ttk.Label(frame, text=f"{label}:", font=("Segoe UI", 11, "bold"), width=25).pack(side="left", padx=10)
            self.param_labels[key] = ttk.Label(frame, text="N/A", font=("Segoe UI", 11))
            self.param_labels[key].pack(side="left", padx=20)

    def refresh(self):
        """Refresh parameters display."""
        options = self.controller.scan_options
        
        self.param_labels["target"].config(text=options.get("target", "N/A"))
        self.param_labels["protocol"].config(text=options.get("protocol", "N/A").upper())
        self.param_labels["scan_type"].config(text=options.get("scan_type", "Custom"))
        
        ports = options.get("ports", [])
        top_n = options.get("top_n")
        if top_n:
            self.param_labels["ports"].config(text=f"Top {top_n} ports")
        elif ports:
            port_str = ",".join(map(str, ports[:5]))
            if len(ports) > 5:
                port_str += f", ... ({len(ports)} total)"
            self.param_labels["ports"].config(text=port_str)
        else:
            self.param_labels["ports"].config(text="N/A")

        self.param_labels["service_version"].config(text="Yes" if options.get("service_version") else "No")
        self.param_labels["detect_os"].config(text="Yes" if options.get("detect_os") else "No")
        self.param_labels["aggressive"].config(text="Yes" if options.get("aggressive") else "No")
        self.param_labels["stealth"].config(text="Yes" if options.get("stealth") else "No")
        
        technique = options.get("technique", "tcp-connect")
        technique_names = {
            "tcp-connect": "TCP Connect",
            "tcp-syn": "TCP SYN",
            "tcp-fin": "TCP FIN",
            "tcp-null": "TCP NULL",
            "tcp-xmas": "TCP XMAS"
        }
        self.param_labels["technique"].config(text=technique_names.get(technique, technique))
        self.param_labels["use_nmap"].config(text="Yes" if options.get("use_nmap") else "No")


class Visual3DTab(ttk.Frame):
    """3D visualization of port scan results."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.fig = None
        self.canvas = None

    def refresh(self):
        """Refresh 3D visualization."""
        # Clear previous widgets
        for widget in self.winfo_children():
            widget.destroy()
        
        if self.canvas:
            self.canvas = None
        if self.fig:
            self.fig = None

        if not self.controller.scan_results:
            ttk.Label(self, text="No scan results to visualize").pack(expand=True)
            return

        results = self.controller.scan_results
        ports = []
        statuses = []

        if results.get("nmap"):
            open_ports = results.get("open_ports", [])
            for port_info in open_ports:
                try:
                    port_num = port_info[0] if isinstance(port_info, (list, tuple)) else port_info.get("port")
                    ports.append(int(port_num))
                    statuses.append("open")
                except (ValueError, TypeError, IndexError):
                    continue
        else:
            result_list = results.get("results", [])
            for item in result_list:
                try:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        ports.append(int(item[0]))
                        statuses.append(item[1])
                except (ValueError, TypeError):
                    continue

        if not ports:
            ttk.Label(self, text="No ports to visualize").pack(expand=True)
            return

        try:
            # Create 3D plot
            self.fig = Figure(figsize=(10, 7), dpi=100)
            ax = self.fig.add_subplot(111, projection="3d")

            # Circular layout for ports
            n_ports = len(ports)
            theta = np.linspace(0, 2 * np.pi, n_ports, endpoint=False)
            x = np.cos(theta)
            y = np.sin(theta)
            z = np.array([p / 1000.0 for p in ports])

            # Colors based on status
            color_map = {"open": "#28a745", "closed": "#dc3545", "timeout": "#fd7e14", "error": "#6f42c1"}
            colors = [color_map.get(s, "#999999") for s in statuses]

            # Plot ports
            ax.scatter(x, y, z, c=colors, s=200, marker="o", depthshade=False)

            # Add port labels
            for i, port in enumerate(ports):
                ax.text(x[i], y[i], z[i], str(port), fontsize=8, ha="center")

            ax.set_xlabel("X")
            ax.set_ylabel("Y")
            ax.set_zlabel("Port Number")
            ax.set_title("3D Port Visualization")

            # Create canvas and display
            self.canvas = FigureCanvasTkAgg(self.fig, master=self)
            canvas_widget = self.canvas.get_tk_widget()
            canvas_widget.pack(fill="both", expand=True)
            self.canvas.draw()
            
        except Exception as e:
            ttk.Label(self, text=f"Visualization Error: {str(e)}").pack(expand=True)
            print(f"[Visual3DTab] Error: {str(e)}")
            import traceback
            traceback.print_exc()


class ScheduleScanTab(ttk.Frame):
    """Tab for scheduling periodic scans."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.scheduled_scans = []
        self.scheduler_running = False

        # Main frame
        main_frame = ttk.LabelFrame(self, text="Schedule Periodic Scans", padding=20)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Schedule info
        info_text = "Set up automatic scans to run periodically. Useful for continuous monitoring."
        ttk.Label(main_frame, text=info_text, font=("Segoe UI", 10)).pack(fill="x", pady=10)

        # Schedule frequency
        freq_frame = ttk.Frame(main_frame)
        freq_frame.pack(fill="x", pady=15)
        ttk.Label(freq_frame, text="Run scan every:", font=("Segoe UI", 11, "bold")).pack(side="left", padx=10)
        
        self.interval_var = tk.IntVar(value=1)
        ttk.Spinbox(freq_frame, from_=1, to=60, textvariable=self.interval_var, width=5).pack(side="left", padx=5)
        
        self.unit_var = tk.StringVar(value="hours")
        unit_combo = ttk.Combobox(freq_frame, textvariable=self.unit_var, 
                                  values=["minutes", "hours", "days"], state="readonly", width=10)
        unit_combo.pack(side="left", padx=5)

        # Scheduled scans list
        list_frame = ttk.LabelFrame(main_frame, text="Scheduled Scans", padding=10)
        list_frame.pack(fill="both", expand=True, pady=15)

        # Listbox with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.schedule_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Segoe UI", 9), height=8)
        self.schedule_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.schedule_listbox.yview)

        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=15)

        self.start_scheduler_btn = ttk.Button(btn_frame, text="▶ Start Scheduler", 
                                              command=self.start_scheduler)
        self.start_scheduler_btn.pack(side="left", padx=5)

        self.stop_scheduler_btn = ttk.Button(btn_frame, text="⏹️  Stop Scheduler", 
                                            command=self.stop_scheduler, state="disabled")
        self.stop_scheduler_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(btn_frame, text="🗑️  Clear All", command=self.clear_schedules)
        clear_btn.pack(side="left", padx=5)

        # Status label
        self.status_label = ttk.Label(main_frame, text="Scheduler: Stopped", 
                                     font=("Segoe UI", 10), foreground="red")
        self.status_label.pack(fill="x", pady=10)

    def start_scheduler(self):
        """Start the scheduler in background."""
        if self.controller.scan_options:
            interval = self.interval_var.get()
            unit = self.unit_var.get()
            
            # Add to list
            schedule_text = f"Every {interval} {unit}"
            self.schedule_listbox.insert("end", schedule_text)
            
            self.scheduler_running = True
            self.start_scheduler_btn.config(state="disabled")
            self.stop_scheduler_btn.config(state="normal")
            self.status_label.config(text="Scheduler: Running", foreground="green")
            
            # Start scheduler thread
            def run_scheduler():
                while self.scheduler_running:
                    try:
                        schedule.run_pending()
                        time.sleep(1)
                    except:
                        pass
            
            # Schedule the scan
            if unit == "minutes":
                schedule.every(interval).minutes.do(self.run_scheduled_scan)
            elif unit == "hours":
                schedule.every(interval).hours.do(self.run_scheduled_scan)
            elif unit == "days":
                schedule.every(interval).days.do(self.run_scheduled_scan)
            
            # Start scheduler thread
            threading.Thread(target=run_scheduler, daemon=True).start()
            
            messagebox.showinfo("Scheduled", f"Scan scheduled to run every {interval} {unit}")
        else:
            messagebox.showwarning("No Scan", "Please configure a scan first")

    def stop_scheduler(self):
        """Stop the scheduler."""
        self.scheduler_running = False
        schedule.clear()
        self.start_scheduler_btn.config(state="normal")
        self.stop_scheduler_btn.config(state="disabled")
        self.status_label.config(text="Scheduler: Stopped", foreground="red")
        messagebox.showinfo("Stopped", "Scheduler stopped")

    def clear_schedules(self):
        """Clear all scheduled scans."""
        self.schedule_listbox.delete(0, "end")
        schedule.clear()
        self.scheduler_running = False
        self.start_scheduler_btn.config(state="normal")
        self.stop_scheduler_btn.config(state="disabled")
        self.status_label.config(text="Scheduler: Stopped", foreground="red")

    def run_scheduled_scan(self):
        """Run a scheduled scan."""
        if self.controller.scan_options:
            opts = self.controller.scan_options
            self.controller.start_scan(
                opts["target"], opts["ports"], opts.get("top_n"), 
                opts.get("service_version"), opts.get("protocol"), 
                opts.get("use_nmap"), aggressive=opts.get("aggressive"),
                stealth=opts.get("stealth"), technique=opts.get("technique"),
                detect_os=opts.get("detect_os")
            )


def launch_gui():
    """Launch the GUI application."""
    app = PortScannerApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
