import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

from scanner import PortScanner
from config import Config
from nmap_integration import nmap_available, run_nmap

# matplotlib is used for the interactive 3D visualization
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401 (required for 3d projection)


class PortScannerApp(tk.Tk):
    """Main application window controlling multiple pages."""

    def __init__(self):
        super().__init__()
        self.title("Professional TCP Port Scanner")
        self.geometry("700x500")
        self.resizable(False, False)

        # configure ttk style for a more polished look
        try:
            import ttkbootstrap as tb
            style = tb.Style(theme="darkly")  # use a professional dark theme if available
        except ImportError:
            style = ttk.Style(self)
            style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 10), padding=5)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("TFrame", background="#f0f0f0")
        style.map("TButton", background=[("active", "#d9d9d9")])

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, OptionsPage, ResultsPage, VisualPage):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.scan_options = {}
        self.scan_results = None

        # store path of last report saved so user can overwrite
        self.last_report = None

        # navigation history stack
        self.history = []
        self.current_page = None

        # global key binding for Backspace (go back unless focus in entry/text)
        def back_handler(event=None):
            widget = event.widget if event else None
            if isinstance(widget, (tk.Entry, tk.Text)):
                return
            if self.history:
                prev = self.history.pop()
                # avoid adding current page again
                self.show_frame(prev)
        self.bind_all("<BackSpace>", back_handler)

        self.show_frame("StartPage")

    def show_frame(self, page_name: str):
        # maintain history for back navigation
        if self.current_page and self.current_page != page_name:
            self.history.append(self.current_page)
        frame = self.frames[page_name]
        frame.tkraise()
        self.current_page = page_name

    def start_scan(self):
        """Dispatch scan work to a background thread so UI remains responsive."""

        def run():
            params = self.scan_options
            target = params.get("target")
            ports = params.get("ports")
            top_n = params.get("top_n")
            service_ver = params.get("service_version", False)
            proto = params.get("protocol", "tcp")
            use_nmap = params.get("use_nmap", False)

            if proto == "udp" and not nmap_available():
                self.after(0, lambda: messagebox.showerror("Error", "UDP scanning requires Nmap"))
                return

            results = {}
            if use_nmap and nmap_available():
                result = run_nmap(
                    target,
                    ports=ports,
                    top_ports=top_n,
                    service_version=service_ver,
                    protocol=proto,
                )
                if result.get("ok"):
                    open_ports = result.get("open_ports", [])
                    results = {"nmap": True, "open_ports": open_ports, "raw": result}
                else:
                    results = {"nmap": True, "error": result.get("error")}
            else:
                try:
                    scanner = PortScanner(
                        target=target,
                        timeout=Config.DEFAULT_TIMEOUT,
                        threads=Config.DEFAULT_THREADS,
                        verbose=False,
                        output_file=None,
                    )
                    scan_result = scanner.scan(ports)
                    results = {"nmap": False, "result": scan_result}
                except Exception as e:
                    results = {"nmap": False, "error": str(e)}

            self.scan_results = results
            # when done, switch to results page on the main thread
            self.after(0, lambda: self.show_frame("ResultsPage"))

        threading.Thread(target=run, daemon=True).start()


class StartPage(ttk.Frame):
    """First page where user enters the target address."""

    def __init__(self, parent, controller: PortScannerApp):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Port Scanner", style="Header.TLabel").pack(pady=20)

        target_frame = ttk.Frame(self)
        target_frame.pack(pady=10, fill="x")
        ttk.Label(target_frame, text="Target (URL/IP):").pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(target_frame, textvariable=self.target_var, width=40).pack(side="left", padx=5)

        ttk.Button(self, text="Next →", command=self.on_next).pack(pady=20)

    def on_next(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target")
            return
        # clean using function from main to avoid duplication
        from main import clean_target

        cleaned = clean_target(target)
        self.controller.scan_options["target"] = cleaned
        self.controller.show_frame("OptionsPage")


class OptionsPage(ttk.Frame):
    """Page to configure scan options: protocol, ports, nmap usage."""

    def __init__(self, parent, controller: PortScannerApp):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Scan Options", style="Header.TLabel").pack(pady=20)

        self.service_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Detect service version", variable=self.service_var).pack(anchor="w", padx=20)

        proto_frame = ttk.Frame(self)
        proto_frame.pack(pady=10, fill="x", padx=20)
        ttk.Label(proto_frame, text="Protocol:").pack(side="left")
        self.protocol_var = tk.StringVar(value="tcp")
        ttk.Radiobutton(proto_frame, text="TCP", variable=self.protocol_var, value="tcp").pack(side="left", padx=5)
        ttk.Radiobutton(proto_frame, text="UDP", variable=self.protocol_var, value="udp").pack(side="left", padx=5)

        ports_frame = ttk.LabelFrame(self, text="Port Selection")
        ports_frame.pack(padx=20, pady=10, fill="x")

        self.port_choice = tk.StringVar(value="common")
        ttk.Radiobutton(ports_frame, text="Common Ports", variable=self.port_choice, value="common").pack(anchor="w")
        ttk.Radiobutton(ports_frame, text="List of Ports", variable=self.port_choice, value="list").pack(anchor="w")
        self.port_list_var = tk.StringVar()
        ttk.Entry(ports_frame, textvariable=self.port_list_var, width=50).pack(anchor="w", padx=20, pady=2)

        ttk.Radiobutton(ports_frame, text="Top N Ports", variable=self.port_choice, value="top").pack(anchor="w")
        self.top_n_var = tk.StringVar()
        ttk.Entry(ports_frame, textvariable=self.top_n_var, width=10).pack(anchor="w", padx=20, pady=2)

        self.use_nmap_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Use Nmap if available", variable=self.use_nmap_var).pack(anchor="w", padx=20, pady=5)

        nav_frame = ttk.Frame(self)
        nav_frame.pack(pady=20)
        ttk.Button(nav_frame, text="← Back", command=lambda: controller.show_frame("StartPage")).pack(side="left", padx=5)
        ttk.Button(nav_frame, text="Scan", command=self.on_scan).pack(side="left", padx=5)

    def on_scan(self):
        choice = self.port_choice.get()
        ports = None
        top_n = None
        if choice == "common":
            ports = Config.COMMON_PORTS
        elif choice == "list":
            raw = self.port_list_var.get().strip()
            try:
                ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
            except ValueError:
                messagebox.showerror("Invalid input", "Please enter a comma-separated list of integers")
                return
        elif choice == "top":
            try:
                top_n = int(self.top_n_var.get().strip())
            except ValueError:
                messagebox.showerror("Invalid input", "Top N must be an integer")
                return
        else:
            messagebox.showerror("Selection Error", "Unknown port selection option")
            return

        self.controller.scan_options["ports"] = ports
        self.controller.scan_options["top_n"] = top_n
        self.controller.scan_options["service_version"] = self.service_var.get()
        self.controller.scan_options["protocol"] = self.protocol_var.get()
        self.controller.scan_options["use_nmap"] = self.use_nmap_var.get()
        self.controller.start_scan()


class ResultsPage(ttk.Frame):
    """Displays the results of the scan once complete."""

    def __init__(self, parent, controller: PortScannerApp):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="Scan Results", style="Header.TLabel").pack(pady=20)

        # treeview for interactive, colored results
        self.tree = ttk.Treeview(self, columns=("port","status","service"), show="headings", height=15)
        self.tree.heading("port", text="Port")
        self.tree.heading("status", text="Status")
        self.tree.heading("service", text="Service")
        self.tree.pack(padx=10, pady=10, fill="both", expand=True)

        # configure color tags
        self.tree.tag_configure("open", background="#d4ffd4")
        self.tree.tag_configure("closed", background="#ffd4d4")
        self.tree.tag_configure("timeout", background="#fff4d4")
        self.tree.tag_configure("error", background="#ffd4ff")

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="New Scan", command=lambda: controller.show_frame("StartPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Visualize →", command=lambda: controller.show_frame("VisualPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Save Report", command=self.save_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Quit", command=controller.destroy).pack(side="left", padx=5)

        # binding to update when shown
        self.bind("<<ShowFrame>>", self.on_show)

    def save_report(self):
        # open save dialog
        fname = filedialog.asksaveasfilename(
            title="Save Scan Report",
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"), ("All files","*.*")],
            initialfile=self.controller.last_report or "scan_report.txt",
        )
        if not fname:
            return
        self.controller.last_report = fname
        results = self.controller.scan_results or {}
        try:
            with open(fname, "w") as f:
                if results.get("nmap"):
                    if results.get("error"):
                        f.write(f"Nmap error: {results['error']}\n")
                    else:
                        f.write("Open Ports (Nmap):\n")
                        for p in results.get("open_ports", []):
                            proto = p.get("protocol","tcp")
                            f.write(f"{p['port']}/{proto} - {p.get('service','')}\n")
                else:
                    if results.get("error"):
                        f.write(f"Error: {results['error']}\n")
                    else:
                        res = results.get("result", {})
                        f.write(f"Target: {res.get('target')} ({res.get('target_ip')})\n")
                        f.write(f"Total ports scanned: {res.get('total_ports')}\n")
                        f.write(f"Open ports: {len(res.get('open_ports', []))}\n")
                        f.write(f"Scan duration: {res.get('scan_duration'):.2f}s\n\n")
                        if res.get('open_ports'):
                            f.write("Open ports:\n")
                            for port in res['open_ports']:
                                serv = Config.PORT_SERVICES.get(port, "Unknown")
                                f.write(f"{port} - {serv}\n")
                        else:
                            f.write("No open ports found\n")
            messagebox.showinfo("Report Saved", f"Report written to {fname}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def save_report(self):
        # open save dialog
        fname = filedialog.asksaveasfilename(
            title="Save Scan Report",
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"), ("All files","*.*")],
            initialfile=self.controller.last_report or "scan_report.txt",
        )
        if not fname:
            return
        self.controller.last_report = fname
        results = self.controller.scan_results or {}
        try:
            with open(fname, "w") as f:
                if results.get("nmap"):
                    if results.get("error"):
                        f.write(f"Nmap error: {results['error']}\n")
                    else:
                        f.write("Open Ports (Nmap):\n")
                        for p in results.get("open_ports", []):
                            proto = p.get("protocol","tcp")
                            f.write(f"{p['port']}/{proto} - {p.get('service','')}\n")
                else:
                    if results.get("error"):
                        f.write(f"Error: {results['error']}\n")
                    else:
                        res = results.get("result", {})
                        f.write(f"Target: {res.get('target')} ({res.get('target_ip')})\n")
                        f.write(f"Total ports scanned: {res.get('total_ports')}\n")
                        f.write(f"Open ports: {len(res.get('open_ports', []))}\n")
                        f.write(f"Scan duration: {res.get('scan_duration'):.2f}s\n\n")
                        if res.get('open_ports'):
                            f.write("Open ports:\n")
                            for port in res['open_ports']:
                                serv = Config.PORT_SERVICES.get(port, "Unknown")
                                f.write(f"{port} - {serv}\n")
                        else:
                            f.write("No open ports found\n")
            messagebox.showinfo("Report Saved", f"Report written to {fname}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def on_show(self, event=None):
        # populate treeview with latest scan results
        self.tree.delete(*self.tree.get_children())
        results = self.controller.scan_results or {}
        if results.get("nmap"):
            # just list open ports, others not available
            if results.get("error"):
                self.tree.insert("", "end", values=("", "error", results.get("error")), tags=("error",))
            else:
                open_ports = results.get("open_ports", [])
                if open_ports:
                    for p in open_ports:
                        proto = p.get("protocol", "tcp")
                        self.tree.insert("", "end", values=(p['port'], "open", p.get('service','')), tags=("open",))
                else:
                    self.tree.insert("", "end", values=("-", "none", "No open ports"))
        else:
            if results.get("error"):
                self.tree.insert("", "end", values=("", "error", results.get("error")), tags=("error",))
            else:
                res = results.get("result", {})
                # optionally show summary row
                self.tree.insert("", "end", values=("Target", "", f"{res.get('target')} ({res.get('target_ip')})"))
                for entry in res.get("results", []):
                    port, status, service = entry
                    tag = status if status in ("open","closed","timeout","error") else ""
                    self.tree.insert("", "end", values=(port, status, service), tags=(tag,))

        # bind show event handled in __init__


class VisualPage(ttk.Frame):
    """3‑D interactive visualization of the scan results."""

    def __init__(self, parent, controller: PortScannerApp):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="3D Visualization", style="Header.TLabel").pack(pady=10)
        self.fig = Figure(figsize=(6,4))
        self.ax = self.fig.add_subplot(111, projection='3d')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="← Back", command=lambda: controller.show_frame("ResultsPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="New Scan", command=lambda: controller.show_frame("StartPage")).pack(side="left", padx=5)

        self.bind("<<ShowFrame>>", self.on_show)

    def on_show(self, event=None):
        # redraw plot based on latest results
        self.ax.clear()
        res = self.controller.scan_results or {}
        ports = []
        statuses = []
        if res.get("nmap"):
            # only open ports available from nmap helper
            for p in res.get("open_ports", []):
                ports.append(p['port'])
                statuses.append('open')
        else:
            if not res.get('error'):
                sc = res.get('result', {})
                for entry in sc.get('results', []):
                    # entry is (port, status, service)
                    port, status, _ = entry
                    ports.append(port)
                    statuses.append(status)
        # create a circular layout around z-axis
        try:
            import numpy as np
        except ImportError:
            messagebox.showerror("Dependency Missing", "numpy is required for 3D visualization")
            return
        if ports:
            theta = np.linspace(0, 2*np.pi, len(ports), endpoint=False)
            radii = np.full_like(theta, 1.0)
            xs = radii * np.cos(theta)
            ys = radii * np.sin(theta)
            zs = np.zeros_like(theta)
            # map status to color: open=green, closed=red, timeout=orange
            color_map = {'open':'green','closed':'red','timeout':'orange'}
            colors = [color_map.get(s,'gray') for s in statuses]
            self.ax.scatter(xs, ys, zs, c=colors, s=50)
            for i, port in enumerate(ports):
                self.ax.text(xs[i], ys[i], zs[i], str(port), size=8)
        self.ax.set_xlabel('X')
        self.ax.set_ylabel('Y')
        self.ax.set_zlabel('Z')
        self.ax.set_title('Open ports around host')
        self.canvas.draw()

# removed duplicate on_show method from VisualPage

    def tkraise(self, aboveThis=None):
        # override tkraise to trigger our custom event when page appears
        super().tkraise(aboveThis)
        self.event_generate("<<ShowFrame>>")
