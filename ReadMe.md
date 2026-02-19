# Professional TCP Port Scanner

A high-performance, multi-threaded TCP port scanner built with Python's standard library.

## Features

- ✅ Multi-threaded scanning for improved performance
- ✅ Support for single host scanning
- ✅ Flexible port specification (individual ports or ranges)
- ✅ Comprehensive logging with timestamps
- ✅ Professional output formatting
- ✅ Exception handling and error recovery
- ✅ Real-time scan progress
- ✅ Results export to file
- ✅ Service detection for common ports
- ✅ Timeout handling for unreachable ports

## Installation

```bash
git clone <repository-url>
cd port_scanner



## 🚀 Key Features Implemented

1. **Professional Structure**: Modular design with separate configuration, utilities, and main scanner logic
2. **Multi-threading**: Efficient concurrent scanning using ThreadPoolExecutor
3. **Comprehensive Logging**: Detailed logs with timestamps saved to files
4. **Error Handling**: Robust exception handling for network errors and timeouts
5. **Flexible Port Options**: Support for both individual ports and ranges
6. **Service Detection**: Identifies common services running on open ports
7. **Real-time Output**: Live progress updates during scanning
8. **Results Export**: Option to save results to text files
9. **Input Validation**: Proper validation of hosts, ports, and parameters
10. **Professional CLI**: Well-structured command-line interface with help text

## 💡 Usage Examples

```bash
# Quick scan of common ports
python main.py -t scanme.nmap.org -p 21,22,23,80,443

# Full port range scan with high thread count
python main.py -t 192.168.1.1 -r 1-65535 -T 200 -v

# Scan with results export
python main.py -t example.com -r 1-1000 -o scan_results.txt

# Launch graphical interface (default) or force CLI mode
python main.py        # opens the Tkinter multi-page UI with interactive 3D visualization of scan results
python main.py --cli  # run the classic terminal CLI

```


The GUI provides a polished multi‑page interface, allows you to toggle between textual results and an **interactive 3‑D plot** (rotate/zoom with the mouse) that color‑codes open/closed/timeout ports, and includes a **Save Report** button to export the scan summary to a text file.  

Optionally install `ttkbootstrap` (listed in requirements) for a more modern/dark theme; the app will use it automatically if available.

Example output (CLI) — the command‑line version will also ask whether to save a report file at the end of a scan:

```
🔍 Professional TCP Port Scanner v1.0
==================================================
🎯 Target: google.com (172.217.12.14)
🔧 Threads: 50
⏱️  Timeout: 1.0s
📊 Scanning 3 ports...
--------------------------------------------------
✅ Port 80/tcp OPEN - HTTP
✅ Port 443/tcp OPEN - HTTPS

==================================================
📋 SCAN SUMMARY
==================================================
Target: google.com (172.217.12.14)
Total ports scanned: 3
Open ports: 2
Closed ports: 1
Timeout ports: 0
Scan duration: 0.15 seconds

🟢 OPEN PORTS (2):
------------------------------
  80/tcp - HTTP
  443/tcp - HTTPS
==================================================
