# 🔍 Professional TCP Port Scanner v2.0

A **complete, enterprise-grade port scanner** with GUI, CLI, and advanced security features.

## ✨ Features Overview

| Feature | Status | Details |
|---------|--------|---------|
| **Multi-threaded Scanning** | ✅ | 5-20 concurrent threads |
| **Service Detection** | ✅ | Identify services on open ports |
| **OS Detection** | ✅ | Detect target OS |
| **Aggressive Scanning** | ✅ | Fast & thorough mode |
| **Stealth Scanning** | ✅ | IDS/IPS bypass capability |
| **Scan Techniques** | ✅ | TCP Connect, SYN, FIN, NULL, XMAS |
| **TCP/UDP Scanning** | ✅ | Both protocols supported |
| **Scan Scheduling** | ✅ | Automatic periodic scans |
| **3D Visualization** | ✅ | Interactive port visualization |
| **Detailed Reports** | ✅ | TXT & JSON export |
| **Nmap Integration** | ✅ | Advanced scanning with Nmap |
| **Professional GUI** | ✅ | Tabbed interface with dark theme |
| **CLI Mode** | ✅ | Command-line interface fallback |

---

## 🎯 Quick Start

### Installation
```bash
# 1. Install dependencies
pip install -r Requirements.txt

# 2. Verify setup
python verify.py

# 3. Run scanner
python main.py              # GUI mode (default)
python main.py --cli        # CLI mode
```

### Basic Usage (GUI)
1. Open GUI: `python main.py`
2. Enter target: `google.com` or `192.168.1.1`
3. Select ports: Common Ports / Top N / Custom
4. Click "▶ Start Scan"
5. View results in Summary/Results tabs
6. Export report: "📥 Download Report"

### Scan Types

#### 🟢 Simple Scan
- Common Ports (23 well-known ports)
- Time: ~5 seconds
- Best for: Quick reconnaissance

#### 🔥 Aggressive Scan
- Checkbox: "🔥 Aggressive Scan (Fast & Thorough)"
- Time: ~2-5 seconds
- Best for: Quick results, controlled environments

#### 🕷️ Stealth Scan
- Checkbox: "🕷️ Stealth Mode (Slow scanning - bypass IDS)"
- Time: ~1-2 minutes
- Best for: Evade IDS/IPS systems

---

## 📋 GUI Tabs Explained

### 1. **Scan Targets** (Configuration)
```
Input: Target address
Select: Port range/type
Choose: Protocol (TCP/UDP)
Advanced: Aggressive/Stealth modes
→ "▶ Start Scan"
```

### 2. **Schedule 📅** (Periodic Scans)
```
Set interval: Every X minutes/hours/days
Click: "▶ Start Scheduler"
Background: Automatic continuous scans
```

### 3. **Summary** (Statistics)
```
Open Ports: 🟢 4
Closed Ports: 🔴 996
Start Time: 10:30:45
Duration: 5.23s
```

### 4. **Results** (Detailed Table)
```
┌──────┬────────┬────────┬──────────┬─────────┐
│ Port │ Status │Service │ Product  │ Version │
├──────┼────────┼────────┼──────────┼─────────┤
│ 80   │ OPEN   │ HTTP   │ Apache   │ 2.4.41  │ 🟢
│ 443  │ OPEN   │ HTTPS  │ Nginx    │ 1.18.0  │ 🟢
│ 22   │ CLOSED │ SSH    │ -        │ -       │ 🔴
```

### 5. **3D Visualization** (Interactive)
```
- Ports arranged in circle
- Color by status (Green/Red/Orange/Purple)
- Mouse: Rotate/Zoom
```

---

## 🔧 Advanced Options

### Scan Techniques
- **TCP Connect Scan** (Standard, safest)
- **TCP SYN Scan** (Nmap-style)
- **FIN Scan** (Stealth, no SYN)
- **NULL Scan** (All flags off)
- **XMAS Scan** (FIN+PSH+URG)

### Modes
- **Normal**: Balanced performance
- **Aggressive**: 20 threads, 2s timeout
- **Stealth**: Slow, IDS-evading

---

## 📊 Output Examples

### Summary Dashboard
```
Open Ports: 4
Closed Ports: 996
Start Time: 2024-02-19 10:30:45
End Time: 2024-02-19 10:30:50
Duration: 5.23 seconds
```

### Results Table (Color-Coded)
```
Port 80    → OPEN   (🟢 Green)
Port 443   → OPEN   (🟢 Green)
Port 22    → CLOSED (🔴 Red)
Port 3389  → TIMEOUT (🟠 Orange)
```

### Downloaded Report
```
Target: google.com
Start: 2024-02-19 10:30:45
End: 2024-02-19 10:30:50
Duration: 5.23s

Open Ports:
  Port 80/tcp OPEN - http
  Port 443/tcp OPEN - https
  ...
```

---

## 🏗️ Project Structure

```
Port Scanner/
├── main.py                 # Entry point (GUI/CLI dispatcher)
├── gui.py                  # Professional Tkinter GUI (5 tabs)
├── scanner.py              # Multi-threaded port scanner
├── config.py               # Configuration constants
├── Utils.py                # Utility functions
├── nmap_integration.py      # Nmap wrapper
├── Requirements.txt        # Python dependencies
├── verify.py               # Setup verification
├── ReadMe.md               # This file
├── FEATURES.md             # Detailed feature list
```

---

## 📦 Dependencies

### Required (pip install -r Requirements.txt)
```
matplotlib   # 3D visualization
numpy        # Numerical calculations
ttkbootstrap # Modern GUI theme
schedule     # Periodic scanning
```

### Optional
```
nmap         # Advanced scanning (install separately)
```

---

## ⚙️ Configuration

Edit `config.py` to customize:
```python
DEFAULT_TIMEOUT = 3         # Connection timeout
DEFAULT_THREADS = 5        # Concurrent threads
MAX_THREADS = 50           # Maximum threads
COMMON_PORTS = [80, 443, 22, ...]  # Common ports
LOG_FORMAT = '...'         # Logging format
```

---

## 🔒 ⚠️ Legal Considerations

- **Use Only For**: 
  - Your own systems
  - Authorized penetration testing
  - Educational/training purposes
  - Network administration

- **Never Use For**:
  - Unauthorized scanning
  - Malicious purposes
  - Illegal network reconnaissance

**⚠️ Unauthorized port scanning is illegal in many jurisdictions!**

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| GUI doesn't start | `python main.py --cli` (use CLI mode) |
| Module not found | `pip install -r Requirements.txt` |
| Nmap not found | Install: `apt-get install nmap` (Linux) |
| Schedule module missing | `pip install schedule` |
| Permission denied | Run as administrator (can help with some ports) |

---

## 🚀 Version History

### v2.0 (Current)
- ✅ Complete GUI overhaul (tabbed interface)
- ✅ Advanced scanning options
- ✅ Periodic scan scheduling
- ✅ 3D visualization
- ✅ Multiple scan techniques
- ✅ Stealth mode implementation

### v1.0 (Previous)
- Basic CLI scanner
- Multi-threaded support
- Service detection

---

## 📞 Quick Commands

```bash
# Verify installation
python verify.py

# Start GUI
python main.py

# Start CLI
python main.py --cli

# Check Python version
python --version

# Install/update dependencies
pip install -r Requirements.txt
```

---

## 🎓 Learning Resources

- **FEATURES.md**: Complete feature breakdown
- **QUICKSTART_URDU.md**: Step-by-step guide in Urdu
- **Code comments**: Detailed inline documentation

---

## ✨ Summary

This is a **professional-grade port scanner** with:
- ✅ Modern GUI interface
- ✅ Advanced scanning techniques
- ✅ Automatic scheduling
- ✅ Professional reporting
- ✅ Multiple operation modes
- ✅ Comprehensive documentation

**Perfect for Security Professionals, Network Admins, and Ethical Hackers!**

---

**Version**: 2.0  
**License**: Open Source  
**Last Updated**: February 19, 2026
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
