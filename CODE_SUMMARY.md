# Port Scanner - Final Clean Code

## Project Structure

```
Port Scanner/
├── main.py              # Entry point - CLI or GUI launcher
├── gui.py               # Tkinter multi-page graphical interface with 3D visualization
├── scanner.py           # Core scanning engine
├── config.py            # Configuration settings
├── Utils.py             # Utility functions
├── init.py              # Package initializer
├── Requirements.txt     # Dependencies
└── ReadMe.md            # Documentation
```

## File Descriptions

### main.py
- **Purpose**: Entry point for the application (CLI or GUI launcher)
- **Features**:
  - Accepts target URL/IP from user
  - Automatically cleans protocol prefixes (http://, https://, etc.)
  - Scans common ports from config
  - Displays results in formatted output
  - Dispatches to graphical interface by default

### scanner.py
- **Purpose**: Core port scanning engine
- **Features**:
  - Multi-threaded port scanning using ThreadPoolExecutor
  - DNS resolution of hostnames
  - Port status detection (open/closed/timeout)
  - Service identification for known ports
  - Automatic logging
  - Results summary display

### config.py
- **Purpose**: Centralized configuration
- **Contains**:
  - DEFAULT_TIMEOUT: Connection timeout (1.0 seconds)
  - DEFAULT_THREADS: Number of threads (50)
  - COMMON_PORTS: List of 23 common ports to scan
  - PORT_SERVICES: Service names for known ports
  - Logging configuration

### Utils.py
- **Purpose**: Helper functions
- **Functions**:
  - `resolve_hostname()`: Resolve domain to IP
  - `is_valid_port()`: Validate port number
  - `format_time()`: Format duration in readable format
  - `parse_port_range()`: Parse port ranges

## Usage

- launch the graphical interface (default):

    ```bash
    python main.py
    ```

  *the GUI includes an interactive 3D port visualization (open/closed/timeouts are color‑coded) and a Save Report button.*

- or, force the legacy command‑line mode using the `--cli` flag:

    ```bash
    python main.py --cli
    ```

After starting either mode the scanner will prompt for a target such as:

- `google.com`
- `https://example.com`
- `192.168.1.1`

## How It Works

1. User enters target (URL or IP)
2. Code removes protocol prefix if present
3. Scanner resolves hostname to IP
4. Scans 23 common ports simultaneously using 50 threads
5. Displays open ports with service names
6. Shows complete scan summary

## Output Example

```
🔍 Professional TCP Port Scanner v1.0
==================================================

Enter target (URL/IP): google.com

🎯 Target: google.com

📡 Scanning 23 common ports...
--------------------------------------------------
🎯 Target: google.com (142.251.45.102)
🔧 Threads: 50
⏱️  Timeout: 1.0s
📊 Scanning 23 ports...
--------------------------------------------------
✅ Port 80/tcp OPEN - HTTP
✅ Port 443/tcp OPEN - HTTPS

==================================================
📋 SCAN SUMMARY
==================================================
Target: google.com (142.251.45.102)
Total ports scanned: 23
Open ports: 2
Closed ports: 21
Timeout ports: 0
Scan duration: 1.2s

🟢 OPEN PORTS (2):
------------------------------
  80/tcp - HTTP
  443/tcp - HTTPS

==================================================
```

## Code Quality

✅ Clean, professional code
✅ Proper error handling
✅ Multi-threading support
✅ Logging capabilities
✅ Service identification
✅ Well-documented functions
✅ Modular design
✅ Report export available from both CLI and GUI
