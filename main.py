#!/usr/bin/env python3
"""
Professional TCP Port Scanner
Description: A multi-threaded TCP port scanner for network security testing
"""

import sys
from scanner import PortScanner
from config import Config
from nmap_integration import nmap_available, run_nmap


def clean_target(target):
    """
    Remove protocol prefix and trailing slash from target.
    
    Args:
        target (str): Target URL or IP address
        
    Returns:
        str: Cleaned target hostname or IP
    """
    protocols = ["http://", "https://", "ftp://", "ftps://", "wss://"]
    target_lower = target.lower()
    
    for protocol in protocols:
        if target_lower.startswith(protocol):
            target = target[len(protocol):]
            break
    
    return target.rstrip('/')


def main():
    """CLI entry point - uses console input/output to perform scans."""
    # this function is retained for backwards compatibility with CLI usage
    print("🔍 Professional TCP Port Scanner v1.0")
    print("=" * 50)
    
    # Get target from user
    target = input("\nEnter target (URL/IP): ").strip()
    if not target:
        print("❌ Target is required")
        sys.exit(1)
    
    # Clean target
    target = clean_target(target)
    print(f"\n🎯 Target: {target}")
    
    # Use predefined common ports from config
    common_ports = Config.COMMON_PORTS

    # Ask user for advanced options like in the UI
    print("\nScan options:")
    service_ver = input("Detect service version? (y/N): ").strip().lower() in ("y", "yes")
    proto = input("Protocol (tcp/udp, default tcp): ").strip().lower() or "tcp"

    print("\nPort selection:")
    print("1. Common ports")
    print("2. List of ports (comma-separated)")
    print("3. Top N ports (e.g., 100)")
    choice = input("Choose option (1/2/3): ").strip() or "1"

    ports_to_scan = None
    top_n = None
    if choice == "1":
        ports_to_scan = common_ports
    elif choice == "2":
        raw = input("Enter ports (comma-separated): ").strip()
        try:
            ports_to_scan = [int(p.strip()) for p in raw.split(",") if p.strip()]
        except ValueError:
            print("Invalid ports list")
            sys.exit(1)
    elif choice == "3":
        num = input("Enter N for top N ports (e.g., 100): ").strip()
        try:
            top_n = int(num)
        except Exception:
            print("Invalid number")
            sys.exit(1)
    else:
        print("Invalid choice")
        sys.exit(1)

    # If user requested UDP but no nmap and built-in can't do UDP, warn
    if proto == "udp" and not nmap_available():
        print("\nUDP scanning requires Nmap. Please install Nmap or choose TCP.")
        sys.exit(1)

    # Ask whether to use Nmap (optional)
    use_nmap = False
    try:
        if nmap_available():
            ans = input("\nUse Nmap for scanning (recommended if installed)? (y/N): ").strip().lower()
            use_nmap = ans in ("y", "yes")
        else:
            print("\nNmap not found on PATH — using built-in scanner.")
    except Exception:
        use_nmap = False

    if use_nmap:
        print(f"\n📡 Running Nmap against {target}...")
        nmap_result = run_nmap(
            target,
            ports=ports_to_scan,
            top_ports=top_n,
            service_version=service_ver,
            protocol=proto,
        )
        if not nmap_result.get("ok"):
            print(f"❌ Nmap error: {nmap_result.get('error')}")
            print("Falling back to built-in scanner.")
            use_nmap = False
        else:
            open_ports = nmap_result.get("open_ports", [])
            if open_ports:
                print("\n✅ Open Ports (Nmap):")
                print("-" * 50)
                for p in open_ports:
                    proto_str = p.get('protocol', 'tcp')
                    print(f"  ✓ Port {p['port']}/{proto_str} OPEN - {p.get('service','unknown')}")
                else:
                    print("\n❌ No open ports found by Nmap")

            # report option for Nmap CLI
            save = input("\nSave Nmap report to file? (y/N): ").strip().lower() in ("y","yes")
            if save:
                path = input("Enter output filename: ").strip()
                if path:
                    try:
                        with open(path, 'w') as f:
                            if open_ports:
                                f.write("Open Ports (Nmap):\n")
                                for p in open_ports:
                                    proto_str = p.get('protocol','tcp')
                                    f.write(f"{p['port']}/{proto_str} - {p.get('service','unknown')}\n")
                            else:
                                f.write("No open ports found by Nmap\n")
                        print(f"Report saved to {path}")
                    except Exception as e:
                        print(f"Failed to save report: {e}")
    else:
        # Use built-in scanner
        try:
            scanner = PortScanner(
                target=target,
                timeout=Config.DEFAULT_TIMEOUT,
                threads=Config.DEFAULT_THREADS,
                verbose=False,
                output_file=None
            )
        except ValueError as e:
            print(f"❌ Error: {e}")
            sys.exit(1)

        # Execute scan
        try:
            results = scanner.scan(common_ports)
            scanner.print_summary(results)
        except KeyboardInterrupt:
            print("\n\n🛑 Scan interrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            sys.exit(1)

    # offer to save a report for CLI mode
    save = input("\nSave report to file? (y/N): ").strip().lower() in ("y","yes")
    if save:
        path = input("Enter output filename: ").strip()
        if path:
            try:
                scanner.output_file = path
                scanner._save_results(results)
            except Exception as e:
                print(f"Failed to save report: {e}")


if __name__ == "__main__":
    # prefer GUI if available unless explicit --cli flag provided
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        main()
    else:
        try:
            from gui import PortScannerApp
        except Exception as exc:
            # if GUI fails to import, fall back to CLI
            print(f"⚠️ GUI unavailable ({exc}), falling back to CLI")
            main()
        else:
            PortScannerApp().mainloop()
