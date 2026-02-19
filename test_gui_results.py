#!/usr/bin/env python3
"""Quick test to verify scan results structure"""

from scanner import PortScanner
from config import Config

# Mock GUI results structure
def test_results_parsing():
    """Test how results would be parsed by the G UI"""
    
    # Simulate what the GUI does
    scanner = PortScanner(
        target="127.0.0.1",
        timeout=2,
        threads=4,
    )
    
    # Scan a few ports
    ports = [22, 80, 443, 3306]
    scan_result = scanner.scan(ports)
    
    # This is what happens line 180 of gui.py
    results = {"nmap": False, **scan_result}
    
    print("=" * 60)
    print("TESTING GUI RESULTS PARSING")
    print("=" * 60)
    
    # This is what ResultsTab.refresh() does
    if results.get("nmap"):
        print("Processing Nmap results...")
    else:
        result_list = results.get("results", [])
        print(f"Processing built-in scanner results")
        print(f"Result list length: {len(result_list)}")
        print(f"Result list: {result_list}")
        
        if not result_list:
            print("ERROR: No results found!")
        else:
            print("\nParsed items:")
            for i, item in enumerate(result_list):
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    port = str(item[0])
                    status = item[1]
                    service = item[2] if len(item) > 2 else "N/A"
                    print(f"  [{i}] Port={port}, Status={status}, Service={service}")
                else:
                    print(f"  [{i}] REJECTED: {item}")

if __name__ == "__main__":
    test_results_parsing()
