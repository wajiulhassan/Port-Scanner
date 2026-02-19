#!/usr/bin/env python3
"""Test script to verify results data structure"""

from scanner import PortScanner
from config import Config

# Test with localhost
if __name__ == "__main__":
    try:
        scanner = PortScanner(
            target="localhost",
            timeout=2,
            threads=4,
            verbose=False,
            output_file=None
        )
        
        # Scan common ports
        ports = [21, 22, 80, 443, 3306, 5432, 8080]
        results = scanner.scan(ports)
        
        print("=" * 60)
        print("FULL RESULTS STRUCTURE:")
        print("=" * 60)
        print(f"Results keys: {results.keys()}")
        print(f"\nResults type: {type(results)}")
        
        print("\n" + "=" * 60)
        print("CHECKING 'results' KEY:")
        print("=" * 60)
        
        result_list = results.get("results", [])
        print(f"Results list type: {type(result_list)}")
        print(f"Results list length: {len(result_list)}")
        
        if result_list:
            print(f"\nFirst item: {result_list[0]}")
            print(f"First item type: {type(result_list[0])}")
            print(f"First item is tuple/list: {isinstance(result_list[0], (tuple, list))}")
            print(f"First item length: {len(result_list[0]) if isinstance(result_list[0], (tuple, list)) else 'N/A'}")
        
        print("\n" + "=" * 60)
        print("ALL RESULTS ITEMS:")
        print("=" * 60)
        for i, item in enumerate(result_list):
            print(f"{i}: {item}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
