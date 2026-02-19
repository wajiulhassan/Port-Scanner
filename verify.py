#!/usr/bin/env python3
"""
Verification script to check if all features are installed and working.
"""

import sys
import subprocess

def check_module(module_name, pip_name=None):
    """Check if a module is installed."""
    try:
        __import__(module_name)
        print(f"✅ {module_name}: OK")
        return True
    except ImportError:
        print(f"❌ {module_name}: MISSING (pip install {pip_name or module_name})")
        return False

def main():
    print("=" * 60)
    print("🔍 Port Scanner v2.0 - Verification Check")
    print("=" * 60)
    
    all_ok = True
    
    # Core modules
    print("\n Checking Core Modules...")
    all_ok &= check_module("tkinter")
    all_ok &= check_module("socket")
    all_ok &= check_module("threading")
    
    # GUI modules
    print("\n Checking GUI Modules...")
    all_ok &= check_module("tkinter.ttk")
    all_ok &= check_module("ttkbootstrap", "ttkbootstrap")
    
    # Visualization
    print("\n Checking Visualization Modules...")
    all_ok &= check_module("matplotlib", "matplotlib")
    all_ok &= check_module("numpy", "numpy")
    
    # Scheduling
    print("\n Checking Scheduling Modules...")
    all_ok &= check_module("schedule", "schedule")
    
    # Project modules
    print("\n Checking Project Files...")
    import os
    files = ["gui.py", "scanner.py", "config.py", "Utils.py", 
             "nmap_integration.py", "main.py", "Requirements.txt"]
    for f in files:
        if os.path.exists(f):
            print(f" {f}: Found")
        else:
            print(f" {f}: MISSING")
            all_ok = False
    
    # Check Python version
    print("\n Checking Python Version...")
    if sys.version_info >= (3, 7):
        print(f" Python {sys.version.split()[0]}: OK")
    else:
        print(f" Python {sys.version.split()[0]}: Too old (need 3.7+)")
        all_ok = False
    
    print("\n" + "=" * 60)
    if all_ok:
        print(" ALL CHECKS PASSED! Ready to use.")
        print("\n To start the scanner:")
        print("   python main.py          (GUI mode)")
        print("   python main.py --cli    (CLI mode)")
    else:
        print(" Some checks failed. Install missing packages:")
        print("   pip install -r Requirements.txt")
    print("=" * 60)
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
