"""
Optional Nmap integration helper.

This module calls the system `nmap` binary (if available) and parses
the XML output to return a list of open ports and service names.

It intentionally uses `subprocess` and XML parsing to avoid adding a
hard dependency on third-party Python packages; the user must install
the Nmap executable separately for this feature to work.
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional


def nmap_available() -> bool:
    """Return True if the `nmap` binary is available on PATH."""
    return shutil.which("nmap") is not None


def run_nmap(
    target: str,
    ports: Optional[List[int]] = None,
    top_ports: Optional[int] = None,
    service_version: bool = False,
    os_detection: bool = False,
    protocol: str = "tcp",
) -> Dict[str, Any]:
    """
    Run nmap against `target` with flexible options.

    Args:
        target: hostname or IP
        ports: explicit list of ports to scan (overrides `top_ports`)
        top_ports: if set, use --top-ports N (or use -F for 100)
        service_version: enable service/version detection (-sV)
        os_detection: enable OS detection (-O)
        protocol: 'tcp' or 'udp'

    Returns a dict with keys:
      - `ok` (bool): whether the run succeeded and produced parsable output
      - `open_ports` (list): list of dicts {port:int, service:str}
      - `raw` (str): raw nmap stdout (XML)
      - `error` (str): error message when `ok` is False
    """
    if not nmap_available():
        return {"ok": False, "error": "nmap binary not found on PATH"}

    cmd = ["nmap", "-Pn", "-T4", "-oX", "-"]

    # Protocol scan type
    if protocol.lower() == "udp":
        cmd.append("-sU")
    else:
        # default TCP connect scan (no raw sockets)
        cmd.append("-sT")

    # service/version and OS detection
    if service_version:
        cmd.append("-sV")
    if os_detection:
        cmd.append("-O")

    # Ports selection
    if ports:
        ports_str = ",".join(str(p) for p in ports)
        cmd.extend(["-p", ports_str])
    elif top_ports:
        # Nmap supports --top-ports N; for top 100 -F could be used
        cmd.extend(["--top-ports", str(top_ports)])

    # Target last
    cmd.append(target)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        return {"ok": False, "error": f"failed to run nmap: {e}"}

    stderr = (proc.stderr or "").strip()
    # If Nmap failed to run and emitted no stdout, handle Npcap/permission problems
    if proc.returncode != 0 and not proc.stdout:
        # If OS detection was requested, Nmap may require Npcap/raw sockets; try retry without -O
        if os_detection and ("Npcap" in stderr or "TCP/IP fingerprinting" in stderr or "QUITTING!" in stderr):
            safe_cmd = [c for c in cmd if c != "-O"]
            try:
                proc2 = subprocess.run(safe_cmd, capture_output=True, text=True, timeout=300)
            except Exception as e:
                return {"ok": False, "error": f"failed to run nmap (retry without -O): {e}", "stderr": stderr}

            if proc2.returncode != 0 and not proc2.stdout:
                return {"ok": False, "error": proc2.stderr.strip() or f"nmap failed (exit {proc2.returncode})", "stderr": stderr}

            xml_out = proc2.stdout
            warning = "Nmap required Npcap for OS detection; retried without OS detection. Install Npcap or run nmap as administrator to enable full features."
            return {"ok": True, "open_ports": _parse_nmap_xml(xml_out), "raw": xml_out, "warning": warning}

        return {"ok": False, "error": stderr or f"nmap failed (exit {proc.returncode})", "stderr": stderr}

    xml_out = proc.stdout

    # Parse and return results
    open_ports = _parse_nmap_xml(xml_out)
    return {"ok": True, "open_ports": open_ports, "raw": xml_out}


def _parse_nmap_xml(xml_out: str) -> List[Dict[str, Any]]:
    """Helper to parse nmap XML output and return open ports list."""
    try:
        root = ET.fromstring(xml_out)
    except ET.ParseError:
        return []

    open_ports: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port in ports_node.findall("port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            state = port.find("state")
            if state is None:
                continue
            state_val = state.get("state")
            if state_val != "open":
                continue
            service_node = port.find("service")
            service_name = service_node.get("name") if service_node is not None else "unknown"
            try:
                port_int = int(portid)
            except Exception:
                continue
            open_ports.append({"port": port_int, "service": service_name, "protocol": proto})

    return open_ports
