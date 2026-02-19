"""
Utility functions for the port scanner
"""

import socket
import ipaddress

def resolve_hostname(hostname):
    """
    Resolve hostname to IP address.
    
    Args:
        hostname (str): Hostname or IP address
        
    Returns:
        str: IP address or None if resolution fails
    """
    # First try to parse as an IP address
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except (ValueError, ipaddress.AddressValueError):
        pass
    
    # If not an IP, try DNS resolution
    try:
        result = socket.gethostbyname(hostname)
        return result
    except (socket.gaierror, socket.error):
        return None

def is_valid_port(port):
    """
    Check if port number is valid.
    
    Args:
        port (int): Port number
        
    Returns:
        bool: True if valid, False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535

def format_time(seconds):
    """
    Format time duration in a readable format.
    
    Args:
        seconds (float): Time in seconds
        
    Returns:
        str: Formatted time string
    """
    if seconds < 1:
        return f"{seconds:.2f} seconds"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"

def parse_port_range(port_range):
    """
    Parse port range string into list of ports.
    
    Args:
        port_range (str): Port range in format "start-end"
        
    Returns:
        list: List of port numbers
        
    Raises:
        ValueError: If range format is invalid
    """
    try:
        start, end = map(int, port_range.split('-'))
        if start > end or start < 1 or end > 65535:
            raise ValueError("Invalid port range")
        return list(range(start, end + 1))
    except Exception:
        raise ValueError("Invalid port range format. Use: start-end (e.g., 1-1000)")
