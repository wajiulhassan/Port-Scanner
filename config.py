"""
Configuration settings for the port scanner
"""

class Config:
    """Configuration constants."""
    
    # Default settings
    DEFAULT_TIMEOUT = 1.0
    DEFAULT_THREADS = 50
    MAX_THREADS = 1000
    
    # Common ports for quick scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
        1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9999
    ]
    
    # Port service mapping
    PORT_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt',
        9999: 'Unkown Service'
    }
    
    # Logging configuration
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
