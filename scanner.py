"""
Main port scanner implementation with threading support
"""

import socket
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime

from config import Config
from Utils import resolve_hostname, is_valid_port, format_time


class PortScanner:
    """Professional TCP Port Scanner with multi-threading support."""
    
    def __init__(self, target, timeout=Config.DEFAULT_TIMEOUT, 
                 threads=Config.DEFAULT_THREADS, verbose=False, output_file=None):
        """
        Initialize the port scanner.
        
        Args:
            target (str): Target hostname or IP address
            timeout (float): Connection timeout in seconds
            threads (int): Number of threads to use
            verbose (bool): Enable verbose output
            output_file (str): Optional output file path
        """
        self.target = target
        self.timeout = timeout
        self.threads = min(threads, Config.MAX_THREADS)
        self.verbose = verbose
        self.output_file = output_file
        
        # Resolve target IP
        self.target_ip = resolve_hostname(target)
        if not self.target_ip:
            raise ValueError(f"Could not resolve hostname: {target}")
        
        # Setup logging
        self._setup_logging()
        
        # Thread-safe results storage
        self.lock = threading.Lock()
        self.open_ports = []
        self.closed_ports = []
        self.timeout_ports = []
        
        self.logger.info(f"Scanner initialized for {self.target} ({self.target_ip})")
    
    def _setup_logging(self):
        """Setup logging configuration."""
        Path(".gitignore").mkdir(exist_ok=True)
        
        # Configure logging
        log_filename = f".gitignore/scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format=Config.LOG_FORMAT,
            datefmt=Config.LOG_DATE_FORMAT,
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler() if self.verbose else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def scan_port(self, port):
        """
        Scan a single port.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port, status, service) where status is 'open', 'closed', or 'timeout'
        """
        if not is_valid_port(port):
            return port, 'invalid', 'Invalid Port'
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    service = Config.PORT_SERVICES.get(port, 'Unknown')
                    with self.lock:
                        self.open_ports.append(port)
                    self.logger.info(f"Port {port} is OPEN ({service})")
                    return port, 'open', service
                else:
                    with self.lock:
                        self.closed_ports.append(port)
                    self.logger.debug(f"Port {port} is CLOSED")
                    return port, 'closed', 'N/A'
                    
        except socket.timeout:
            with self.lock:
                self.timeout_ports.append(port)
            self.logger.debug(f"Port {port} TIMEOUT")
            return port, 'timeout', 'N/A'
            
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            return port, 'error', str(e)
    
    def scan(self, ports):
        """
        Scan multiple ports using threading.
        
        Args:
            ports (list): List of port numbers to scan
            
        Returns:
            dict: Scan results with timing information
        """
        print(f"🎯 Target: {self.target} ({self.target_ip})")
        print(f"🔧 Threads: {self.threads}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print(f"📊 Scanning {len(ports)} ports...")
        print("-" * 50)
        
        start_time = time.time()
        results = []
        
        try:
            # Use ThreadPoolExecutor for efficient thread management
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all port scan tasks
                future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
                
                # Process completed tasks
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Print real-time results for open ports
                        if result[1] == 'open':
                            print(f"✅ Port {result[0]}/tcp OPEN - {result[2]}")
                            
                    except Exception as e:
                        self.logger.error(f"Error processing port {port}: {e}")
                        results.append((port, 'error', str(e)))
        
        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted!")
            raise
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Compile final results
        scan_results = {
            'target': self.target,
            'target_ip': self.target_ip,
            'total_ports': len(ports),
            'open_ports': sorted(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'timeout_ports': len(self.timeout_ports),
            'scan_duration': scan_duration,
            'results': results
        }
        
        # Save results to file if specified
        if self.output_file:
            self._save_results(scan_results)
        
        return scan_results
    
    def print_summary(self, results):
        """
        Print scan summary.
        
        Args:
            results (dict): Scan results from scan() method
        """
        print("\n" + "=" * 50)
        print("📋 SCAN SUMMARY")
        print("=" * 50)
        
        print(f"Target: {results['target']} ({results['target_ip']})")
        print(f"Total ports scanned: {results['total_ports']}")
        print(f"Open ports: {len(results['open_ports'])}")
        print(f"Closed ports: {results['closed_ports']}")
        print(f"Timeout ports: {results['timeout_ports']}")
        print(f"Scan duration: {format_time(results['scan_duration'])}")
        
        if results['open_ports']:
            print(f"\n🟢 OPEN PORTS ({len(results['open_ports'])}):")
            print("-" * 30)
            for port in results['open_ports']:
                service = Config.PORT_SERVICES.get(port, 'Unknown')
                print(f"  {port}/tcp - {service}")
        else:
            print("\n❌ No open ports found")
        
        print("\n" + "=" * 50)
    
    def _save_results(self, results):
        """Save scan results to file."""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"Port Scan Results for {results['target']}\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {results['target']} ({results['target_ip']})\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {format_time(results['scan_duration'])}\n\n")
                
                if results['open_ports']:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 20 + "\n")
                    for port in results['open_ports']:
                        service = Config.PORT_SERVICES.get(port, 'Unknown')
                        f.write(f"{port}/tcp - {service}\n")
                else:
                    f.write("No open ports found.\n")
            
            print(f"💾 Results saved to: {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    """Professional TCP Port Scanner with threading support."""
    
    def __init__(self, target, timeout=Config.DEFAULT_TIMEOUT, 
                 threads=Config.DEFAULT_THREADS, verbose=False, output_file=None):
        """
        Initialize the port scanner.
        
        Args:
            target (str): Target hostname or IP address
            timeout (float): Connection timeout in seconds
            threads (int): Number of threads to use
            verbose (bool): Enable verbose output
            output_file (str): Optional output file path
        """
        self.target = target
        self.timeout = timeout
        self.threads = min(threads, Config.MAX_THREADS)
        self.verbose = verbose
        self.output_file = output_file
        
        # Resolve target IP
        self.target_ip = resolve_hostname(target)
        if not self.target_ip:
            raise ValueError(f"Could not resolve hostname: {target}")
        
        # Setup logging
        self._setup_logging()
        
        # Thread-safe results storage
        self.lock = threading.Lock()
        self.open_ports = []
        self.closed_ports = []
        self.timeout_ports = []
        
        self.logger.info(f"Scanner initialized for {self.target} ({self.target_ip})")
    
    def _setup_logging(self):
        """Setup logging configuration."""
        # Create logs directory if it doesn't exist
        Path(".gitignore").mkdir(exist_ok=True)
        
        # Configure logging
        log_filename = f".gitignore/scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format=Config.LOG_FORMAT,
            datefmt=Config.LOG_DATE_FORMAT,
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler() if self.verbose else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def scan_port(self, port):
        """
        Scan a single port.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port, status, service) where status is 'open', 'closed', or 'timeout'
        """
        if not is_valid_port(port):
            return port, 'invalid', 'Invalid Port'
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    service = Config.PORT_SERVICES.get(port, 'Unknown')
                    with self.lock:
                        self.open_ports.append(port)
                    self.logger.info(f"Port {port} is OPEN ({service})")
                    return port, 'open', service
                else:
                    with self.lock:
                        self.closed_ports.append(port)
                    self.logger.debug(f"Port {port} is CLOSED")
                    return port, 'closed', 'N/A'
                    
        except socket.timeout:
            with self.lock:
                self.timeout_ports.append(port)
            self.logger.debug(f"Port {port} TIMEOUT")
            return port, 'timeout', 'N/A'
            
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            return port, 'error', str(e)
    
    def scan(self, ports):
        """
        Scan multiple ports using threading.
        
        Args:
            ports (list): List of port numbers to scan
            
        Returns:
            dict: Scan results with timing information
        """
        print(f"🎯 Target: {self.target} ({self.target_ip})")
        print(f"🔧 Threads: {self.threads}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print(f"📊 Scanning {len(ports)} ports...")
        print("-" * 50)
        
        start_time = time.time()
        results = []
        
        try:
            # Use ThreadPoolExecutor for efficient thread management
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all port scan tasks
                future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
                
                # Process completed tasks
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Print real-time results for open ports
                        if result[1] == 'open':
                            print(f"✅ Port {result[0]}/tcp OPEN - {result[2]}")
                            
                    except Exception as e:
                        self.logger.error(f"Error processing port {port}: {e}")
                        results.append((port, 'error', str(e)))
        
        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted!")
            raise
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Compile final results
        scan_results = {
            'target': self.target,
            'target_ip': self.target_ip,
            'total_ports': len(ports),
            'open_ports': sorted(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'timeout_ports': len(self.timeout_ports),
            'scan_duration': scan_duration,
            'results': results
        }
        
        # Save results to file if specified
        if self.output_file:
            self._save_results(scan_results)
        
        return scan_results
    
    def print_summary(self, results):
        """
        Print scan summary.
        
        Args:
            results (dict): Scan results from scan() method
        """
        print("\n" + "=" * 50)
        print("📋 SCAN SUMMARY")
        print("=" * 50)
        
        print(f"Target: {results['target']} ({results['target_ip']})")
        print(f"Total ports scanned: {results['total_ports']}")
        print(f"Open ports: {len(results['open_ports'])}")
        print(f"Closed ports: {results['closed_ports']}")
        print(f"Timeout ports: {results['timeout_ports']}")
        print(f"Scan duration: {format_time(results['scan_duration'])}")
        
        if results['open_ports']:
            print(f"\n🟢 OPEN PORTS ({len(results['open_ports'])}):")
            print("-" * 30)
            for port in results['open_ports']:
                service = Config.PORT_SERVICES.get(port, 'Unknown')
                print(f"  {port}/tcp - {service}")
        else:
            print("\n❌ No open ports found")
        
        print("\n" + "=" * 50)
    
    def _save_results(self, results):
        """Save scan results to file."""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"Port Scan Results for {results['target']}\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {results['target']} ({results['target_ip']})\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {format_time(results['scan_duration'])}\n\n")
                
                if results['open_ports']:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 20 + "\n")
                    for port in results['open_ports']:
                        service = Config.PORT_SERVICES.get(port, 'Unknown')
                        f.write(f"{port}/tcp - {service}\n")
                else:
                    f.write("No open ports found.\n")
            
            print(f"💾 Results saved to: {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
