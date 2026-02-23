#!/usr/bin/env python3
"""
Enhanced USB Security Analyzer
Detects: Rubber Ducky, Bash Bunny, Reverse Shells, Keystroke Injection
"""

import subprocess
import sys
import os
import time
import threading
import socket
import re
from datetime import datetime
from collections import deque

# Try to import psutil, but don't fail if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[!] psutil not installed. Some features will be limited.")
    print("[*] Install with: pip install psutil")

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'  # Added PURPLE
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    END = '\033[0m'

# Known malicious USB signatures 
MALICIOUS_USB_SIGNATURES = {
    # Rubber Ducky & Hak5 Devices
    "1D6B:0104": "⚠️ RUBBER DUCKY - USB Gadget (HID Keyboard)",
    "1D50:6089": "⚠️ BASH BUNNY - Hak5 Attack Device",
    "0FC5:B080": "⚠️ HAK5 KEYBOARD INJECTOR",
    "1D50:60C6": "⚠️ HAK5 WiFi Coconut",
    "1D50:60A4": "⚠️ HAK5 LAN Turtle",
    "1D50:60A5": "⚠️ HAK5 Packet Squirrel",
    "1D50:60A6": "⚠️ HAK5 Plunder Bug",
    
    # Arduino-based BadUSB 
    "2341:8036": "⚠️ Arduino Micro (Potential BadUSB - EvilDuck)",
    "2341:8037": "⚠️ Arduino Leonardo (Potential BadUSB)",
    "239A:0001": "⚠️ Teensy (Rubber Ducky Compatible)",
    "16C0:05DF": "⚠️ Teensy 2.0 (BadUSB Capable)",
    "16C0:0483": "⚠️ Teensy 3.0/4.0",
    
    # Flipper Zero & Others 
    "0483:3748": "⚠️ Flipper Zero (BadUSB Capable)",
    "303A:4001": "⚠️ Flipper Zero - Advanced Mode",
    "1EAF:0004": "⚠️ USB Rubber Ducky - Original",
    "03EB:2044": "⚠️ Atmel Touchpad (Potential BadUSB)",
}

class USBEnhancedAnalyzer:
    def __init__(self):
        self.baseline_processes = set()
        self.baseline_connections = set()
        self.keystroke_buffer = deque(maxlen=100)
        self.last_keystroke_time = None
        self.suspicious_patterns = []
        self.monitoring = False
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Print colorful banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════╗
{Colors.YELLOW}║     ENHANCED USB SECURITY ANALYZER - BADUSB & SHELL DETECTION    ║
{Colors.GREEN}║         Detects Rubber Ducky, Bash Bunny, Reverse Shells          ║
{Colors.CYAN}║                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                    ║
{Colors.RED}╚══════════════════════════════════════════════════════════════════╝{Colors.END}
"""
        print(banner)
    
    def print_menu(self):
        """Display the enhanced main menu"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}    USB SECURITY ANALYZER - ENHANCED EDITION{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}1.{Colors.END} List and analyze USB devices")
        print(f"{Colors.CYAN}2.{Colors.END} Check for HID/BadUSB devices only")
        print(f"{Colors.CYAN}3.{Colors.END} Safe mount check for a device")
        print(f"{Colors.CYAN}4.{Colors.END} {Colors.RED}⚠️{Colors.END} Check for known malicious USB signatures (Rubber Ducky, Bash Bunny) ")
        print(f"{Colors.CYAN}5.{Colors.END} {Colors.YELLOW}⌨️{Colors.END} Monitor keystroke patterns (detect automated injection) ")
        print(f"{Colors.CYAN}6.{Colors.END} {Colors.RED}🔍{Colors.END} Scan for reverse shell / meterpreter activity ")
        print(f"{Colors.CYAN}7.{Colors.END} {Colors.BLUE}📊{Colors.END} Full system audit pre/post USB insertion")
        print(f"{Colors.CYAN}8.{Colors.END} {Colors.PURPLE}🔄{Colors.END} Real-time USB monitor with threat detection")
        print(f"{Colors.CYAN}9.{Colors.END} Exit")
        print(f"{Colors.BOLD}{Colors.BLUE}═══════════════════════════════════════════════════════════════{Colors.END}")
    
    def check_sudo(self):
        """Check if running with sudo"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!] This script must be run as root (sudo){Colors.END}")
            print(f"{Colors.YELLOW}[*] Try: sudo python3 {sys.argv[0]}{Colors.END}")
            return False
        return True
    
    def list_usb_devices(self):
        """List all USB devices with colors"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Scanning USB devices...{Colors.END}\n")
        
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.strip().split('\n')
            
            if not devices or devices == ['']:
                print(f"{Colors.YELLOW}[!] No USB devices found{Colors.END}")
                return []
            
            for i, device in enumerate(devices):
                # Check if this is a known malicious device
                malicious = self.check_malicious_signature_in_line(device)
                if malicious:
                    print(f"{Colors.RED}{i+1:2d}. {device} {malicious}{Colors.END}")
                elif i % 2 == 0:
                    print(f"{Colors.CYAN}{i+1:2d}. {device}{Colors.END}")
                else:
                    print(f"{Colors.GREEN}{i+1:2d}. {device}{Colors.END}")
            
            print(f"\n{Colors.BOLD}{Colors.BLUE}[+] Found {len(devices)} USB devices{Colors.END}")
            return devices
        except Exception as e:
            print(f"{Colors.RED}[!] Error listing devices: {e}{Colors.END}")
            return []
    
    def check_malicious_signature_in_line(self, device_line):
        """Extract VID:PID from lsusb line and check against malicious database"""
        # Parse lsusb output format: "Bus XXX Device YYY: ID 1234:5678 Manufacturer Product"
        match = re.search(r'ID ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})', device_line)
        if match:
            vid_pid = match.group(1).upper()
            if vid_pid in MALICIOUS_USB_SIGNATURES:
                return MALICIOUS_USB_SIGNATURES[vid_pid]
        return None
    
    def check_malicious_signatures(self):
        """Option 4: Check for known malicious USB devices """
        print(f"\n{Colors.BOLD}{Colors.RED}[*] Scanning for known malicious USB signatures...{Colors.END}\n")
        
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.strip().split('\n')
            
            found = False
            for device in devices:
                if not device.strip():
                    continue
                signature = self.check_malicious_signature_in_line(device)
                if signature:
                    print(f"{Colors.RED}{Colors.BOLD}{signature}{Colors.END}")
                    print(f"{Colors.YELLOW}  └─ Device: {device}{Colors.END}")
                    print(f"{Colors.CYAN}     This device can emulate a keyboard and inject keystrokes{Colors.END}")
                    print(f"{Colors.CYAN}     Common attack: Reverse shell, credential harvesting, data exfiltration {Colors.END}\n")
                    found = True
            
            if not found:
                print(f"{Colors.GREEN}[✓] No known malicious USB devices detected{Colors.END}")
                print(f"{Colors.YELLOW}[*] Note: Custom BadUSB devices may still be present{Colors.END}")
            
            # Also check for HID devices that could be BadUSB
            self.check_hid_devices_enhanced()
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
    
    def check_hid_devices_enhanced(self):
        """Enhanced HID device check with behavioral analysis"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Checking for HID devices with BadUSB potential...{Colors.END}\n")
        
        try:
            # Get detailed USB info
            result = subprocess.run(['lsusb', '-v'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            
            current_device = ""
            hid_found = False
            storage_found = False
            
            for line in lines:
                if 'Bus' in line and 'Device' in line and 'ID' in line:
                    if current_device and hid_found and storage_found:
                        print(f"{Colors.RED}{Colors.BOLD}[!] CRITICAL: Device with both HID and STORAGE capabilities detected!{Colors.END}")
                        print(f"{Colors.YELLOW}    └─ This is characteristic of Bash Bunny / advanced BadUSB {Colors.END}")
                        print(f"{Colors.CYAN}    └─ Device: {current_device}{Colors.END}")
                        print(f"{Colors.CYAN}    └─ Can inject keystrokes AND appear as a normal flash drive{Colors.END}\n")
                    elif hid_found:
                        print(f"{Colors.YELLOW}[!] HID Keyboard device detected: {current_device}{Colors.END}")
                    
                    current_device = line.strip()
                    hid_found = False
                    storage_found = False
                
                if 'bInterfaceClass' in line:
                    if 'Human Interface Device' in line:
                        hid_found = True
                    if 'Mass Storage' in line:
                        storage_found = True
            
            # Check last device
            if current_device and hid_found and storage_found:
                print(f"{Colors.RED}{Colors.BOLD}[!] CRITICAL: Device with both HID and STORAGE capabilities detected!{Colors.END}")
                print(f"{Colors.YELLOW}    └─ This is characteristic of Bash Bunny / advanced BadUSB {Colors.END}")
                print(f"{Colors.CYAN}    └─ Device: {current_device}{Colors.END}")
                print(f"{Colors.CYAN}    └─ Can inject keystrokes AND appear as a normal flash drive{Colors.END}\n")
            elif hid_found:
                print(f"{Colors.YELLOW}[!] HID Keyboard device detected: {current_device}{Colors.END}")
                    
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] Device analysis timed out{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error in HID detection: {e}{Colors.END}")
    
    def monitor_keystroke_patterns(self):
        """Option 5: Monitor keystroke patterns to detect automated injection """
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Starting keystroke pattern monitor...{Colors.END}")
        print(f"{Colors.CYAN}[*] This will detect automated typing (Rubber Ducky style attacks){Colors.END}")
        print(f"{Colors.CYAN}[*] Humans type at 40-80 WPM, devices can type 1000+ WPM{Colors.END}")
        print(f"{Colors.RED}[!] Press Ctrl+C to stop monitoring{Colors.END}\n")
        
        try:
            # Find keyboard device
            kb_device = self.find_keyboard_device()
            if not kb_device:
                print(f"{Colors.RED}[!] No keyboard device found. Make sure you're on a system with a keyboard.{Colors.END}")
                print(f"{Colors.YELLOW}[*] Try running on your main system, not a VM without USB passthrough.{Colors.END}")
                return
            
            print(f"{Colors.GREEN}[✓] Monitoring keyboard: {kb_device}{Colors.END}")
            print(f"{Colors.YELLOW}[*] Start typing to see WPM analysis...{Colors.END}\n")
            
            # Open and monitor the device
            with open(kb_device, 'rb') as f:
                keystroke_times = []
                
                while True:
                    # Read input event (24 bytes on Linux)
                    data = f.read(24)
                    if data:
                        current_time = time.time()
                        keystroke_times.append(current_time)
                        
                        # Keep only last 50 keystrokes
                        if len(keystroke_times) > 50:
                            keystroke_times.pop(0)
                        
                        # Calculate typing speed over last 10 keystrokes
                        if len(keystroke_times) >= 10:
                            recent = keystroke_times[-10:]
                            time_span = recent[-1] - recent[0]
                            if time_span > 0:
                                wpm = (10 / time_span) * 12  # 12 keystrokes = ~1 word
                                
                                # Color code based on speed
                                if wpm > 200:
                                    color = Colors.RED
                                    warning = f"{Colors.RED}{Colors.BOLD}[!] AUTOMATED TYPING DETECTED!{Colors.END}"
                                elif wpm > 100:
                                    color = Colors.YELLOW
                                    warning = f"{Colors.YELLOW}[!] Suspicious typing speed{Colors.END}"
                                else:
                                    color = Colors.GREEN
                                    warning = f"{Colors.GREEN}[✓] Normal typing speed{Colors.END}"
                                
                                sys.stdout.write(f"\r{color}WPM: {wpm:.1f} {warning}{Colors.END}    ")
                                sys.stdout.flush()
                        
                        # Check for impossible timing (sub-millisecond keystrokes)
                        if len(keystroke_times) > 1:
                            interval = keystroke_times[-1] - keystroke_times[-2]
                            if interval < 0.001:  # Less than 1ms between keystrokes
                                print(f"\n{Colors.RED}{Colors.BOLD}[!] IMPOSSIBLE TYPING SPEED DETECTED!{Colors.END}")
                                print(f"{Colors.YELLOW}    Interval: {interval*1000:.2f}ms (Human minimum: ~100ms){Colors.END}")
                                print(f"{Colors.YELLOW}    This is characteristic of Rubber Ducky injection {Colors.END}")
                        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] Keystroke monitoring stopped{Colors.END}")
        except PermissionError:
            print(f"{Colors.RED}[!] Permission denied. Make sure to run with sudo.{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
    
    def find_keyboard_device(self):
        """Find the keyboard input device """
        try:
            # Common keyboard device paths
            for event_file in os.listdir('/dev/input'):
                if event_file.startswith('event'):
                    full_path = f'/dev/input/{event_file}'
                    
                    # Check if it's a keyboard using udevadm
                    try:
                        result = subprocess.run(['udevadm', 'info', '--query=property', '--name=' + full_path], 
                                              capture_output=True, text=True, timeout=2)
                        
                        if 'ID_INPUT_KEYBOARD=1' in result.stdout:
                            return full_path
                    except:
                        continue
            
            # Fallback: return first event device if we can't identify
            if os.path.exists('/dev/input/event0'):
                return '/dev/input/event0'
        except:
            pass
        return None
    
    def scan_reverse_shell(self):
        """Option 6: Scan for reverse shell / meterpreter activity """
        print(f"\n{Colors.BOLD}{Colors.RED}[*] Scanning for reverse shell activity...{Colors.END}\n")
        
        if not PSUTIL_AVAILABLE:
            print(f"{Colors.YELLOW}[!] psutil not installed. Using basic system commands instead.{Colors.END}")
            self.scan_reverse_shell_basic()
            return
        
        try:
            suspicious_processes = []
            suspicious_connections = []
            
            # Check for common reverse shell patterns 
            reverse_shell_indicators = [
                'nc -lvp', 'nc -lvnp', 'netcat',
                'bash -i', '/bin/bash -i',
                'python -c', 'python3 -c',
                'perl -e', 'php -r',
                'socat', 'ncat',
                'powershell -enc', 'powershell -e',
                'meterpreter', 'msfvenom'
            ]
            
            # Check all running processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    
                    # Check for reverse shell indicators in command line
                    for indicator in reverse_shell_indicators:
                        if indicator in cmdline.lower():
                            suspicious_processes.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'cmdline': cmdline[:100] + "..." if len(cmdline) > 100 else cmdline,
                                'indicator': indicator
                            })
                            break
                    
                    # Check for suspicious network connections
                    # Check for suspicious network connections
                    try:
                        # FIXED: changed connections() to net_connections()
                        for conn in proc.net_connections(kind='inet'):
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                # Flag non-standard ports
                                if conn.raddr.port in [4444, 5555, 6666, 7777, 8888, 9001, 31337]:
                                    suspicious_connections.append({
                                        'pid': proc.info['pid'],
                                        'name': proc.info['name'],
                                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                                        'port': conn.raddr.port
                                    })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        # AttributeError handles case where net_connections isn't available
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Report findings
            if suspicious_processes:
                print(f"{Colors.RED}{Colors.BOLD}[!] SUSPICIOUS PROCESSES DETECTED!{Colors.END}")
                for proc in suspicious_processes:
                    print(f"{Colors.YELLOW}    PID: {proc['pid']} - {proc['name']}{Colors.END}")
                    print(f"{Colors.CYAN}    Indicator: {proc['indicator']}{Colors.END}")
                    print(f"{Colors.DIM}    Cmd: {proc['cmdline']}{Colors.END}\n")
            
            if suspicious_connections:
                print(f"{Colors.RED}{Colors.BOLD}[!] SUSPICIOUS NETWORK CONNECTIONS!{Colors.END}")
                for conn in suspicious_connections:
                    print(f"{Colors.YELLOW}    PID: {conn['pid']} - {conn['name']}{Colors.END}")
                    print(f"{Colors.RED}    Connected to: {conn['remote']} (Port {conn['port']} - Common reverse shell port){Colors.END}\n")
            
            if not suspicious_processes and not suspicious_connections:
                print(f"{Colors.GREEN}[✓] No reverse shell indicators found{Colors.END}")
                
            # Check for netcat listeners 
            self.check_netcat_listeners()
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
    
    def scan_reverse_shell_basic(self):
        """Basic reverse shell scan without psutil"""
        try:
            # Check for netcat processes
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            found = False
            for line in lines:
                line_lower = line.lower()
                if any(indicator in line_lower for indicator in ['nc -l', 'netcat', 'bash -i', 'python -c']):
                    print(f"{Colors.YELLOW}[!] Potential reverse shell process: {line[:100]}{Colors.END}")
                    found = True
            
            if not found:
                print(f"{Colors.GREEN}[✓] No obvious reverse shell processes found{Colors.END}")
                
            self.check_netcat_listeners()
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
    
    def check_netcat_listeners(self):
        """Check for netcat listeners that could be waiting for reverse shells """
        try:
            result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'LISTEN' in line:
                    for port in ['4444', '5555', '6666', '7777', '8888', '9001', '31337']:
                        if f':{port}' in line:
                            print(f"{Colors.RED}{Colors.BOLD}[!] Potential reverse shell listener detected on port {port}!{Colors.END}")
                            print(f"{Colors.YELLOW}    {line}{Colors.END}")
        except:
            pass
    
    def full_system_audit(self):
        """Option 7: Full system audit pre/post USB insertion"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Performing full system audit...{Colors.END}\n")
        
        # Take baseline snapshot
        print(f"{Colors.YELLOW}[*] Taking system baseline (pre-USB)...{Colors.END}")
        baseline = self.take_system_snapshot()
        
        print(f"\n{Colors.GREEN}[✓] Baseline captured{Colors.END}")
        print(f"{Colors.YELLOW}[*] Now plug in the USB device and press Enter when ready...{Colors.END}")
        input()
        
        # Take post-insertion snapshot
        print(f"{Colors.YELLOW}[*] Taking post-USB snapshot...{Colors.END}")
        time.sleep(2)  # Wait for any auto-run
        post = self.take_system_snapshot()
        
        # Compare
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Analyzing changes...{Colors.END}\n")
        
        # Check for new processes
        new_procs = post['processes'] - baseline['processes']
        if new_procs:
            print(f"{Colors.RED}[!] New processes detected:{Colors.END}")
            for proc in list(new_procs)[:10]:  # Show first 10
                print(f"{Colors.YELLOW}    → {proc[:100]}{Colors.END}")
            if len(new_procs) > 10:
                print(f"{Colors.YELLOW}    ... and {len(new_procs)-10} more{Colors.END}")
        
        # Check for new network connections
        new_conns = post['connections'] - baseline['connections']
        if new_conns:
            print(f"{Colors.RED}[!] New network connections detected:{Colors.END}")
            for conn in new_conns:
                print(f"{Colors.YELLOW}    → {conn}{Colors.END}")
        
        # Check for USB device changes
        new_usb = post['usb_devices'] - baseline['usb_devices']
        if new_usb:
            print(f"{Colors.GREEN}[+] New USB devices:{Colors.END}")
            for usb in new_usb:
                # Check if malicious
                sig = self.check_malicious_signature_in_line(usb)
                if sig:
                    print(f"{Colors.RED}    → {usb} {sig}{Colors.END}")
                else:
                    print(f"{Colors.CYAN}    → {usb}{Colors.END}")
        
        if not new_procs and not new_conns and not new_usb:
            print(f"{Colors.GREEN}[✓] No significant changes detected{Colors.END}")
    
    def take_system_snapshot(self):
        """Take a snapshot of system state"""
        snapshot = {
            'processes': set(),
            'connections': set(),
            'usb_devices': set()
        }
        
        # Get processes
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:11]:  # First 10 processes only
                if line.strip():
                    snapshot['processes'].add(line[:100])  # Truncate long lines
        except:
            pass
        
        # Get network connections
        try:
            result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    snapshot['connections'].add(line)
        except:
            pass
        
        # Get USB devices
        try:
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    snapshot['usb_devices'].add(line)
        except:
            pass
        
        return snapshot
    
    def real_time_monitor(self):
        """Option 8: Real-time USB monitor with threat detection"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[*] Starting real-time USB monitor...{Colors.END}")
        print(f"{Colors.YELLOW}[*] Monitoring for new USB connections and threats{Colors.END}")
        print(f"{Colors.RED}[!] Press Ctrl+C to stop{Colors.END}\n")
        
        known_devices = set()
        
        try:
            while True:
                # Check current USB devices
                result = subprocess.run(['lsusb'], capture_output=True, text=True)
                current = set(result.stdout.strip().split('\n'))
                
                # Check for new devices
                new_devices = current - known_devices
                for device in new_devices:
                    if device.strip():
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        
                        # Check if malicious
                        sig = self.check_malicious_signature_in_line(device)
                        if sig:
                            print(f"{Colors.RED}{Colors.BOLD}[{timestamp}] ⚠️ MALICIOUS USB DETECTED!{Colors.END}")
                            print(f"{Colors.RED}    {sig}{Colors.END}")
                            print(f"{Colors.YELLOW}    Device: {device}{Colors.END}")
                            
                            # Immediately check for HID capabilities
                            self.check_hid_devices_enhanced()
                            
                            # Monitor for process changes
                            self.scan_reverse_shell()
                        else:
                            print(f"{Colors.GREEN}[{timestamp}] New USB: {device}{Colors.END}")
                
                # Check for removed devices
                removed = known_devices - current
                for device in removed:
                    if device.strip():
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        print(f"{Colors.BLUE}[{timestamp}] USB removed: {device}{Colors.END}")
                
                known_devices = current
                time.sleep(2)
                
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] Real-time monitoring stopped{Colors.END}")
    
    def analyze_menu(self):
        """Handle the device analysis option"""
        devices = self.list_usb_devices()
        
        if not devices:
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Enter the device number to analyze (or 0 to cancel):{Colors.END}")
        
        try:
            choice = input(f"{Colors.GREEN}→ {Colors.END}").strip()
            
            if choice == '0':
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                self.analyze_device_details(devices[idx])
                
                # Ask for physical device path
                print(f"\n{Colors.YELLOW}Enter physical device path (e.g., /dev/sdb) or press Enter to skip:{Colors.END}")
                dev_path = input(f"{Colors.GREEN}→ {Colors.END}").strip()
                if dev_path:
                    self.safe_mount_check(dev_path)
            else:
                print(f"{Colors.RED}[!] Invalid device number{Colors.END}")
                
        except ValueError:
            print(f"{Colors.RED}[!] Please enter a valid number{Colors.END}")
        
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    
    def analyze_device_details(self, device_line):
        """Analyze specific device details"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}  ANALYZING: {device_line}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.END}")
        
        # First check if it's a known malicious device
        sig = self.check_malicious_signature_in_line(device_line)
        if sig:
            print(f"\n{Colors.RED}{Colors.BOLD}[!] {sig}{Colors.END}")
            print(f"{Colors.YELLOW}    This device is designed for keystroke injection attacks{Colors.END}")
            print(f"{Colors.YELLOW}    Can execute: Reverse shells, credential harvesting, data theft {Colors.END}\n")
        
        # Extract bus and device numbers
        parts = device_line.split()
        if len(parts) >= 4:
            bus = parts[1]
            device = parts[3].rstrip(':')
            
            try:
                result = subprocess.run(['lsusb', '-v', '-s', f'{bus}:{device}'], 
                               capture_output=True, text=True, timeout=5)
                details = result.stdout
                
                # Check for HID/keyboard capabilities
                if 'bInterfaceClass' in details and 'Human Interface Device' in details:
                    print(f"\n{Colors.RED}{Colors.BOLD}[!] WARNING: HID/Keyboard device detected!{Colors.END}")
                    print(f"{Colors.RED}    This could be a BadUSB device pretending to be a keyboard{Colors.END}")
                    print(f"{Colors.YELLOW}    Attack potential: Reverse shell, keylogging, command injection {Colors.END}")
                
                # Check for mass storage
                if 'bInterfaceClass' in details and 'Mass Storage' in details:
                    print(f"\n{Colors.GREEN}[✓] Mass storage capability detected{Colors.END}")
                
                # Check vendor/product
                for line in details.split('\n'):
                    if 'idVendor' in line:
                        print(f"{Colors.BLUE}    Vendor ID: {line.strip()}{Colors.END}")
                    if 'idProduct' in line:
                        print(f"{Colors.BLUE}    Product ID: {line.strip()}{Colors.END}")
                    if 'iManufacturer' in line:
                        print(f"{Colors.CYAN}    Manufacturer: {line.strip()}{Colors.END}")
                    if 'iProduct' in line:
                        print(f"{Colors.CYAN}    Product: {line.strip()}{Colors.END}")
                    
            except subprocess.TimeoutExpired:
                print(f"{Colors.YELLOW}[!] Device analysis timed out{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error analyzing device: {e}{Colors.END}")
    
    def safe_mount_check(self, device_path):
        """Check if device can be safely mounted"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Safe mount check for {device_path}{Colors.END}")
        
        if not os.path.exists(device_path):
            print(f"{Colors.RED}[!] Device {device_path} not found{Colors.END}")
            return
        
        result = subprocess.run(['mount'], capture_output=True, text=True)
        if device_path in result.stdout:
            print(f"{Colors.RED}[!] Device is already mounted!{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[✓] Device exists and is not mounted{Colors.END}")
        print(f"{Colors.YELLOW}[*] To safely examine contents, use read-only mount:{Colors.END}")
        print(f"{Colors.CYAN}    sudo mkdir -p /mnt/usb_safe{Colors.END}")
        print(f"{Colors.CYAN}    sudo mount -o ro {device_path} /mnt/usb_safe{Colors.END}")
        print(f"{Colors.CYAN}    # Examine files, then unmount:{Colors.END}")
        print(f"{Colors.CYAN}    sudo umount /mnt/usb_safe{Colors.END}")
    
    def run(self):
        """Main menu loop"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            if not self.check_sudo():
                input(f"{Colors.YELLOW}Press Enter to exit...{Colors.END}")
                sys.exit(1)
            
            self.print_menu()
            
            try:
                choice = input(f"\n{Colors.GREEN}Enter your choice [1-9]: {Colors.END}").strip()
                
                if choice == '1':
                    self.analyze_menu()
                    
                elif choice == '2':
                    self.clear_screen()
                    self.print_banner()
                    self.check_hid_devices_enhanced()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '3':
                    self.clear_screen()
                    self.print_banner()
                    print(f"\n{Colors.YELLOW}Available devices:{Colors.END}")
                    os.system('lsblk | grep -E "disk|part"')
                    print()
                    dev_path = input(f"{Colors.GREEN}Enter device path (e.g., /dev/sdb): {Colors.END}").strip()
                    if dev_path:
                        self.safe_mount_check(dev_path)
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '4':
                    self.clear_screen()
                    self.print_banner()
                    self.check_malicious_signatures()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '5':
                    self.clear_screen()
                    self.print_banner()
                    self.monitor_keystroke_patterns()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '6':
                    self.clear_screen()
                    self.print_banner()
                    self.scan_reverse_shell()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '7':
                    self.clear_screen()
                    self.print_banner()
                    self.full_system_audit()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '8':
                    self.clear_screen()
                    self.print_banner()
                    self.real_time_monitor()
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
                    
                elif choice == '9':
                    print(f"\n{Colors.GREEN}[✓] Goodbye! Stay safe.{Colors.END}")
                    sys.exit(0)
                    
                else:
                    print(f"{Colors.RED}[!] Invalid option. Please enter 1-9{Colors.END}")
                    time.sleep(2)
                    
            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
                time.sleep(1)

if __name__ == "__main__":
    analyzer = USBEnhancedAnalyzer()
    analyzer.run()
