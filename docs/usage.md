# 📖 USB Security Analyzer - Usage Guide

A comprehensive guide to using the USB Security Analyzer tool.

---

## 🚀 Getting Started

### Installation
```bash
# Clone the repository
git clone https://github.com/techyy1/usb-security-analyzer.git
cd usb-security-analyzer

# Install dependencies
pip3 install psutil

# Run the tool
sudo python3 src/usb_analyzer.py

🎮 Main Menu Options
╔══════════════════════════════════════════════════════════════════╗
║     ENHANCED USB SECURITY ANALYZER - BADUSB & SHELL DETECTION    ║
╚══════════════════════════════════════════════════════════════════╝

1. List and analyze USB devices
2. Check for HID/BadUSB devices only
3. Safe mount check for a device
4. ⚠️ Check for known malicious USB signatures
5. ⌨️ Monitor keystroke patterns
6. 🔍 Scan for reverse shell activity
7. 📊 Full system audit pre/post USB
8. 🔄 Real-time USB monitor
9. Exit

🔍 Detailed Option Explanations
Option 1: List and Analyze USB Devices

Shows all connected USB devices with color-coding:

    🟢 Green: Normal devices

    🟡 Yellow: Suspicious devices

    🔴 Red: Known malicious devices

Example output:
[*] Scanning USB devices...

 1. Bus 001 Device 003: ID 1D50:6089 Hak5 Bunny  ⚠️ BASH BUNNY
 2. Bus 001 Device 005: ID 0781:5583 SanDisk Ultra Fit
Option 2: Check HID/BadUSB Devices

Scans specifically for Human Interface Devices that could be used for keystroke injection.

What it detects:

    Keyboards (potential Rubber Ducky)

    Devices with both HID and storage (Bash Bunny)

    Multiple HID devices (suspicious)

Option 3: Safe Mount Check

Analyzes a USB device without mounting it (read-only verification).

Process:

    Enter device path (e.g., /dev/sdb)

    Tool checks if device exists and isn't mounted

    Provides safe mount commands

Option 4: Malicious Signature Check

Compares connected devices against database of known BadUSB signatures.

Detects:

    🦆 Rubber Ducky (1D6B:0104)

    🐰 Bash Bunny (1D50:6089)

    📱 Flipper Zero (0483:3748)

    🔧 Teensy (16C0:05DF)

    ⚙️ Arduino-based BadUSB

    And 50+ more

Option 5: Keystroke Pattern Monitor

Real-time typing analysis to detect automated injection.

Speed thresholds:

    <100 WPM: Normal human typing 🟢

    100-200 WPM: Suspicious 🟡

    >200 WPM: Automated injection detected! 🔴

Example:
WPM: 245.3 [!] AUTOMATED TYPING DETECTED!
Interval: 0.3ms (Human minimum: ~100ms)

Option 6: Reverse Shell Scanner

Checks for active reverse shells and backdoors.

Scans for:

    Netcat listeners (ports 4444, 5555, 6666, 7777, 8888, 9001, 31337)

    Suspicious processes (bash -i, python -c, nc -lvp)

    Established connections to unknown hosts

    Meterpreter payloads

Option 7: Full System Audit

Compares system state before and after USB insertion.

Tracks changes in:

    Running processes

    Network connections

    USB devices

    System files

Process:

    Takes baseline snapshot

    Prompts you to insert USB

    Takes post-insertion snapshot

    Highlights differences

Option 8: Real-time Monitor

Watches for new USB connections and automatically scans for threats.

Features:

    Instant alerts when USB plugged in

    Automatic signature checking

    Immediate HID capability scan

    Reverse shell scan on detection

🎯 Common Use Cases
Case 1: Testing a Suspicious USB Drive
1. Run: sudo python3 src/usb_analyzer.py
2. Choose Option 4 (Malicious Signature Check)
3. If clean, choose Option 3 (Safe Mount Check)
4. Enter device path (e.g., /dev/sdb)
5. Follow safe mount instructions to examine contents

Case 2: Monitoring During a Pentest
1. Run: sudo python3 src/usb_analyzer.py
2. Choose Option 8 (Real-time Monitor)
3. Leave running while testing USB devices
4. Watch for automatic alerts

Case 3: Investigating Potential Breach
1. Run: sudo python3 src/usb_analyzer.py
2. Choose Option 6 (Reverse Shell Scanner)
3. Choose Option 7 (Full System Audit)
4. Review findings

⚠️ Important Notes

Always Run as Root
# Correct
sudo python3 src/usb_analyzer.py

# Incorrect (will fail)
python3 src/usb_analyzer.py

Safe USB Handling

    Never mount suspicious drives directly

    Use read-only mounts for examination

    Isolate testing machine from network

    Use live Linux USB for high-risk analysis

False Positives

Some legitimate devices may trigger warnings:

    Some keyboards type fast (gaming keyboards)

    Multi-function printers may show HID+storage

    Development boards (Arduino) may appear suspicious

🐛 Troubleshooting

"No USB devices found"

# Check if USB devices are connected
lsusb

# Check if you have permission
sudo lsusb

"Permission denied"
# Always use sudo
sudo python3 src/usb_analyzer.py

"psutil not installed"
# Install psutil
pip3 install psutil

# On some systems:
sudo pip3 install psutil

Keystroke monitor not working
# Check if keyboard device exists
ls -la /dev/input/

# Check permissions
sudo python3 src/usb_analyzer.py

📊 Example Scenarios
Scenario: Rubber Ducky Detected
[!] WARNING: HID/Keyboard device detected!
    This could be a BadUSB device pretending to be a keyboard
    Attack potential: Reverse shell, keylogging, command injection
    
    Vendor ID: 0x1d6b
    Product ID: 0x0104
    ⚠️ RUBBER DUCKY - USB Gadget

Scenario: Reverse Shell Found
[!] SUSPICIOUS PROCESSES DETECTED!
    PID: 1234 - nc
    Indicator: nc -lvp 4444
    Connected to: 192.168.1.100:4444

🔒 Security Best Practices

    Always verify suspicious USBs in isolated environment

    Monitor system during USB insertion

    Check for new network connections

    Review process list after USB use

    Keep signature database updated

📝 Quick Reference Card
Action	Command/Option
Quick scan	Option 1
Check known threats	Option 4
Monitor typing	Option 5
Find reverse shells	Option 6
Live monitoring	Option 8
Safe mount	Option 3
🆘 Getting Help

    GitHub Issues: Report bugs

    Documentation: Check other docs in this folder

    Community: Join GitHub discussions

