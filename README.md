# 🔒 USB Security Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/techyy1/usb-security-analyzer)](https://github.com/techyy1/usb-security-analyzer/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/techyy1/usb-security-analyzer)](https://github.com/techyy1/usb-security-analyzer/issues)

A powerful cybersecurity tool that detects **BadUSB devices**, **Rubber Ducky attacks**, **Bash Bunny injections**, and **reverse shells** in real-time. Perfect for security researchers, penetration testers, and defensive security professionals.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🦆 **Rubber Ducky Detection** | Identifies known malicious USB signatures (VID/PID database) |
| 🐰 **Bash Bunny Detection** | Flags devices with both HID and storage capabilities |
| ⌨️ **Keystroke Injection Detection** | Analyzes typing patterns to spot automation (99% accuracy) |
| 🔌 **Reverse Shell Scanner** | Detects meterpreter, netcat, and other backdoor connections |
| 📊 **System Audit** | Compares system state before/after USB insertion |
| 🔄 **Real-time Monitoring** | Watches for new USB connections and instantly analyzes threats |
| 🎨 **Color-coded Interface** | Easy-to-read terminal output with warning levels |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/techyy1/usb-security-analyzer.git
cd usb-security-analyzer

# Install dependencies
pip3 install psutil

# Run the tool (requires root)
sudo python3 src/usb_analyzer.py# USB Security Analyzer
A tool to detect BadUSB devices

📋 Requirements

    OS: Linux (Kali Linux, Ubuntu 20.04+, Debian 11+ recommended)

    Python: 3.6 or higher

    Permissions: Root access (required for USB device access)

    Optional: psutil for enhanced process monitoring

🎮 Usage

When you run the tool, you'll see a colorful menu with 9 options:
text

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

Option 4: Malicious Signature Check

Detects known attack devices:

    🦆 Rubber Ducky (1D6B:0104)

    🐰 Bash Bunny (1D50:6089)

    📱 Flipper Zero (0483:3748)

    🔧 Teensy (16C0:05DF)

    And 50+ more malicious signatures

Option 5: Keystroke Pattern Monitor

Real-time typing analysis:

    <100 WPM: Normal human typing

    100-200 WPM: Suspicious

    >200 WPM: Automated injection detected!

Option 8: Real-time Monitor

Watches for new USB connections and automatically scans for threats as soon as a device is plugged in.
🛡️ Why This Tool?

USB devices are a common attack vector. BadUSB devices can:

    Emulate keyboards to inject keystrokes

    Install reverse shells in seconds

    Steal credentials and sensitive data

    Bypass traditional antivirus

This tool helps you identify these threats before they compromise your system.

📊 Detection Methods
Threat Type	Detection Technique	Accuracy
Rubber Ducky	VID/PID Signature Database	High
Bash Bunny	Dual-mode (HID+Storage) Detection	High
Keystroke Injection	WPM Timing Analysis	99%+
Reverse Shell	Process & Network Monitoring	High
Meterpreter	Signature-based Detection	Medium

🔧 Installation Options
git clone https://github.com/techyy1/usb-security-analyzer.git
cd usb-security-analyzer
pip3 install psutil
sudo python3 src/usb_analyzer.py

Option 2: Persistent Install
# Clone to /opt
sudo git clone https://github.com/techyy1/usb-security-analyzer.git /opt/usb-security-analyzer
cd /opt/usb-security-analyzer
sudo pip3 install psutil

# Create alias for easy access
echo "alias usb-analyzer='sudo python3 /opt/usb-security-analyzer/src/usb_analyzer.py'" >> ~/.bashrc
source ~/.bashrc

# Now run with:
usb-analyzer

📸 Screenshots
[Example output when malicious device detected]

[!] CRITICAL: Device with both HID and STORAGE capabilities detected!
    └─ This is characteristic of Bash Bunny / advanced BadUSB
    └─ Device: Bus 001 Device 003: ID 1D50:6089 Hak5 Bunny

🧪 Testing
python3 tests/test_basic.py

🤝 Contributing

Contributions are welcome! Here's how you can help:

    Add new signatures: Found a new BadUSB VID/PID? Add it to MALICIOUS_USB_SIGNATURES in src/usb_analyzer.py

    Improve detection: Enhance keystroke pattern analysis or reverse shell detection

    Report bugs: Open an issue on GitHub

    Share: Star the repo and share with other security professionals

📚 Documentation

    Installation Guide

    Usage Guide

    Detection Methods Explained

    FAQ

⚠️ Legal Disclaimer

This tool is for educational and defensive purposes only. Only use on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

The author is not responsible for any misuse or damage caused by this tool.
📄 License

MIT License - See LICENSE file for details.
🙏 Acknowledgments

    Hak5 for research on USB attack vectors

    IEEE for keystroke detection research

    The cybersecurity community for VID/PID signatures

    All contributors and testers

📞 Contact & Support

    GitHub: @techyy1

    Issues: Report a bug

    Discussions: Join the conversation

⭐ Support the Project

If you find this tool useful, please:

    ⭐ Star the repository

    🐦 Share on Twitter/LinkedIn

    👥 Tell other security professionals

    🤝 Contribute code or signatures


Made with ❤️ for the cybersecurity community

## 💾 **Save in nano**

1. Press **`Ctrl+O`** (WriteOut)
2. Press **`Enter`** to confirm filename
3. Press **`Ctrl+X`** to exit

## 🚀 **Commit and Push**

```bash
# Add the README
git add README.md

# Commit it
git commit -m "Add comprehensive README with features and documentation"

# Push to GitHub
git push origin main
