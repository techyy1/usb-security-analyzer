📄 Paste this into tests/test_basic.py:
#!/usr/bin/env python3
"""
Basic test script for USB Security Analyzer
Run this to verify your installation is working
"""

import sys
import os

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}  {text}{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def test_python_version():
    """Test Python version"""
    print_header("Testing Python Version")
    
    version = sys.version_info
    if version.major >= 3 and version.minor >= 6:
        print_success(f"Python {version.major}.{version.minor}.{version.micro} detected (OK)")
        return True
    else:
        print_error(f"Python {version.major}.{version.minor} detected - need 3.6+")
        return False

def test_psutil():
    """Test if psutil is installed"""
    print_header("Testing psutil Installation")
    
    try:
        import psutil
        print_success(f"psutil version {psutil.__version__} installed")
        return True
    except ImportError:
        print_error("psutil not installed")
        print_warning("Run: pip3 install psutil")
        return False

def test_usb_access():
    """Test USB device access"""
    print_header("Testing USB Device Access")
    
    # Check if running as root
    if os.geteuid() != 0:
        print_warning("Not running as root - USB access may be limited")
        print_warning("For full functionality, run with: sudo python3 tests/test_basic.py")
    
    # Try to list USB devices
    import subprocess
    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            devices = result.stdout.strip().split('\n')
            print_success(f"USB access working - found {len(devices)} devices")
            if devices and devices[0]:
                print(f"  First device: {devices[0][:60]}...")
            return True
        else:
            print_error("Failed to list USB devices")
            return False
    except Exception as e:
        print_error(f"USB access error: {e}")
        return False

def test_main_script():
    """Test if main script exists"""
    print_header("Testing Main Script")
    
    script_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'usb_analyzer.py')
    script_path = os.path.abspath(script_path)
    
    if os.path.exists(script_path):
        print_success(f"Main script found at: {script_path}")
        
        # Check if it's executable
        if os.access(script_path, os.X_OK):
            print_success("Script is executable")
        else:
            print_warning("Script not executable - run: chmod +x src/usb_analyzer.py")
        
        return True
    else:
        print_error(f"Main script not found at: {script_path}")
        return False

def test_import():
    """Test if we can import the main script's components"""
    print_header("Testing Import")
    
    try:
        # Add src to path
        src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
        sys.path.insert(0, os.path.abspath(src_path))
        
        # Try to import the script (will fail if syntax errors)
        import usb_analyzer
        print_success("Successfully imported usb_analyzer module")
        
        # Check if USBEnhancedAnalyzer class exists
        if hasattr(usb_analyzer, 'USBEnhancedAnalyzer'):
            print_success("USBEnhancedAnalyzer class found")
        else:
            print_error("USBEnhancedAnalyzer class not found")
            return False
            
        return True
    except Exception as e:
        print_error(f"Import failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}  USB SECURITY ANALYZER - TEST SUITE{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")
    
    tests = [
        ("Python Version", test_python_version),
        ("psutil Installation", test_psutil),
        ("USB Access", test_usb_access),
        ("Main Script", test_main_script),
        ("Module Import", test_import)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print_error(f"Test '{name}' crashed: {e}")
            results.append(False)
    
    # Summary
    print_header("Test Summary")
    passed = sum(1 for r in results if r)
    total = len(results)
    
    if passed == total:
        print_success(f"All {total} tests PASSED! ✅")
        print("\nYour USB Security Analyzer is ready to use!")
        print("Run it with: sudo python3 src/usb_analyzer.py")
    else:
        print_warning(f"{passed}/{total} tests passed")
        print("\nPlease fix the issues above before running the main tool.")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

💾 Save test_basic.py
1.    Press Ctrl+O, then Enter, then Ctrl+X

🚀 Make test file executable and commit everything
# Make test file executable
chmod +x tests/test_basic.py

# Add both new files to git
git add docs/usage.md tests/test_basic.py

# Commit them
git commit -m "Add usage documentation and basic test script"

# Push to GitHub
git push origin main

✅ Test your installation
# Run the test script
python3 tests/test_basic.py

# Or with sudo for full USB access
sudo python3 tests/test_basic.py

📂 Your complete project now has:

/home/hackerz/Documents/Projects/usb-security-analyzer/
├── src/
│   └── usb_analyzer.py
├── docs/
│   └── usage.md
├── scripts/
├── tests/
│   └── test_basic.py
├── README.md
├── LICENSE
├── .gitignore
└── requirements.txt
