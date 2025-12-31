<div align="center">


# 🔍 **ZERO Scanner v1.0** - Advanced SMB Security Assessment Tool

  <img src="https://i.ibb.co/SDCvHZn4/Image-fx-5.jpg" alt="ZERO Scanner Logo" width="400">
</div>
<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)
![Version](https://img.shields.io/badge/Version-1.0-brightgreen.svg)

**"From zero to full SMB enumeration in seconds"**

</div>

## 🔍 **Two Usage Modes: Interactive & Direct**

### **Mode 1: Interactive Menu (Recommended)**
Run without arguments to launch the **complete interactive menu system**:

```bash
python3 zero_scanner.py
```

**Features:**
- Step-by-step guidance through all options
- Color-coded menu interface
- Real-time dependency checking
- Configuration wizards
- Post-scan automation tools

### **Mode 2: Direct Command Line (Fast)**
Provide a target IP to run **immediately without menus**:

```bash
# Basic scan with default settings
python3 zero_scanner.py 192.168.1.100

# Full audit with all options
python3 zero_scanner.py 192.168.1.100 -m full -v -o results.json
```

**Features:**
- No interaction, straight to scanning
- Perfect for automation and scripts
- All command-line options available
- Fast results

### **Quick Reference:**

| What you need | Command to use |
|---------------|----------------|
| **Explore all features** | `python3 zero_scanner.py` |
| **Quick single scan** | `python3 zero_scanner.py 192.168.1.100` |
| **Advanced scan** | `python3 zero_scanner.py 192.168.1.100 -m full -v` |
| **Save to file** | `python3 zero_scanner.py 192.168.1.100 -o report.json` |
| **Custom ports** | `python3 zero_scanner.py 192.168.1.100 -m custom -p "139,445,135,3389"` |

## 📋 **What ZERO Scanner Does**

**ZERO Scanner v1.0** is a comprehensive security assessment tool designed by **.Zer0** for penetration testers, security researchers, and system administrators. It provides **complete SMB enumeration** with professional reporting and an intuitive interface.

### **Core Capabilities:**
- ✅ **Port Scanning** - Multiple modes (Basic, Full, Custom)
- ✅ **SMB Service Detection** - Version and OS fingerprinting
- ✅ **Share Enumeration** - Discover all accessible SMB shares
- ✅ **Vulnerability Assessment** - Check for MS17-010 (EternalBlue) and other vulnerabilities
- ✅ **User Enumeration** - Attempt to discover users and groups
- ✅ **Professional Reporting** - JSON and text reports with recommendations

## 🚀 **Key Features**

### **Smart Dependency Management**
- **Auto-detection** of missing tools before execution
- **OS-specific installation instructions** (Debian/Ubuntu, RHEL/CentOS, Arch)
- **Continue options** even if some tools are missing
- **Clear visual feedback** on available/missing tools

### **Advanced Scanning Options**
- **Basic Mode**: Ports 139 & 445 only (30 seconds)
- **Full Mode**: All SMB/AD ports (20+ ports, 60-90 seconds)
- **Custom Mode**: User-defined port ranges
- **Parallel scanning** with configurable threads

### **Professional Output**
- **Color-coded console output** for easy reading
- **JSON reports** for machine processing and integration
- **Text reports** with detailed findings and recommendations
- **Command generation** for manual follow-up testing

### **Post-Scan Automation**
- **enum4linux integration** for comprehensive enumeration
- **Share access testing** with multiple credential options
- **Vulnerability scanning** for known SMB vulnerabilities
- **Command generation** for extended manual testing

## 🛠️ **Installation**

### **1. Clone Repository**
```bash
git clone https://github.com/zeroaualy/zero-scanner.git
cd zero-scanner
```

### **2. Install Dependencies**
The script will check dependencies automatically, but you can install them manually:

**For Debian/Ubuntu/Kali:**
```bash
sudo apt-get update
sudo apt-get install -y nmap smbclient netcat samba-common-bin samba-client ldap-utils
```

**For RHEL/CentOS/Fedora:**
```bash
sudo yum install -y nmap samba-client nc samba-common-tools openldap-clients
```

### **3. Make Executable**
```bash
chmod +x zero_scanner.py
```

## 📖 **Complete Usage Guide**

### **Interactive Mode Walkthrough**

**Step 1: Launch the interface**
```bash
python3 zero_scanner.py
```

**Step 2: Choose from Main Menu**
```bash
🎯 ZERO SCANNER MAIN MENU
════════════════════════════════════════════════════════════

[1] Quick SMB Scan # Fast port 139/445 check
[2] Advanced SMB Audit # Complete scan with configuration
[3] Custom Configuration # Set wordlists, tools, timeouts
[4] Post-Scan Tools # Enum4Linux, share testing, etc.
[5] Exit
```

**Step 3: Follow the prompts**
- Enter target IP
- Choose scan mode
- Configure options
- View real-time results
- Access post-scan tools

### **Command Line Options**

| Option | Description | Example |
|--------|-------------|---------|
| `target` | Target IP/hostname (required for CLI mode) | `192.168.1.100` |
| `-m, --mode` | Scan mode: basic, full, custom | `-m full` |
| `-p, --ports` | Custom ports (for custom mode) | `-p "139,445,135,3389"` |
| `-o, --output` | Save results to file | `-o scan_results.json` |
| `-v, --verbose` | Enable verbose output | `-v` |
| `-f, --force` | Force scan even if ports appear closed | `-f` |
| `--no-banner` | Hide banner on startup | `--no-banner` |
| `-i, --interactive` | Force interactive mode | `-i` |

### **Examples:**

**Basic usage:**
```bash
# Interactive mode
python3 zero_scanner.py

# Direct scan mode
python3 zero_scanner.py 192.168.1.100
```

**Advanced scanning:**
```bash
# Full audit with verbose output
python3 zero_scanner.py 192.168.1.100 -m full -v

# Custom ports with report saving
python3 zero_scanner.py 192.168.1.100 -m custom -p "139,445,135,3389" -o report.json

# Force scan (ignore port status)
python3 zero_scanner.py 192.168.1.100 -f
```

**Batch scanning:**
```bash
#!/bin/bash
# Scan multiple targets
for ip in 192.168.1.{100..110}; do
    echo "Scanning $ip..."
    python3 zero_scanner.py $ip -o "scan_$ip.json" --no-banner
done
```

## 📊 **Sample Output**

### **Port Scan Results:**
```
[14:30:25] [INFO] Starting scan on target: 192.168.1.100
[14:30:25] [SCAN] Starting Full SMB/AD Ports scan...
[14:30:27] [SUCCESS] Port 139/tcp (NetBIOS Session): OPEN
[14:30:27] [SUCCESS] Port 445/tcp (SMB over TCP): OPEN
[14:30:28] [SUCCESS] Port 135/tcp (MSRPC): OPEN

📊 Port Scan Summary:
  Scanned: 12 ports
  Open: 4 ports
  Open ports:
    • 139/tcp - NetBIOS Session
    • 445/tcp - SMB over TCP
    • 135/tcp - MSRPC
    • 389/tcp - LDAP
```

### **Share Enumeration:**
```
[14:31:10] [SUCCESS] Found share: ADMIN$ (Disk)
[14:31:10] [SUCCESS] Found share: C$ (Disk)
[14:31:10] [SUCCESS] Found share: IPC$ (IPC) - IPC Service
[14:31:15] [SUCCESS] Not vulnerable to EternalBlue
```

### **Final Report:**
```
============================================================
           SCAN COMPLETED - SUMMARY
============================================================

📊 RESULTS:
  • Target: 192.168.1.100
  • Scan Mode: FULL
  • Ports Open: 4/12
  • Shares Found: 3
  • EternalBlue: NOT VULNERABLE
  • OS Detected: Windows 10 Pro 19042

🎯 RECOMMENDATIONS:
  1. Review discovered shares for proper permissions
  2. Close unnecessary ports (135/tcp)
  3. Enable SMB signing for enhanced security
  4. Consider disabling SMBv1 if not required

✓ Reports saved to: zero_scan_192.168.1.100_20241231_143025.json
✓ Text report saved to: zero_scan_192.168.1.100_20241231_143025.txt
```

## 🛠️ **Technical Specifications**

### **Dependencies**
The script checks for these tools automatically:

**Required Core Tools:**
- `nmap` (>= 7.80) - Network scanning
- `smbclient` (>= 4.10) - SMB protocol client
- `nc` (netcat) - Network connectivity testing

**Recommended Enumeration Tools:**
- `nmblookup` - NetBIOS name lookup
- `rpcclient` - RPC client for Windows services
- `net` - Samba net utility

**Optional Enhanced Tools:**
- `enum4linux` - Windows/Samba enumeration
- `ldapsearch` - LDAP query tool
- `polenum` - Windows policy enumeration
- `hydra` - Brute force testing

### **Supported Platforms**
- ✅ **Kali Linux** (Recommended)
- ✅ **Ubuntu/Debian** (18.04+)
- ✅ **Parrot Security OS**
- ✅ **Windows Subsystem for Linux (WSL2)**
- ✅ **RHEL/CentOS** (7+ with EPEL)
- ⚠️ **macOS** (Limited, requires manual tool installation)

### **Performance**
- **Scan Speed**: 30-90 seconds per host
- **Memory Usage**: < 100MB RAM
- **Network Impact**: Minimal, configurable timeouts
- **Parallel Processing**: Multi-threaded port scanning

## 🔧 **Advanced Features**

### **Custom Configuration**
Access through Main Menu → Custom Configuration:
- Set custom wordlist paths for brute force
- Configure tool locations if installed in non-standard paths
- Adjust scan timeouts (10-300 seconds)
- Set thread count for parallel processing (1-50)
- Configure output directory

### **Post-Scan Tools**
After any scan, access additional tools:
1. **Detailed Enumeration** - Automated enum4linux scans
2. **Share Access Testing** - Test credentials on discovered shares
3. **Vulnerability Scanning** - Check for known SMB vulnerabilities
4. **Command Generation** - Create command list for manual testing
5. **Report Export** - Save results in multiple formats

### **Error Handling**
- Graceful timeout handling for slow networks
- Missing dependency detection with installation help
- Network connectivity validation
- Permission and access right verification
- Clean exit on user interruption (Ctrl+C)

## 📁 **Project Structure**

```
zero-scanner/
│
├── zero_scanner.py              # Main scanner script with interactive menu
├── README.md                    # This documentation
├── LICENSE                      # MIT License
│

```

## 🔧 **Advanced Usage**

### **Python Integration**
```python
#!/usr/bin/env python3
# automation.py - Integrate with Python scripts
import subprocess
import json

def scan_target(target_ip):
    """Run ZERO scanner and parse results"""
    cmd = f"python3 zero_scanner.py {target_ip} -o -"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Parse JSON output
        data = json.loads(result.stdout)
        print(f"Scan completed for {target_ip}")
        print(f"Shares found: {len(data.get('scan_results', {}).get('shares', []))}")
        return data
    return None

# Example usage
if __name__ == "__main__":
    results = scan_target("192.168.1.100")
```

### **Docker Usage**
```dockerfile
# Dockerfile
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nmap \
    smbclient \
    netcat \
    samba-common-bin \
    samba-client \
    ldap-utils \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY zero_scanner.py /app/
WORKDIR /app

ENTRYPOINT ["python3", "zero_scanner.py"]
```

```bash
# Build and run
docker build -t zero-scanner .
docker run zero-scanner 192.168.1.100

# Interactive mode in Docker
docker run -it zero-scanner
```

## 📊 **Tool Comparison**

| Feature | ZERO Scanner | Nmap | Metasploit | Manual Testing |
|:---|:---:|:---:|:---:|:---:|
| **Speed** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐ |
| **Reporting** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Comprehensiveness** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Automation** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐ |
| **Learning Curve** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐ |

### **Key Advantages of ZERO Scanner:**
- **✅ All-in-One Solution** - Combines multiple tools into a single command
- **✅ Professional Reporting** - Built-in report generation with color coding
- **✅ Beginner Friendly** - Minimal learning curve with intuitive interface
- **✅ Consistent Output** - Standardized formatting across all scans
- **✅ Lightweight** - Pure Python with no external dependencies
- **✅ Ethical Focus** - Clear warnings and legal disclaimers built-in

## ⚠️ **Legal & Ethical Disclaimer**

**IMPORTANT - READ BEFORE USE:**

This tool is designed **exclusively for authorized security testing**. Unauthorized scanning of computer systems is illegal and punishable by law.

### **Authorized Use Cases**
- Testing your own systems and networks
- Authorized penetration testing engagements (with written permission)
- Security research with explicit authorization
- Educational purposes in controlled lab environments
- Compliance testing with proper authorization

### **Strictly Prohibited**
- Scanning networks without explicit written permission
- Testing systems you don't own or have permission to test
- Any activity that violates laws or regulations
- Malicious attacks on production systems
- Violation of terms of service

### **User Responsibility**
By using this tool, you agree to:
1. Obtain proper written authorization before scanning
2. Comply with all applicable laws and regulations
3. Respect privacy and data protection requirements
4. Use the tool only for legitimate security purposes
5. Accept full responsibility for your actions

**The developer (.Zer0) assumes no liability for misuse of this tool.**

## 🤝 **Contributing**

We welcome contributions from security professionals and developers!

### **Reporting Issues**
1. Check existing issues to avoid duplicates
2. Include full error messages and tracebacks
3. Provide exact reproduction steps
4. Include OS version and Python version
5. List installed tool versions (nmap, smbclient, etc.)

### **Feature Requests**
1. Describe the real-world use case
2. Explain the security benefit
3. Suggest implementation approach if possible
4. Consider backward compatibility

### **Code Contributions**
```bash
# 1. Fork and clone
git clone https://github.com/zeroaualy/zero-scanner.git
cd zero-scanner

# 2. Create feature branch
git checkout -b feature/improvement-name

# 3. Test your changes
python3 zero_scanner.py 127.0.0.1 -v
python3 zero_scanner.py 192.168.1.1 -f

# 4. Commit and push
git add .
git commit -m "feat: add new feature"
git push origin feature/improvement-name

# 5. Create Pull Request
```

### **Development Guidelines**
- Follow PEP 8 Python style guide
- Use type hints for function parameters and returns
- Include docstrings for all modules, classes, and functions
- Write meaningful comments for complex logic
- Test on multiple platforms (Kali, Ubuntu, WSL)
- Verify backward compatibility
- Update documentation for new features

## 📄 **License**

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **Nmap Project** - For the incredible scanning capabilities
- **Samba Team** - For open-source SMB implementation
- **Security Community** - For continuous knowledge sharing
- **Open Source Contributors** - For inspiring collaboration

## 📞 **Support & Community**

- **GitHub Issues**: [Bug reports & feature requests](https://github.com/zeroaualy/zero-scanner/issues)
- **GitHub Discussions**: [Join the conversation](https://github.com/zeroaualy/zero-scanner/discussions)

## 🔗 **Related Projects**

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - Post-exploitation toolkit
- [Responder](https://github.com/lgandx/Responder) - LLMNR/NBT-NS/mDNS poisoner
- [Impacket](https://github.com/fortra/impacket) - Network protocol library
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory analysis

---

<div align="center">

### **"In security, zero is the goal"**

**Developed with ❤️ by .Zer0 | [https://github.com/zeroaualy](https://github.com/zeroaualy)**

![ZERO Scanner](https://img.shields.io/badge/ZERO-Scanner-blueviolet)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Follow](https://img.shields.io/github/followers/zeroaualy?style=social)

</div>
