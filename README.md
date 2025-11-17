# 🛡️ MCP Kali Server

<div align="center">

**AI-Powered Offensive Security Toolkit**

Bridge your AI assistant to 50+ Kali Linux security tools via Model Context Protocol

[![smithery badge](https://smithery.ai/badge/@atimevil/mcp-kali-server)](https://smithery.ai/server/@atimevil/mcp-kali-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Security Tools](https://img.shields.io/badge/Security_Tools-50+-green.svg)](KALI_TOOLS_INSTALLATION.md)
[![CTF Categories](https://img.shields.io/badge/CTF_Categories-7-orange.svg)](#-ctf-categories-supported)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Architecture](#-architecture) • [Legal](#%EF%B8%8F-legal-notice)

</div>

---

## 📖 Overview

**MCP Kali Server** transforms your AI assistant into a powerful offensive security companion by providing seamless access to professional penetration testing and CTF-solving tools from Kali Linux.

Built on the **Model Context Protocol (MCP)**, this server enables AI assistants like Claude, ChatGPT, and others to orchestrate complex security workflows, automate CTF challenge solving, and perform intelligent penetration testing through natural language.

### 🎯 What Can It Do?

```
You: "I found an RSA challenge with n=12345..., e=65537. Can you decrypt it?"

AI: *Automatically queries FactorDB → runs RsaCtfTool → decrypts ciphertext → extracts flag*
    "Flag found: CTF{...}"
```

```
You: "Scan this web app for vulnerabilities: http://target.com"

AI: *Runs nmap → gobuster → nikto → sqlmap → provides comprehensive security report*
```

---

## ✨ Features

### 🎓 **7 Major CTF Categories Supported**

<table>
<tr>
<td width="50%">

**🔓 Pwnable** (80% coverage)
- Buffer overflow exploitation
- ROP chain building
- Format string attacks
- Heap exploitation
- Tools: `checksec`, `ROPgadget`, `pwntools`, `radare2`

**🔐 Cryptography** (50-80% coverage)
- RSA attacks (factorization, Wiener, Hastad)
- Hash cracking (MD5, SHA, bcrypt)
- Mathematical cryptanalysis
- Tools: `hashcat`, `RsaCtfTool`, `SageMath`, `john`

**🔍 Forensics** (43-70% coverage)
- Memory dump analysis
- Steganography detection
- File carving & recovery
- Tools: `Volatility3`, `binwalk`, `steghide`, `foremost`

**🌐 Web Security** (90% coverage)
- SQL injection testing
- Directory enumeration
- Vulnerability scanning
- Tools: `sqlmap`, `gobuster`, `nikto`, `wpscan`

</td>
<td width="50%">

**☁️ Cloud Security** (52-85% coverage)
- AWS/GCP/Azure enumeration
- S3 bucket scanning
- IAM privilege escalation
- Tools: `aws-cli`, `pacu`, `s3scanner`

**⛓️ Web3 & Blockchain** (40-75% coverage)
- Smart contract analysis
- Reentrancy attacks
- Integer overflow detection
- Tools: `Slither`, `Mythril`, `web3.py`, `solc`

**🔄 Reversing** (67% coverage)
- Binary disassembly
- Dynamic analysis
- Deobfuscation
- Tools: `radare2`, `ltrace`, `strace`, `objdump`

</td>
</tr>
</table>

### 🛠️ **50+ Professional Security Tools**

- **Network Recon**: nmap, masscan, enum4linux
- **Web Testing**: gobuster, dirb, nikto, sqlmap, wpscan, ffuf
- **Password Attacks**: hydra, john, hashcat
- **Binary Analysis**: checksec, ROPgadget, radare2, pwntools, Ghidra
- **Forensics**: Volatility3, binwalk, foremost, steghide, exiftool, tesseract
- **Cryptography**: RsaCtfTool, SageMath, hashcat, openssl
- **Cloud**: AWS CLI, Pacu, s3scanner, ScoutSuite
- **Web3**: Slither, Mythril, web3.py, solc, Ganache
- **Exploitation**: metasploit, searchsploit
- **And many more...**

### 🤖 **AI-Powered Automation**

- **Automatic Vulnerability Detection**: AI analyzes binaries and identifies exploitable weaknesses
- **Multi-Step Attack Chains**: Orchestrate complex exploitation workflows
- **Session Management**: Persistent workspaces for multi-step analysis
- **Interactive Shells**: Bidirectional communication with running exploits
- **Intelligent Tool Selection**: AI chooses appropriate tools based on context

### 📚 **Comprehensive Guidance**

- **Workflow Prompts**: Pre-built templates for common CTF scenarios
- **Problem-Solving Guide**: Ready-to-use prompts for each category
- **Tool Installation**: Automated setup scripts for Kali Linux
- **Best Practices**: Security testing guidelines and ethics

---

## 🚀 Quick Start

### Prerequisites

- **Kali Linux** (or any Linux with security tools installed)
- **Python 3.12+**
- **AI Assistant** with MCP support (Claude Desktop, 5ire, etc.)

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
```

**2. Install dependencies**
```bash
pip install -e .
# OR use uv for faster installation
uv pip install -e .
```

**3. Install security tools** (see [KALI_TOOLS_INSTALLATION.md](KALI_TOOLS_INSTALLATION.md))
```bash
# Quick install essential tools
sudo apt install -y nmap gobuster dirb nikto sqlmap wpscan hydra john \
    checksec binwalk steghide volatility3 radare2

# See installation guide for complete setup
```

**4. Start the Kali server**
```bash
python3 kali_server.py
# Server runs on http://0.0.0.0:5000
```

**5. Configure your MCP client**

**For Claude Desktop** (edit `~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "kali_mcp": {
      "command": "python3",
      "args": [
        "/absolute/path/to/src/my_server/mcp_server.py",
        "--server",
        "http://KALI_IP:5000/"
      ]
    }
  }
}
```

**For 5ire Desktop**:
- Add MCP server with command: `python3 /path/to/src/my_server/mcp_server.py --server http://KALI_IP:5000`

**6. Start solving CTFs!** 🎉

---

## 🏗️ Architecture

```
┌─────────────────────┐         HTTP/JSON        ┌─────────────────────┐
│  MCP Client         │◄──────────────────────────│  Kali Linux Server  │
│  (Claude Desktop,   │        Port 5000          │  (Flask API)        │
│   5ire, etc.)       │                           │                     │
│                     │                           │  - Command Executor │
│  - FastMCP Server   │                           │  - Tool Endpoints   │
│  - Tool Definitions │                           │  - Session Manager  │
│  - Workflow Prompts │                           │  - Timeout Handler  │
└─────────────────────┘                           └─────────────────────┘
     Windows/Mac/Linux                                Kali Linux
```

### Components

**Kali Server** (`kali_server.py`)
- Flask HTTP API server (port 5000)
- 70+ security tool endpoints
- Session-based workspaces
- Interactive shell management
- Graceful timeout handling (180s default)

**MCP Client** (`src/my_server/mcp_server.py`)
- FastMCP protocol implementation
- 50+ MCP tool wrappers
- AI-guided workflow prompts
- Resources (server status, wordlists, guides)

---

## 💡 Usage Examples

### Example 1: RSA Cryptography Challenge

```
User: "I have an RSA challenge:
       n = 85188995949975973...
       e = 65537
       c = 34577152691579622...
       Can you decrypt it?"

AI Assistant:
1. Creates analysis session
2. Queries FactorDB for factorization of n
3. Runs RsaCtfTool with multiple attack methods
4. Successfully decrypts using Wiener's attack
5. Returns: "Plaintext: CTF{weak_rsa_exponent}"
```

### Example 2: Web Application Testing

```
User: "Test http://target.com for vulnerabilities"

AI Assistant:
1. Runs nmap port scan
2. Discovers web server on ports 80, 443
3. Runs gobuster for directory enumeration
4. Finds /admin, /backup, /api endpoints
5. Runs nikto for vulnerability scanning
6. Tests SQLi with sqlmap on login form
7. Provides comprehensive security report
```

### Example 3: Binary Exploitation (Pwnable)

```
User: "Analyze this binary: challenge.bin"

AI Assistant:
1. Uploads binary to session workspace
2. Runs checksec (finds: No canary, NX enabled, No PIE)
3. Auto-detects buffer overflow vulnerability
4. Finds ROP gadgets for NX bypass
5. Locates system() and "/bin/sh"
6. Generates pwntools exploit script
7. Tests locally and captures flag
```

### Example 4: Memory Forensics

```
User: "Analyze this memory dump: memory.dmp (Windows)"

AI Assistant:
1. Runs Volatility3 windows.info
2. Lists running processes (windows.pslist)
3. Identifies suspicious process: malware.exe
4. Dumps process memory
5. Scans for network connections
6. Extracts command line arguments
7. Finds hidden flag in process memory
```

---

## 📚 Documentation

- **[PROBLEM_SOLVING_PROMPTS.md](PROBLEM_SOLVING_PROMPTS.md)** - Ready-to-use AI prompts for each CTF category
- **[KALI_TOOLS_INSTALLATION.md](KALI_TOOLS_INSTALLATION.md)** - Complete tool installation guide with automated scripts
- **[CTF_ENHANCEMENT.md](CTF_ENHANCEMENT.md)** - Advanced features and capability analysis
- **[CLAUDE.md](CLAUDE.md)** - Comprehensive guide for AI assistants working with this codebase

---

## 🎮 Supported CTF Platforms

This tool works with **all major CTF platforms**:

- **HackTheBox** (HTB)
- **TryHackMe** (THM)
- **PicoCTF**
- **CTFtime** competitions
- **OverTheWire**
- **pwnable.kr** / **pwnable.tw**
- **Root-Me**
- **RingZer0 CTF**
- **VulnHub**
- And many more!

---

## 🎯 Use Cases

### ✅ **Authorized & Legal**

- CTF competitions and wargames
- Authorized penetration testing (with written permission)
- Bug bounty programs (within scope)
- Security research and education
- Personal lab environments
- Capture The Flag training

### ❌ **Prohibited**

- Unauthorized access to systems
- Malicious hacking or attacks
- Testing without explicit permission
- Any illegal activities

---

## 🔧 Configuration

### Environment Variables

```bash
export KALI_SERVER_URL="http://localhost:5000"
export KALI_REQUEST_TIMEOUT=300  # 5 minutes
export DEBUG_MODE=1  # Enable debug logging
```

### Custom Port

```bash
# Kali server on custom port
python3 kali_server.py --port 8080

# MCP client with custom server
python3 src/my_server/mcp_server.py --server http://localhost:8080
```

### Remote Access (SSH Tunnel)

```bash
# On client machine
ssh -L 5000:localhost:5000 user@kali-server.example.com

# Configure MCP client to use localhost:5000
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone repository
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server

# Install in development mode
pip install -e .

# Run tests
python3 kali_server.py --debug
```

---

## 📰 Media & Articles

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

📝 **[How MCP is Revolutionizing Offensive Security](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)** - Medium Article by Author

---

## ⚠️ Legal Notice

### FOR AUTHORIZED SECURITY TESTING ONLY

This tool is designed exclusively for:

✅ **Authorized penetration testing** with written permission
✅ **CTF competitions** and educational wargames
✅ **Security research** in controlled environments
✅ **Bug bounty programs** within defined scope
✅ **Personal lab environments** you own

❌ **Unauthorized access** to systems
❌ **Malicious hacking** or attacks
❌ **Testing without explicit permission**
❌ **Any illegal activities**

**By using this tool, you agree to:**
- Obtain proper authorization before testing any systems
- Comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Accept full responsibility for your actions

**The authors assume NO responsibility for misuse.** Unauthorized access to computer systems is illegal and punishable by law.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **Author**: [Yousof Nahya](https://github.com/Wh0am123)
- **Inspired by**: [Project Astro](https://github.com/whit3rabbit0/project_astro)
- **Built with**: [FastMCP](https://github.com/jlowin/fastmcp), Flask, and the offensive security community
- **Powered by**: Kali Linux, Model Context Protocol

---

## 🔗 Links

- **GitHub Repository**: [github.com/Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server)
- **Model Context Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Kali Linux**: [kali.org](https://www.kali.org/)
- **FastMCP**: [github.com/jlowin/fastmcp](https://github.com/jlowin/fastmcp)

---

## 📊 Statistics

- **50+ Security Tools** integrated
- **7 CTF Categories** supported
- **70+ API Endpoints** available
- **4 Workflow Prompts** included
- **100+ Pages** of documentation

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ by the offensive security community

</div>