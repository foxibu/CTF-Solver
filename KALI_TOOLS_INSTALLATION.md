# Kali Linux Tools Installation Guide

This document provides comprehensive installation instructions for all security tools required by the MCP Kali Server to support Pwnable, Reversing, Web, Cryptography, Forensics, Cloud Security, and Web3 CTF challenges.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Core Tools (Pre-installed on Kali)](#core-tools-pre-installed-on-kali)
- [Pwnable & Binary Exploitation Tools](#pwnable--binary-exploitation-tools)
- [Cryptography Tools](#cryptography-tools)
- [Forensics Tools](#forensics-tools)
- [Cloud Security Tools](#cloud-security-tools)
- [Web3 & Blockchain Tools](#web3--blockchain-tools)
- [Verification](#verification)

---

## Prerequisites

Ensure you're running a fresh Kali Linux installation:

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install basic build tools
sudo apt install -y build-essential git curl wget python3 python3-pip python3-venv
```

---

## Core Tools (Pre-installed on Kali)

These tools are typically pre-installed on Kali Linux. Verify their presence:

```bash
# Web security tools
which nmap gobuster dirb nikto sqlmap wpscan hydra john

# Pwnable tools
which gdb checksec objdump strings strace ltrace

# Forensics basics
which exiftool binwalk foremost file xxd
```

If any are missing, install them:

```bash
sudo apt install -y nmap gobuster dirb nikto sqlmap wpscan hydra john \
    gdb-multiarch binutils strace ltrace exiftool binwalk foremost
```

---

## Pwnable & Binary Exploitation Tools

### 1. Checksec

```bash
# Install checksec for binary protection analysis
sudo apt install -y checksec
```

### 2. ROPgadget

```bash
# Install ROPgadget for ROP chain building
sudo pip3 install ropgadget
```

### 3. Radare2

```bash
# Install radare2 for advanced binary analysis
sudo apt install -y radare2
```

### 4. pwntools

```bash
# Install pwntools for exploit development
sudo pip3 install pwntools
```

### 5. pwndbg (GDB plugin)

```bash
# Install pwndbg for enhanced GDB debugging
cd /opt
sudo git clone https://github.com/pwndbg/pwndbg
cd pwndbg
sudo ./setup.sh
```

### 6. one_gadget (Optional but recommended)

```bash
# Install one_gadget for finding one-shot RCE gadgets
sudo apt install -y ruby
sudo gem install one_gadget
```

---

## Cryptography Tools

### 1. Hashcat

```bash
# Install hashcat for GPU-accelerated password cracking
sudo apt install -y hashcat hashcat-data
```

### 2. John the Ripper (Enhanced)

```bash
# John is pre-installed, but install jumbo version for more features
sudo apt install -y john john-data
```

### 3. SageMath

```bash
# Install SageMath for advanced mathematical cryptanalysis
sudo apt install -y sagemath

# Verify installation
sage --version
```

**Note**: SageMath is a large package (~2GB). For minimal installations, consider using Docker:

```bash
docker pull sagemath/sagemath
```

### 4. RsaCtfTool

```bash
# Install RsaCtfTool for automated RSA attacks
cd /opt
sudo git clone https://github.com/Ganapati/RsaCtfTool.git
cd RsaCtfTool
sudo pip3 install -r requirements.txt

# Create symlink for easy access
sudo ln -s /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool
```

### 5. OpenSSL

```bash
# OpenSSL should be pre-installed, verify version
openssl version

# If not installed or outdated
sudo apt install -y openssl libssl-dev
```

### 6. FactorDB Python Client (Optional)

```bash
# Install factordb-pycli for programmatic FactorDB access
sudo pip3 install factordb-pycli
```

---

## Forensics Tools

### 1. Volatility 3

```bash
# Install Volatility 3 for memory forensics
sudo pip3 install volatility3

# Create alias for convenience
echo "alias vol='python3 -m volatility3'" >> ~/.bashrc
source ~/.bashrc

# Verify installation
vol --help
```

### 2. Binwalk (Enhanced)

```bash
# Binwalk is pre-installed, but add extraction dependencies
sudo apt install -y binwalk python3-binwalk mtd-utils gzip bzip2 tar \
    arj lhasa p7zip p7zip-full cabextract cramffs cramfsswap squashfs-tools \
    sleuthkit default-jdk lzop srecord
```

### 3. Steghide

```bash
# Install steghide for steganography
sudo apt install -y steghide
```

### 4. Foremost

```bash
# Install foremost for file carving
sudo apt install -y foremost
```

### 5. ExifTool

```bash
# Install exiftool for metadata extraction
sudo apt install -y libimage-exiftool-perl
```

### 6. Tesseract OCR

```bash
# Install tesseract for OCR
sudo apt install -y tesseract-ocr tesseract-ocr-eng

# Install additional language packs (optional)
sudo apt install -y tesseract-ocr-fra tesseract-ocr-deu tesseract-ocr-jpn tesseract-ocr-kor
```

### 7. Additional Forensics Tools

```bash
# Install other useful forensics tools
sudo apt install -y \
    autopsy \
    scalpel \
    bulk-extractor \
    dc3dd \
    guymager \
    photorec
```

### 8. Advanced Forensics Automation Tools

```bash
# Install SleuthKit for disk forensics
sudo apt install -y sleuthkit

# Verify installation
mmls -V
fls -V
```

```bash
# Install YARA for malware scanning
sudo apt install -y yara

# Install YARA rules repository
cd /opt
sudo git clone https://github.com/Yara-Rules/rules.git yara-rules
sudo ln -s /opt/yara-rules /usr/share/yara/rules

# Verify installation
yara --version
```

```bash
# Install md5deep/hashdeep for hash analysis
sudo apt install -y md5deep

# Verify installation
md5deep -v
hashdeep -V
```

```bash
# Install additional analysis tools
sudo apt install -y \
    strings \
    hexdump \
    xxd \
    file \
    clamav \
    clamav-daemon

# Update ClamAV virus database
sudo freshclam
```

**Note:** These tools enable the advanced forensics automation features:
- `auto_memory_analysis`: Automated Volatility workflows
- `auto_disk_analysis`: SleuthKit automation (timeline, deleted files)
- `auto_malware_hunt`: YARA + IOC extraction + entropy analysis

---

## Cloud Security Tools

### 1. AWS CLI

```bash
# Install AWS CLI v2
cd /tmp
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version

# Configure (if you have credentials)
# aws configure
```

### 2. S3 Scanner

```bash
# Install s3scanner for S3 bucket enumeration
sudo pip3 install s3scanner
```

### 3. Pacu

```bash
# Install Pacu AWS exploitation framework
cd /opt
sudo git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
sudo pip3 install -r requirements.txt

# Create wrapper script
sudo cat > /usr/local/bin/pacu << 'EOF'
#!/bin/bash
cd /opt/pacu
python3 pacu.py "$@"
EOF
sudo chmod +x /usr/local/bin/pacu
```

### 4. ScoutSuite (Optional)

```bash
# Install ScoutSuite for cloud security auditing
sudo pip3 install scoutsuite
```

### 5. Cloud Security Tools

```bash
# Install additional cloud tools
sudo pip3 install awscli-local localstack
```

---

## Web3 & Blockchain Tools

### 1. Solidity Compiler (solc)

```bash
# Install solc for compiling Solidity contracts
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:ethereum/ethereum
sudo apt update
sudo apt install -y solc

# Verify installation
solc --version
```

**Alternative (Using solc-select for multiple versions):**

```bash
sudo pip3 install solc-select
solc-select install 0.8.0
solc-select use 0.8.0
```

### 2. Slither

```bash
# Install Slither for static analysis
sudo pip3 install slither-analyzer

# Verify installation
slither --version
```

### 3. Mythril

```bash
# Install Mythril for symbolic execution
sudo pip3 install mythril

# Verify installation
myth version
```

### 4. Web3.py

```bash
# Install web3.py for blockchain interaction
sudo pip3 install web3
```

### 5. Ganache CLI (Optional for local testing)

```bash
# Install Node.js and npm first
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install ganache-cli
sudo npm install -g ganache-cli

# Verify installation
ganache-cli --version
```

### 6. Foundry (Optional - Advanced)

```bash
# Install Foundry toolkit (forge, cast, anvil, chisel)
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Verify installation
forge --version
```

### 7. Ethereum Development Tools

```bash
# Install additional Web3 tools
sudo pip3 install py-evm eth-brownie eth-ape
```

---

## Verification

After installation, verify all tools are accessible:

```bash
#!/bin/bash
echo "=== Verifying Tool Installation ==="

# Core tools
echo -e "\n[Core Tools]"
for tool in nmap gobuster dirb nikto sqlmap wpscan hydra john; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

# Pwnable tools
echo -e "\n[Pwnable Tools]"
for tool in checksec ROPgadget r2 python3; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

# Check pwntools
if python3 -c "import pwn" 2>/dev/null; then
    echo "✓ pwntools"
else
    echo "✗ pwntools (MISSING)"
fi

# Crypto tools
echo -e "\n[Cryptography Tools]"
for tool in hashcat sage openssl; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

if [ -f /opt/RsaCtfTool/RsaCtfTool.py ]; then
    echo "✓ RsaCtfTool"
else
    echo "✗ RsaCtfTool (MISSING)"
fi

# Forensics tools
echo -e "\n[Forensics Tools]"
for tool in binwalk steghide foremost exiftool tesseract vol; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

# Cloud tools
echo -e "\n[Cloud Security Tools]"
for tool in aws s3scanner pacu; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

# Web3 tools
echo -e "\n[Web3 Tools]"
for tool in solc slither myth; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool"
    else
        echo "✗ $tool (MISSING)"
    fi
done

# Check web3.py
if python3 -c "import web3" 2>/dev/null; then
    echo "✓ web3.py"
else
    echo "✗ web3.py (MISSING)"
fi

echo -e "\n=== Verification Complete ==="
```

Save this as `verify_tools.sh` and run:

```bash
chmod +x verify_tools.sh
./verify_tools.sh
```

---

## Automated Installation Script

For a complete automated installation, use this script:

```bash
#!/bin/bash
# Complete MCP Kali Server Tool Installation

set -e

echo "=== MCP Kali Server Tool Installation ==="
echo "This will install all required security tools..."
echo ""

# Update system
echo "[1/7] Updating system..."
sudo apt update && sudo apt upgrade -y

# Install core packages
echo "[2/7] Installing core tools..."
sudo apt install -y build-essential git curl wget python3 python3-pip python3-venv \
    nmap gobuster dirb nikto sqlmap wpscan hydra john \
    gdb-multiarch binutils strace ltrace checksec \
    exiftool binwalk foremost steghide tesseract-ocr

# Install pwnable tools
echo "[3/7] Installing pwnable tools..."
sudo pip3 install ropgadget pwntools
sudo apt install -y radare2

# Install crypto tools
echo "[4/7] Installing cryptography tools..."
sudo apt install -y hashcat sagemath openssl
cd /opt
sudo git clone https://github.com/Ganapati/RsaCtfTool.git 2>/dev/null || echo "RsaCtfTool already exists"
cd RsaCtfTool
sudo pip3 install -r requirements.txt

# Install forensics tools
echo "[5/7] Installing forensics tools..."
sudo pip3 install volatility3

# Install cloud tools
echo "[6/7] Installing cloud security tools..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
cd /tmp && unzip -o awscliv2.zip && sudo ./aws/install
sudo pip3 install s3scanner
cd /opt
sudo git clone https://github.com/RhinoSecurityLabs/pacu.git 2>/dev/null || echo "Pacu already exists"
cd pacu
sudo pip3 install -r requirements.txt

# Install web3 tools
echo "[7/7] Installing Web3 tools..."
sudo pip3 install slither-analyzer mythril web3 solc-select
solc-select install 0.8.0
solc-select use 0.8.0

echo ""
echo "=== Installation Complete ==="
echo "Please run ./verify_tools.sh to verify all tools are installed correctly"
```

Save as `install_all_tools.sh` and run:

```bash
chmod +x install_all_tools.sh
sudo ./install_all_tools.sh
```

---

## Troubleshooting

### Common Issues

**1. Python package conflicts:**
```bash
# Use virtual environment
python3 -m venv ~/ctf-env
source ~/ctf-env/bin/activate
pip install <package>
```

**2. Permission errors:**
```bash
# Add your user to necessary groups
sudo usermod -aG sudo $USER
sudo usermod -aG wireshark $USER
```

**3. Missing dependencies:**
```bash
# Install missing build dependencies
sudo apt install -y pkg-config libssl-dev libffi-dev
```

---

## Additional Resources

- **Wordlists Location**: `/usr/share/wordlists/`
- **SecLists**: `sudo apt install seclists`
- **Payloads**: `/usr/share/payloadsallthethings` (install separately)

---

## Maintenance

Keep tools updated:

```bash
# Update apt packages
sudo apt update && sudo apt upgrade -y

# Update Python packages
sudo pip3 install --upgrade pwntools ropgadget slither-analyzer mythril web3 volatility3

# Update git repositories
cd /opt/RsaCtfTool && sudo git pull
cd /opt/pacu && sudo git pull
```

---

## Docker Alternative

For a containerized approach, consider using Docker:

```bash
# Pull pre-configured Kali image
docker pull kalilinux/kali-rolling

# Run with all tools
docker run -it kalilinux/kali-rolling bash
```

---

## Notes

- Some tools require significant disk space (especially SageMath ~2GB)
- GPU-based tools (hashcat) work best with proper GPU drivers
- Cloud tools require proper credentials configuration
- Web3 tools may need access to blockchain nodes

For detailed usage of each tool, refer to the main [CLAUDE.md](CLAUDE.md) documentation.
