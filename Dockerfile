# CTF Solver - AI-Powered Offensive Security Toolkit
# Based on Kali Linux with 55+ security tools

FROM kalilinux/kali-rolling:latest

LABEL maintainer="foxibu"
LABEL description="AI-Powered CTF Solver with 55+ Kali Linux security tools"
LABEL version="1.0.0"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Update system and install base packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Core security tools
    nmap \
    gobuster \
    dirb \
    nikto \
    sqlmap \
    wpscan \
    hydra \
    john \
    masscan \
    enum4linux \
    # Web testing tools
    ffuf \
    # Binary analysis tools
    gdb-multiarch \
    binutils \
    strace \
    ltrace \
    checksec \
    radare2 \
    # Forensics tools
    exiftool \
    binwalk \
    foremost \
    steghide \
    tesseract-ocr \
    tesseract-ocr-eng \
    sleuthkit \
    yara \
    md5deep \
    strings \
    hexdump \
    xxd \
    file \
    clamav \
    clamav-daemon \
    # Forensics dependencies
    mtd-utils \
    gzip \
    bzip2 \
    tar \
    arj \
    lhasa \
    p7zip \
    p7zip-full \
    cabextract \
    squashfs-tools \
    lzop \
    # Cryptography tools
    hashcat \
    hashcat-data \
    openssl \
    libssl-dev \
    # Additional utilities
    software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip3 install --no-cache-dir \
    # Flask for API server
    flask==3.0.0 \
    requests==2.31.0 \
    # Pwnable tools
    ropgadget \
    pwntools \
    # Forensics tools
    volatility3 \
    # Crypto tools
    factordb-pycli \
    # Cloud tools
    s3scanner \
    scoutsuite \
    # Web3 tools
    slither-analyzer \
    mythril \
    web3 \
    solc-select \
    py-evm \
    # Additional tools
    && pip3 cache purge

# Install AWS CLI v2
RUN cd /tmp && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

# Install RsaCtfTool
RUN cd /opt && \
    git clone --depth 1 https://github.com/Ganapati/RsaCtfTool.git && \
    cd RsaCtfTool && \
    pip3 install --no-cache-dir -r requirements.txt && \
    ln -s /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool && \
    pip3 cache purge

# Install Pacu AWS exploitation framework
RUN cd /opt && \
    git clone --depth 1 https://github.com/RhinoSecurityLabs/pacu.git && \
    cd pacu && \
    pip3 install --no-cache-dir -r requirements.txt && \
    pip3 cache purge

# Install YARA rules
RUN cd /opt && \
    git clone --depth 1 https://github.com/Yara-Rules/rules.git yara-rules && \
    mkdir -p /usr/share/yara && \
    ln -s /opt/yara-rules /usr/share/yara/rules

# Install pwndbg (GDB plugin)
RUN cd /opt && \
    git clone --depth 1 https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

# Update ClamAV virus database (in background to avoid blocking)
RUN freshclam || true

# Set up Solidity compiler
RUN solc-select install 0.8.0 && \
    solc-select use 0.8.0

# Copy application code
COPY kali_server.py /app/
COPY src/ /app/src/
COPY pyproject.toml /app/
COPY README.md /app/
COPY KALI_TOOLS_INSTALLATION.md /app/
COPY PROBLEM_SOLVING_PROMPTS.md /app/

# Create directories for sessions and workspaces
RUN mkdir -p /app/sessions /app/workspaces

# Expose Flask API port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the Kali server
CMD ["python3", "kali_server.py"]
