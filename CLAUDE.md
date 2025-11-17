# CLAUDE.md - AI Assistant Guide for MCP Kali Server

## Project Overview

**MCP Kali Server** is a Model Context Protocol (MCP) server designed for AI-assisted offensive security testing. It provides a secure bridge between AI assistants (like Claude Desktop or 5ire) and a Kali Linux terminal, enabling automated penetration testing, CTF challenge solving, and security research.

### Purpose
- Enable AI-driven offensive security testing and CTF challenge solving
- Provide controlled access to Kali Linux security tools via MCP protocol
- Support ethical hacking workflows including reconnaissance, vulnerability assessment, and exploitation
- Facilitate educational security research and authorized penetration testing

### Key Features
- **Dual-component architecture**: Separate Kali server and MCP client
- **13+ security tools exposed**: nmap, gobuster, dirb, nikto, sqlmap, metasploit, hydra, john, wpscan, enum4linux, and more
- **Generic command execution**: Fallback for any terminal command
- **Comprehensive timeout handling**: 5-minute default timeout with graceful partial results
- **FastMCP implementation**: Modern MCP protocol with resources, prompts, and tools

---

## Architecture

### System Components

```
┌─────────────────────┐         HTTP/JSON        ┌─────────────────────┐
│  MCP Client         │◄──────────────────────────│  Kali Linux Server  │
│  (Claude Desktop,   │        Port 5000          │  (Flask API)        │
│   5ire, etc.)       │                           │                     │
│                     │                           │  - Command Executor │
│  - FastMCP Server   │                           │  - Tool Endpoints   │
│  - Tool Definitions │                           │  - Timeout Manager  │
│  - Client Library   │                           │  - Health Checks    │
└─────────────────────┘                           └─────────────────────┘
     Windows/Linux                                    Kali Linux
```

### Component Responsibilities

**1. Kali Server (`kali_server.py`)**
- Runs on Kali Linux or any Linux system with security tools installed
- Flask HTTP API server listening on port 5000
- Executes shell commands with timeout handling (180s default)
- Provides tool-specific endpoints for common security tools
- Health check endpoint to verify tool availability
- Thread-based output handling for long-running commands

**2. MCP Client (`src/my_server/mcp_server.py`)**
- Runs on the same or different machine as the MCP client application
- Implements FastMCP protocol for AI assistant integration
- Wraps Kali server HTTP API calls into MCP tool definitions
- Provides resources (server status, wordlists, guides)
- Offers prompt templates for common security workflows
- Handles request/response transformation between MCP and HTTP

---

## Codebase Structure

```
MCP-Kali-Server/
├── kali_server.py              # Flask API server (runs on Kali Linux)
│   ├── CommandExecutor         # Thread-based command execution with timeout
│   ├── execute_command()       # Generic command wrapper
│   └── API Endpoints:
│       ├── /api/command        # Generic command execution
│       ├── /api/tools/nmap     # Network scanning
│       ├── /api/tools/gobuster # Directory enumeration
│       ├── /api/tools/dirb     # Directory bruteforcing
│       ├── /api/tools/nikto    # Web vulnerability scanning
│       ├── /api/tools/sqlmap   # SQL injection testing
│       ├── /api/tools/metasploit # Exploitation framework
│       ├── /api/tools/hydra    # Password cracking
│       ├── /api/tools/john     # Hash cracking
│       ├── /api/tools/wpscan   # WordPress scanning
│       ├── /api/tools/enum4linux # SMB enumeration
│       └── /health             # Server health check
│
├── src/my_server/
│   ├── __init__.py             # Package initialization
│   └── mcp_server.py           # MCP client implementation
│       ├── KaliToolsClient     # HTTP client for Kali API
│       ├── setup_mcp_server()  # MCP server configuration
│       ├── create_server()     # Factory for Smithery deployment
│       ├── Tool Definitions    # 13+ security tool wrappers
│       ├── Resources           # Server status, wordlists, guides
│       └── Prompts             # Workflow templates
│
├── pyproject.toml              # Project metadata and dependencies
├── smithery.yaml               # Smithery deployment config
├── README.md                   # User-facing documentation
└── LICENSE                     # MIT License

Dependencies:
- mcp>=1.13.0                   # Model Context Protocol library
- smithery>=0.1.23              # Smithery deployment tools
- requests                       # HTTP client for API calls
- flask (kali_server.py)        # Web framework for API server
```

### File-Level Details

**`kali_server.py` (570 lines)**
- Lines 35-127: `CommandExecutor` class with thread-based timeout handling
- Lines 129-141: `execute_command()` wrapper function
- Lines 143-515: API endpoint implementations for each tool
- Lines 519-540: Health check endpoint with tool availability verification
- Lines 552-572: Main entry point and argument parsing

**`src/my_server/mcp_server.py` (747 lines)**
- Lines 30-117: `KaliToolsClient` HTTP client class
- Lines 119-666: `setup_mcp_server()` with all MCP tool definitions
- Lines 131-451: 13 tool definitions with comprehensive annotations
- Lines 454-567: 3 resource definitions (status, wordlists, guides)
- Lines 570-664: 3 prompt templates (recon, web testing, password attacks)
- Lines 668-703: `create_server()` factory for Smithery deployment
- Lines 714-743: Main entry point for standalone execution

---

## Development Workflow

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server

# Install dependencies (Python 3.12+ required)
pip install -e .

# Or use uv for faster installation
uv pip install -e .
```

### Running the System Locally

**1. Start Kali Server (on Kali Linux or any Linux system)**
```bash
python3 kali_server.py
# Server runs on http://0.0.0.0:5000

# With debug mode
python3 kali_server.py --debug

# Custom port
python3 kali_server.py --port 8080
```

**2. Run MCP Client (standalone mode)**
```bash
python3 src/my_server/mcp_server.py --server http://LINUX_IP:5000

# With debug logging
python3 src/my_server/mcp_server.py --server http://LINUX_IP:5000 --debug

# Custom timeout
python3 src/my_server/mcp_server.py --server http://LINUX_IP:5000 --timeout 600
```

**3. Configure with Claude Desktop**
Edit `~/.config/Claude/claude_desktop_config.json` (Linux) or `C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "kali_mcp": {
      "command": "python3",
      "args": [
        "/absolute/path/to/src/my_server/mcp_server.py",
        "--server",
        "http://LINUX_IP:5000/"
      ]
    }
  }
}
```

### Testing Changes

**Unit Testing Approach**
```bash
# Test Kali server health
curl http://localhost:5000/health

# Test command execution
curl -X POST http://localhost:5000/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# Test nmap tool
curl -X POST http://localhost:5000/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "scan_type": "-sV", "ports": "80,443"}'
```

**Integration Testing**
1. Start kali_server.py on Kali machine
2. Run mcp_server.py in standalone mode with --debug
3. Verify connection and tool execution in logs
4. Test with actual MCP client (Claude Desktop)

### Common Development Tasks

#### Adding a New Security Tool

1. **Add Kali Server Endpoint** (`kali_server.py`)
```python
@app.route("/api/tools/newtool", methods=["POST"])
def newtool():
    """Execute newtool with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")

        if not target:
            logger.warning("NewTool called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"newtool {target}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in newtool endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```

2. **Add MCP Tool Definition** (`src/my_server/mcp_server.py`)
```python
@mcp.tool(annotations={
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True
})
def newtool_scan(
    target: str,
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    Execute NewTool security scanner for [specific purpose].

    Args:
        target: Target IP address or hostname to scan (e.g., '192.168.1.1')
        additional_args: Additional arguments like '--verbose' or '--fast' (default: '')

    Returns:
        Scan results including [specific output description]
    """
    data = {
        "target": target,
        "additional_args": additional_args
    }
    return kali_client.safe_post("api/tools/newtool", data)
```

3. **Update Health Check** (optional, for essential tools)
```python
essential_tools = ["nmap", "gobuster", "dirb", "nikto", "newtool"]
```

#### Modifying Tool Parameters

**Example: Adding port parameter to nikto**

In `kali_server.py`:
```python
def nikto():
    params = request.json
    target = params.get("target", "")
    port = params.get("port", "80")  # NEW
    additional_args = params.get("additional_args", "")

    command = f"nikto -h {target} -port {port}"  # MODIFIED
```

In `src/my_server/mcp_server.py`:
```python
def nikto_scan(
    target: str,
    port: int = 80,  # NEW
    additional_args: str = ""
) -> Dict[str, Any]:
    """
    Args:
        target: Target URL or IP address
        port: Target port (default: 80)  # NEW
        additional_args: Additional arguments
    """
    data = {
        "target": target,
        "port": port,  # NEW
        "additional_args": additional_args
    }
```

#### Improving Timeout Handling

The `CommandExecutor` class handles timeouts gracefully. To modify timeout behavior:

```python
# In kali_server.py
COMMAND_TIMEOUT = 300  # Change global default (currently 180)

# Or per-tool basis
executor = CommandExecutor(command, timeout=600)  # 10 minutes for specific tool
```

---

## Key Conventions

### Code Style

**Python Style**
- Follow PEP 8 conventions
- Use type hints for function parameters and return types
- Comprehensive docstrings with Args and Returns sections
- Clear logging at INFO level for operations, DEBUG for detailed tracing

**MCP Tool Annotations**
- `readOnlyHint: True` - Tool doesn't modify system state (reconnaissance)
- `readOnlyHint: False` - Tool may modify state (exploitation)
- `destructiveHint: True` - Tool can compromise systems (use with caution)
- `destructiveHint: False` - Tool is safe for information gathering
- `idempotentHint: True` - Same input produces same output
- `idempotentHint: False` - Output may vary (time-based, randomized)

**Example Classification**
- `nmap_scan`: readOnly=True, destructive=False, idempotent=True (safe scanning)
- `sqlmap_scan`: readOnly=False, destructive=True, idempotent=False (can modify DB)
- `execute_command`: readOnly=False, destructive=True, idempotent=False (unrestricted)

### Error Handling

**Kali Server Pattern**
```python
try:
    # Validate inputs
    if not required_param:
        logger.warning("Tool called without required parameter")
        return jsonify({"error": "Descriptive error message"}), 400

    # Execute command
    result = execute_command(command)
    return jsonify(result)
except Exception as e:
    logger.error(f"Error in tool endpoint: {str(e)}")
    logger.error(traceback.format_exc())
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

**MCP Client Pattern**
```python
try:
    response = requests.post(url, json=json_data, timeout=self.timeout)
    response.raise_for_status()
    return response.json()
except requests.exceptions.RequestException as e:
    logger.error(f"Request failed: {str(e)}")
    return {"error": f"Request failed: {str(e)}", "success": False}
```

### Security Considerations

**Input Validation**
- Always validate required parameters before execution
- Sanitize file paths to prevent directory traversal
- Validate enum-like parameters (e.g., gobuster mode must be dir/dns/fuzz/vhost)
- Log all command executions for audit trail

**Command Injection Prevention**
- Current implementation uses shell=True for flexibility but is vulnerable
- When possible, use shlex.split() or parameterized execution
- Avoid user-controlled command construction without validation
- Consider allowlist approach for additional_args parameters

**Authentication & Authorization**
- Currently NO authentication on Kali server (designed for trusted networks)
- Deploy Kali server on localhost or trusted private network only
- Consider adding API key authentication for production use
- MCP client connects via HTTP (no encryption) - use SSH tunnels for remote access

### Logging Standards

**Kali Server Logging**
```python
logger.info(f"Executing command: {command}")  # Command start
logger.warning(f"Command timed out after {timeout} seconds")  # Timeout events
logger.error(f"Error executing command: {str(e)}")  # Errors
```

**MCP Client Logging**
```python
logger.info(f"Initialized Kali Tools Client connecting to {server_url}")  # Startup
logger.debug(f"POST {url} with data: {json_data}")  # Request details (debug only)
logger.warning(f"Unable to connect to Kali API server")  # Connection issues
```

---

## MCP Tools Reference

### Tool Categories

**Network Reconnaissance**
- `nmap_scan` - Port scanning, service detection, version enumeration
- `enum4linux_scan` - Windows/Samba enumeration (users, shares, groups)

**Web Application Testing**
- `gobuster_scan` - Directory/DNS/vhost enumeration
- `dirb_scan` - Directory bruteforcing
- `nikto_scan` - Web server vulnerability scanning
- `wpscan_analyze` - WordPress security scanning
- `sqlmap_scan` - SQL injection detection and exploitation

**Exploitation**
- `metasploit_run` - Exploit module execution
- `hydra_attack` - Online password cracking
- `john_crack` - Offline hash cracking

**System Utilities**
- `execute_command` - Generic command execution (fallback)
- `server_health` - Check Kali server and tool availability

### Tool Usage Examples

**Network Reconnaissance Workflow**
```python
# Step 1: Check server health
server_health()

# Step 2: Initial port scan
nmap_scan(target="192.168.1.10", scan_type="-sV", ports="")

# Step 3: Deep scan on discovered ports
nmap_scan(target="192.168.1.10", scan_type="-sC", ports="22,80,443,445")

# Step 4: SMB enumeration if port 445 open
enum4linux_scan(target="192.168.1.10", additional_args="-a")
```

**Web Application Testing Workflow**
```python
# Step 1: Fingerprint web server
nikto_scan(target="http://192.168.1.10")

# Step 2: Directory enumeration
gobuster_scan(
    url="http://192.168.1.10",
    mode="dir",
    wordlist="/usr/share/wordlists/dirb/common.txt",
    additional_args="-x php,html,txt"
)

# Step 3: WordPress scan if detected
wpscan_analyze(
    url="http://192.168.1.10",
    additional_args="--enumerate u,p,t"
)

# Step 4: SQL injection testing on forms
sqlmap_scan(
    url="http://192.168.1.10/login.php",
    data="username=admin&password=test",
    additional_args="--batch --dbs"
)
```

**Password Attack Workflow**
```python
# Offline hash cracking
john_crack(
    hash_file="/tmp/hashes.txt",
    wordlist="/usr/share/wordlists/rockyou.txt",
    format_type="raw-md5"
)

# Online password attack (use with extreme caution)
hydra_attack(
    target="192.168.1.10",
    service="ssh",
    username="admin",
    password_file="/usr/share/wordlists/fasttrack.txt",
    additional_args="-t 4 -V"
)
```

### Resources Available

**`kali://server/status`**
- Get current Kali server health and tool availability
- Returns formatted status with emoji indicators

**`kali://wordlists/common`**
- List of common wordlists available on Kali Linux
- Includes paths for passwords, directories, usernames, DNS

**`kali://guides/safe-testing`**
- Comprehensive security testing safety guidelines
- Legal requirements, best practices, red flags, emergency procedures

### Prompt Templates

**`network_reconnaissance(target)`**
- 4-phase network recon workflow
- Initial discovery → Service enumeration → Directory enum → Vulnerability assessment

**`web_application_testing(url)`**
- 4-phase web app testing workflow
- Fingerprinting → Content discovery → CMS detection → Injection testing

**`password_attack_workflow(target, service)`**
- 3-phase password attack workflow
- Prerequisites check → Username enum → Hash/online cracking

---

## Security & Ethics Guidelines for AI Assistants

### Critical Rules - ALWAYS Follow

1. **Authorization Required**
   - NEVER execute offensive security tools without explicit written authorization
   - Verify scope, targets, and testing timeframe before any active testing
   - Remind users about legal requirements if unclear

2. **Destructive Tool Warning**
   - Tools marked `destructiveHint: True` can compromise systems
   - Always warn users before executing: sqlmap, metasploit, hydra
   - Confirm intent and authorization explicitly

3. **Scope Validation**
   - Verify target IP/domain is within authorized scope
   - Check for private IP ranges (10.x, 172.16-31.x, 192.168.x) - often unauthorized
   - Question testing against public IPs without proof of authorization

4. **Rate Limiting & Stability**
   - Start with least invasive scans (nmap -sV before -sS)
   - Use limited wordlists initially (common.txt before big.txt)
   - Monitor for system instability (timeouts, errors)
   - Avoid account lockout scenarios (hydra with large wordlists)

5. **Data Handling**
   - Never exfiltrate or share sensitive data discovered during testing
   - Immediately report critical vulnerabilities to system owner
   - Maintain confidentiality of findings

### Recommended Workflow for AI Assistants

**Phase 1: Verification (REQUIRED)**
```
User: "Scan 192.168.1.10 for vulnerabilities"

AI Response:
"Before proceeding with security testing, I need to verify:
1. Do you have written authorization to test 192.168.1.10?
2. What is the authorized scope (full network, specific ports)?
3. Are there any restricted systems or testing limitations?

Security testing without authorization is illegal. Please confirm authorization before proceeding."
```

**Phase 2: Reconnaissance (Safe)**
```
AI: "I'll start with passive reconnaissance using read-only tools:
1. Running server_health() to verify tools are available
2. Running nmap_scan(target='192.168.1.10', scan_type='-sV') for service detection
3. This is safe and non-invasive"
```

**Phase 3: Active Testing (Warn)**
```
AI: "Based on findings, I recommend:
1. gobuster_scan() for directory enumeration (moderate impact)
2. nikto_scan() for vulnerability scanning (moderate impact)
3. sqlmap_scan() for SQL injection testing (HIGH IMPACT - can modify database)

Proceeding with 1 and 2. For #3, please explicitly confirm authorization to test for SQL injection, as this can modify database contents."
```

**Phase 4: Exploitation (Explicit Confirmation)**
```
AI: "I found potential SQL injection. Before exploiting:
⚠️ WARNING: sqlmap can modify database contents and may cause data loss
⚠️ WARNING: This action is destructive and irreversible

Please type 'I authorize exploitation' to proceed with sqlmap testing."
```

### Red Flags - Stop and Clarify

**Suspicious Requests**
- Testing public IPs without clear authorization context
- Requests to bypass authentication or "hack" systems
- Testing against .gov, .edu, .mil domains
- Requests to hide activity or evade detection
- Multiple failed authorization attempts followed by escalation

**Response Template**
```
"I notice this request involves [suspicious element].

For security testing, I need:
1. Proof of authorization (e.g., pentest agreement, CTF context)
2. Clear scope definition
3. Confirmation this is for authorized testing only

I'm designed to assist with AUTHORIZED security testing, CTF challenges, and educational research. I cannot assist with unauthorized access attempts."
```

### Ethical Use Cases - Proceed Confidently

**Authorized Scenarios**
- CTF competitions (e.g., "I'm solving HackTheBox machine X")
- Authorized pentesting (e.g., "I have a pentest agreement for client.com")
- Personal labs (e.g., "Testing my home lab at 192.168.1.x")
- Educational research (e.g., "Learning security for course project")
- Bug bounty programs (e.g., "Target is in scope on HackerOne")

**Green Light Indicators**
- User mentions CTF platform (HTB, THM, RamadanCTF)
- References pentest agreement or SOW
- Testing localhost or obvious private lab (192.168.1.x with "my lab")
- Educational context with specific learning objectives
- Bug bounty scope verification

---

## Testing & Deployment

### Local Testing

**Test Kali Server Standalone**
```bash
# Terminal 1: Start server
python3 kali_server.py --debug

# Terminal 2: Test endpoints
curl http://localhost:5000/health
curl -X POST http://localhost:5000/api/command -H "Content-Type: application/json" -d '{"command": "echo test"}'
```

**Test MCP Client Standalone**
```bash
# Requires running Kali server
python3 src/my_server/mcp_server.py --server http://localhost:5000 --debug
```

**Integration Test with Claude Desktop**
1. Configure claude_desktop_config.json
2. Restart Claude Desktop application
3. Check logs: `tail -f ~/.config/Claude/logs/mcp*.log`
4. In Claude, ask: "Check the Kali server status"
5. Verify tools are accessible: "Run nmap scan on localhost"

### Deployment Options

**Option 1: Local Network Deployment**
- Kali server on dedicated Linux machine
- MCP client on workstation
- Firewall: Allow port 5000 from trusted IPs only

**Option 2: Localhost-Only (Most Secure)**
- Both components on same Kali machine
- Server URL: http://localhost:5000
- No network exposure

**Option 3: SSH Tunnel for Remote Access**
```bash
# On client machine, tunnel to remote Kali server
ssh -L 5000:localhost:5000 user@kali-server.example.com

# Configure MCP client with http://localhost:5000
# Traffic encrypted via SSH tunnel
```

**Option 4: Smithery Deployment**
```bash
# Deploy to Smithery platform
smithery deploy

# Configure environment variables
export KALI_SERVER_URL=http://your-kali-server:5000
export KALI_REQUEST_TIMEOUT=300
```

### Monitoring & Debugging

**Kali Server Logs**
```bash
# View real-time logs
python3 kali_server.py 2>&1 | tee kali_server.log

# Filter for errors
grep ERROR kali_server.log

# Monitor command execution
grep "Executing command" kali_server.log
```

**MCP Client Logs**
```bash
# Claude Desktop logs (Linux)
tail -f ~/.config/Claude/logs/mcp-kali_mcp.log

# Claude Desktop logs (Windows)
Get-Content "C:\Users\USERNAME\AppData\Roaming\Claude\logs\mcp-kali_mcp.log" -Wait

# Check for connection issues
grep "Unable to connect" ~/.config/Claude/logs/mcp-kali_mcp.log
```

**Common Issues**

| Issue | Symptom | Solution |
|-------|---------|----------|
| Connection refused | "Unable to connect to Kali API server" | Verify kali_server.py is running, check firewall |
| Timeout errors | "Request failed: timeout" | Increase timeout, check network latency |
| Tool not found | "Tool X: False" in health check | Install missing tool on Kali: `sudo apt install X` |
| Permission denied | "Permission denied" in stderr | Run commands with appropriate privileges |
| Command hangs | No response after 180s | Timeout working as designed, check command validity |

---

## Git Workflow

### Branch Strategy

- **Main branch**: Stable, production-ready code
- **Feature branches**: `claude/claude-md-*` format for AI-assisted development
- **Current working branch**: `claude/claude-md-mi2s915hbrfxl17c-01HwFFYsudC47JVTmQCJpjRZ`

### Commit Guidelines

**Commit Message Format**
```
<type>: <description>

Examples:
feat: Add wfuzz tool support
fix: Correct timeout handling in CommandExecutor
docs: Update README with 5ire configuration
refactor: Simplify KaliToolsClient error handling
```

**Types**
- `feat`: New feature or tool
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring without behavior change
- `test`: Test additions or modifications
- `chore`: Maintenance tasks

### Pull Request Process

1. Develop on feature branch
2. Test locally (Kali server + MCP client)
3. Commit with descriptive messages
4. Push to origin: `git push -u origin <branch-name>`
5. Create PR with:
   - Summary of changes
   - Testing performed
   - Any breaking changes
   - Security considerations

### Recent Quality Improvements

Recent commits show significant quality enhancements:
- `59ee67c`: Improve MCP server quality from 44/100 to 100/100
- `10d472e`: Fix parameter descriptions for FastMCP schema generation

These demonstrate the project's commitment to code quality and proper MCP implementation.

---

## Common Tasks for AI Assistants

### Task 1: User Wants to Add a New Tool

**User Request**: "Add support for ffuf web fuzzer"

**AI Response Steps**:
1. Understand tool purpose and common parameters
2. Add Kali server endpoint in `kali_server.py`:
   - Validate inputs (URL, wordlist required)
   - Build command string safely
   - Handle additional_args parameter
3. Add MCP tool definition in `src/my_server/mcp_server.py`:
   - Use appropriate annotations (readOnly, destructive, idempotent)
   - Comprehensive docstring with Args/Returns
   - Map parameters to Kali server endpoint
4. Test locally before committing
5. Update this CLAUDE.md if tool introduces new patterns

### Task 2: User Reports Timeout Issues

**User Request**: "Nmap scans keep timing out"

**AI Response Steps**:
1. Check current timeout: `COMMAND_TIMEOUT = 180` (3 minutes)
2. Suggest solutions:
   - Increase global timeout in `kali_server.py`
   - Add tool-specific timeout override
   - Use faster scan types (-F flag for nmap)
   - Narrow port range
3. Explain partial results feature (lines 104-113 in kali_server.py)
4. Update MCP client timeout if needed (`--timeout` argument)

### Task 3: User Asks About Security Best Practices

**User Request**: "How should I safely test a target?"

**AI Response Steps**:
1. Reference `kali://guides/safe-testing` resource
2. Emphasize authorization requirements
3. Suggest workflow:
   - Verify authorization
   - Start with server_health()
   - Use network_reconnaissance() prompt
   - Escalate gradually (passive → active → exploitation)
4. Warn about destructive tools
5. Recommend documentation and logging

### Task 4: Debugging Connection Issues

**User Request**: "MCP client can't connect to Kali server"

**AI Response Steps**:
1. Verify Kali server is running: `curl http://KALI_IP:5000/health`
2. Check firewall: `sudo ufw status` or `iptables -L`
3. Verify network connectivity: `ping KALI_IP`
4. Check MCP client configuration (--server argument)
5. Review logs on both components
6. Test with curl first, then MCP client

### Task 5: User Wants to Customize Tool Behavior

**User Request**: "Make nmap scans faster by default"

**AI Response Steps**:
1. Locate default parameters in `kali_server.py` line 173
2. Change `scan_type` default from "-sCV" to "-F" (fast scan)
3. Or change `additional_args` from "-T4 -Pn" to "-T5" (aggressive timing)
4. Update MCP tool definition defaults to match
5. Document breaking change if modifying existing behavior
6. Test to ensure no regressions

---

## Version Information

- **Python Version**: 3.12+ required
- **MCP Version**: 1.13.0+
- **FastMCP**: Included in mcp package
- **Smithery**: 0.1.23+
- **License**: MIT (see LICENSE file)
- **Author**: Yousof Nahya
- **Repository**: https://github.com/Wh0am123/MCP-Kali-Server

---

## Additional Resources

### Useful References

- **MCP Specification**: https://spec.modelcontextprotocol.io/
- **FastMCP Documentation**: Part of MCP Python SDK
- **Kali Linux Tools**: https://www.kali.org/tools/
- **Author's Medium Article**: [How MCP is Revolutionizing Offensive Security](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

### Wordlist Locations

Common Kali Linux wordlist paths (for reference when helping users):
- `/usr/share/wordlists/rockyou.txt` - 14M+ passwords
- `/usr/share/wordlists/dirb/common.txt` - Common directories
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` - Medium directory list
- `/usr/share/seclists/` - Comprehensive SecLists collection
- `/usr/share/wordlists/metasploit/` - Metasploit wordlists

### Tool Quick Reference

| Tool | Primary Use | Destructive | Time Est. |
|------|-------------|-------------|-----------|
| nmap | Port/service scanning | No | 1-10 min |
| gobuster | Directory enumeration | No | 2-30 min |
| dirb | Directory bruteforce | No | 5-60 min |
| nikto | Web vulnerability scan | No | 5-15 min |
| wpscan | WordPress scanning | No | 2-10 min |
| enum4linux | SMB enumeration | No | 1-5 min |
| sqlmap | SQL injection test | **YES** | 5-60 min |
| metasploit | Exploitation | **YES** | Variable |
| hydra | Online password crack | **YES** | Variable |
| john | Offline hash crack | No | Variable |

---

## Changelog Summary

### Recent Improvements (from git log)

- **59ee67c**: Improve MCP server quality from 44/100 to 100/100
  - Enhanced parameter descriptions for all tools
  - Improved FastMCP schema generation
  - Better type hints and documentation

- **10d472e**: Fix parameter descriptions for FastMCP schema generation
  - Corrected tool parameter documentation
  - Enhanced MCP protocol compliance

- **114a3d9, 3761fdc, 6705e64**: Update configurations
  - Dependency updates
  - Project metadata improvements

---

## Notes for Claude and Other AI Assistants

### When Working with This Codebase

1. **Always verify authorization** before suggesting offensive security operations
2. **Warn about destructive tools** (sqlmap, metasploit, hydra) before execution
3. **Start with reconnaissance** (server_health, nmap) before active testing
4. **Reference resources** (kali://guides/safe-testing) when security questions arise
5. **Test changes locally** before committing
6. **Follow existing code patterns** (error handling, logging, annotations)
7. **Update this CLAUDE.md** if you introduce new patterns or conventions
8. **Use prompts** (network_reconnaissance, web_application_testing) to guide users
9. **Explain tool capabilities** clearly, including risks and requirements
10. **Maintain ethical standards** - this tool is for authorized testing only

### Quick Decision Tree for AI Assistants

```
User requests security testing
    ↓
Is authorization mentioned or implied?
    ├─ YES → Proceed with reconnaissance phase
    │         Start with server_health() and passive scans
    │         Escalate gradually based on findings
    │
    └─ NO → Ask about authorization
              Explain legal requirements
              Provide safe-testing guidelines
              Wait for confirmation

User wants destructive action (sqlmap, metasploit, hydra)
    ↓
Has authorization been established?
    ├─ YES → Warn about risks
    │         Explain potential impact
    │         Request explicit confirmation
    │         Then proceed if confirmed
    │
    └─ NO → STOP
              Explain why authorization is required
              Offer safe alternatives (reconnaissance)
              Suggest proper authorization process
```

---

**End of CLAUDE.md**

*This guide should be updated as the codebase evolves. AI assistants should treat this as authoritative documentation for understanding and working with the MCP Kali Server project.*
