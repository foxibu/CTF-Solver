#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def nmap_scan(
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute an Nmap network scan to discover hosts, open ports, services, and versions.

        Args:
            target: Target IP address or hostname to scan (e.g., '192.168.1.1' or 'example.com')
            scan_type: Nmap scan type - use '-sV' for version detection, '-sS' for SYN scan, '-sT' for TCP connect, '-sU' for UDP scan, or '-A' for aggressive scan (default: '-sV')
            ports: Ports to scan - can be single port '80', range '1-1000', comma-separated list '22,80,443', or empty for default ports (default: '')
            additional_args: Additional Nmap arguments like '-O' for OS detection or '--script vuln' for vulnerability scripts (default: '')

        Returns:
            Scan results including discovered ports, services, and version information
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def gobuster_scan(
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Gobuster directory/DNS/vhost enumeration to discover hidden paths, subdomains, or virtual hosts.

        Args:
            url: Target URL (http://example.com) or domain for DNS mode
            mode: Scan mode - 'dir' for directory bruteforce, 'dns' for subdomain enumeration, 'vhost' for virtual host discovery, or 'fuzz' for fuzzing (default: 'dir')
            wordlist: Path to wordlist file on Kali server (default: '/usr/share/wordlists/dirb/common.txt')
            additional_args: Additional Gobuster arguments like '-x php,html' for file extensions or '-t 50' for thread count (default: '')

        Returns:
            Discovered directories, subdomains, or virtual hosts with response codes
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Dirb web content scanner to discover hidden directories and files through dictionary-based attacks.

        Args:
            url: Target URL to scan (e.g., http://example.com)
            wordlist: Path to wordlist file on Kali server (default: '/usr/share/wordlists/dirb/common.txt')
            additional_args: Additional Dirb arguments like '-r' for non-recursive or '-z 10' for millisecond delay (default: '')

        Returns:
            Discovered directories and files with HTTP response codes
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def nikto_scan(
        target: str,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Nikto web server vulnerability scanner to identify server misconfigurations, outdated software, and security issues.

        Args:
            target: Target URL or IP address to scan (e.g., 'http://example.com' or '192.168.1.1')
            additional_args: Additional Nikto arguments like '-Tuning x' for specific test types or '-port 8080' for custom port (default: '')

        Returns:
            Vulnerability findings, server information, and security recommendations
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def sqlmap_scan(
        url: str,
        data: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute SQLmap automated SQL injection detection and exploitation tool. WARNING: Can modify database contents.

        Args:
            url: Target URL to test for SQL injection vulnerabilities (e.g., 'http://example.com/page.php?id=1')
            data: POST data string for testing POST parameters (e.g., 'username=admin&password=test') (default: '')
            additional_args: Additional SQLmap arguments like '--batch' for non-interactive mode, '--dbs' to enumerate databases, or '--risk 3' for aggressive testing (default: '')

        Returns:
            SQL injection vulnerabilities found, database information, and exploitation results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def metasploit_run(
        module: str,
        options: Dict[str, Any] = {}
    ) -> Dict[str, Any]:
        """
        Execute a Metasploit Framework module for exploitation, scanning, or auxiliary functions. WARNING: Can compromise systems.

        Args:
            module: Metasploit module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue' or 'auxiliary/scanner/portscan/tcp')
            options: Module options as key-value pairs (e.g., {'RHOSTS': '192.168.1.1', 'RPORT': 445}) (default: {})

        Returns:
            Module execution results, including any exploited sessions or scan findings
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra online password cracking tool for authentication brute-forcing. WARNING: May lock accounts or trigger security alerts.

        Args:
            target: Target IP address or hostname to attack (e.g., '192.168.1.1' or 'example.com')
            service: Service to attack - supports 'ssh', 'ftp', 'http-post-form', 'rdp', 'smb', 'telnet', etc.
            username: Single username to test (leave empty if using username_file) (default: '')
            username_file: Path to username wordlist file on Kali server (e.g., '/usr/share/wordlists/usernames.txt') (default: '')
            password: Single password to test (leave empty if using password_file) (default: '')
            password_file: Path to password wordlist file on Kali server (e.g., '/usr/share/wordlists/rockyou.txt') (default: '')
            additional_args: Additional Hydra arguments like '-t 4' for thread count or '-V' for verbose output (default: '')

        Returns:
            Successfully cracked credentials and attack statistics
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper offline password hash cracker using wordlist and rules-based attacks.

        Args:
            hash_file: Path to file containing password hashes on Kali server (e.g., '/tmp/hashes.txt')
            wordlist: Path to wordlist file on Kali server (default: '/usr/share/wordlists/rockyou.txt')
            format_type: Hash format type like 'md5', 'sha256', 'NT', 'des', 'raw-md5' - leave empty for auto-detection (default: '')
            additional_args: Additional John arguments like '--rules' for mangling rules or '--show' to display previously cracked passwords (default: '')

        Returns:
            Cracked passwords, hash format information, and cracking statistics
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def wpscan_analyze(
        url: str,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute WPScan WordPress security scanner to identify vulnerabilities, plugins, themes, and users.

        Args:
            url: Target WordPress site URL (e.g., 'http://example.com')
            additional_args: Additional WPScan arguments like '--enumerate u,p,t' for enumerating users/plugins/themes or '--api-token TOKEN' for vulnerability data (default: '')

        Returns:
            WordPress version, installed plugins/themes, known vulnerabilities, and enumerated users
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def enum4linux_scan(
        target: str,
        additional_args: str = "-a"
    ) -> Dict[str, Any]:
        """
        Execute Enum4linux tool to enumerate Windows/Samba systems for users, shares, groups, and OS information.

        Args:
            target: Target Windows/Samba host IP address or hostname (e.g., '192.168.1.10')
            additional_args: Additional enum4linux arguments - use '-a' for all enumeration, '-U' for users only, or '-S' for shares only (default: '-a')

        Returns:
            Enumerated users, shares, groups, password policies, and system information
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def server_health() -> Dict[str, Any]:
        """
        Check the health status and tool availability of the Kali API server.

        Returns:
            Server status, available security tools, and system health information
        """
        return kali_client.check_health()

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def execute_command(
        command: str
    ) -> Dict[str, Any]:
        """
        Execute an arbitrary shell command on the Kali Linux server. WARNING: Unrestricted command execution - use with extreme caution.

        Args:
            command: Shell command to execute on Kali server (e.g., 'whoami' or 'ls -la /tmp'). WARNING: Can execute any command with server permissions.

        Returns:
            Command output (stdout/stderr), exit code, and execution status
        """
        return kali_client.execute_command(command)

    # Resources for accessing server information and common data
    @mcp.resource("kali://server/status")
    def get_server_status() -> str:
        """
        Get the current status and health of the Kali API server.
        """
        health = kali_client.check_health()
        if "error" in health:
            return f"Error connecting to Kali server: {health['error']}"

        status_text = f"""# Kali Server Status

**Status**: {health.get('status', 'unknown')}
**All Tools Available**: {health.get('all_essential_tools_available', False)}

## Tool Availability
"""
        for tool, available in health.get('tools_status', {}).items():
            status_icon = "✅" if available else "❌"
            status_text += f"- {status_icon} {tool}\n"

        return status_text

    @mcp.resource("kali://wordlists/common")
    def get_common_wordlists() -> str:
        """
        List common wordlists available on Kali Linux systems.
        """
        return """# Common Kali Wordlists

## Password Lists
- `/usr/share/wordlists/rockyou.txt` - Most popular password list (14M+ passwords)
- `/usr/share/wordlists/fasttrack.txt` - FastTrack common passwords
- `/usr/share/john/password.lst` - John the Ripper default wordlist

## Directory/File Lists
- `/usr/share/wordlists/dirb/common.txt` - Common web directories
- `/usr/share/wordlists/dirb/big.txt` - Larger directory list
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` - DirBuster medium list

## Username Lists
- `/usr/share/wordlists/metasploit/unix_users.txt` - Unix usernames
- `/usr/share/wordlists/metasploit/namelist.txt` - Common names

## DNS/Subdomain Lists
- `/usr/share/wordlists/dnsmap.txt` - DNS subdomain wordlist
- `/usr/share/seclists/Discovery/DNS/` - SecLists DNS collections

## Usage
Specify these paths in the wordlist parameter of scanning tools like gobuster, dirb, hydra, and john.
"""

    @mcp.resource("kali://guides/safe-testing")
    def get_safety_guide() -> str:
        """
        Security testing safety guidelines and best practices.
        """
        return """# Safe Penetration Testing Guidelines

## Legal Requirements
✅ **ALWAYS REQUIRED**:
- Written authorization from system owner
- Clearly defined scope (IP ranges, domains, systems)
- Testing timeframe agreement
- Rules of engagement document

❌ **NEVER TEST WITHOUT**:
- Explicit written permission
- Understanding of acceptable testing methods
- Emergency contact information
- Backup and rollback plans

## Testing Best Practices

### Reconnaissance Phase
- Start with passive information gathering
- Document all findings systematically
- Verify targets are within authorized scope

### Active Testing Phase
- Begin with least invasive tests
- Gradually increase test intensity
- Monitor for system instability
- Take regular breaks to review findings

### Exploitation Phase
- Obtain explicit approval before exploitation
- Use isolated test systems when possible
- Document all exploitation attempts
- Maintain system stability

### Password Attacks
- Verify account lockout policies first
- Use limited wordlists initially
- Monitor for lockout triggers
- Consider time delays between attempts

## Red Flags - STOP IMMEDIATELY IF:
- System becomes unresponsive
- You access unauthorized systems
- You discover personal/sensitive data unexpectedly
- Client requests you stop testing

## Professional Conduct
- Maintain confidentiality of findings
- Report critical vulnerabilities immediately
- Provide clear, actionable remediation advice
- Never use discovered vulnerabilities maliciously

## Emergency Procedures
1. Document exact actions taken
2. Notify client immediately
3. Assist with incident response if needed
4. Preserve all logs and evidence
"""

    # Prompts for common workflows
    @mcp.prompt()
    def network_reconnaissance(target: str) -> str:
        """
        Generate a comprehensive network reconnaissance workflow for a target.

        Args:
            target: Target IP address or hostname to scan
        """
        return f"""# Network Reconnaissance Workflow for {target}

## Phase 1: Initial Discovery
1. Run server_health() to verify Kali tools are available
2. Run nmap_scan(target="{target}", scan_type="-sV", ports="") for initial port discovery

## Phase 2: Service Enumeration
Based on open ports from Phase 1:
- If port 80/443 open: Run nikto_scan(target="http://{target}")
- If port 445 open: Run enum4linux_scan(target="{target}")
- If WordPress detected: Run wpscan_analyze(url="http://{target}")

## Phase 3: Directory Enumeration
If web services found:
- Run gobuster_scan(url="http://{target}", mode="dir")
- Run dirb_scan(url="http://{target}")

## Phase 4: Vulnerability Assessment
- Analyze all results for potential vulnerabilities
- Document findings and prioritize exploitation targets
"""

    @mcp.prompt()
    def web_application_testing(url: str) -> str:
        """
        Generate a web application security testing workflow.

        Args:
            url: Target web application URL
        """
        return f"""# Web Application Testing Workflow for {url}

## Phase 1: Server Fingerprinting
1. Run nikto_scan(target="{url}") to identify server vulnerabilities

## Phase 2: Content Discovery
1. Run gobuster_scan(url="{url}", mode="dir") for directory enumeration
2. Run dirb_scan(url="{url}") for additional path discovery

## Phase 3: CMS Detection & Testing
If WordPress is detected:
- Run wpscan_analyze(url="{url}")

## Phase 4: Injection Testing
For forms and parameters found:
- Run sqlmap_scan(url="{url}/vulnerable_page.php?id=1") for SQL injection

## Safety Reminders
- Ensure you have written authorization
- Test only in authorized scope
- Document all findings professionally
"""

    @mcp.prompt()
    def password_attack_workflow(target: str, service: str) -> str:
        """
        Generate a password attack workflow for credential testing.

        Args:
            target: Target IP or hostname
            service: Service to test (ssh, ftp, rdp, etc.)
        """
        return f"""# Password Attack Workflow for {service} on {target}

## Prerequisites Check
1. Run server_health() to verify tools are ready
2. Confirm written authorization exists for testing
3. Verify account lockout policies to avoid DoS

## Phase 1: Username Enumeration
- Identify valid usernames through service-specific enumeration
- Common usernames: admin, root, administrator, user

## Phase 2: Offline Hash Cracking (if hashes obtained)
If you have password hashes:
- Run john_crack(hash_file="/path/to/hashes.txt", wordlist="/usr/share/wordlists/rockyou.txt")

## Phase 3: Online Password Attack (use with extreme caution)
- Run hydra_attack(target="{target}", service="{service}", username="target_user", password_file="/usr/share/wordlists/rockyou.txt")
- Use limited wordlists to avoid account lockout
- Monitor for lockout thresholds

## Safety Warnings
⚠️ Online attacks may lock accounts
⚠️ May trigger security alerts/IDS
⚠️ Only test with explicit written permission
"""

    return mcp

def create_server() -> FastMCP:
    """
    Factory function for Smithery deployment.
    Reads configuration from environment variables.

    Returns:
        Configured FastMCP instance
    """
    # Read configuration from environment variables
    server_url = os.environ.get("KALI_SERVER_URL", DEFAULT_KALI_SERVER)
    timeout = int(os.environ.get("KALI_REQUEST_TIMEOUT", str(DEFAULT_REQUEST_TIMEOUT)))

    logger.info(f"Creating Kali MCP server (Smithery mode)")
    logger.info(f"Kali API server: {server_url}")
    logger.info(f"Request timeout: {timeout}s")

    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(server_url, timeout)

    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {server_url}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")

    # Set up and return the MCP server
    return setup_mcp_server(kali_client)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
