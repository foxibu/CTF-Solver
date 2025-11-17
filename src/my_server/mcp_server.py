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

    # ========================================================================
    # SESSION MANAGEMENT TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def create_analysis_session(
        user_id: str = "mcp_client"
    ) -> Dict[str, Any]:
        """
        Create a new analysis session for multi-step binary analysis or exploitation. Sessions maintain workspace, context, and history.

        Args:
            user_id: Identifier for the session owner (default: 'mcp_client')

        Returns:
            Session ID and workspace path for file operations
        """
        return kali_client.safe_post("api/session/create", {"user_id": user_id})

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def save_analysis_result(
        session_id: str,
        key: str,
        value: str
    ) -> Dict[str, Any]:
        """
        Save analysis results to session context for later retrieval. Use this to persist findings across multiple analysis steps.

        Args:
            session_id: Session ID from create_analysis_session()
            key: Context key (e.g., 'protections', 'gadgets', 'exploit_script')
            value: Value to store (can be string, JSON, or any serializable data)

        Returns:
            Success status
        """
        return kali_client.safe_post(f"api/session/{session_id}/context", {
            "key": key,
            "value": value
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def load_analysis_results(
        session_id: str
    ) -> Dict[str, Any]:
        """
        Load all analysis results saved in the session context.

        Args:
            session_id: Session ID from create_analysis_session()

        Returns:
            All saved context data including workspace path and creation time
        """
        return kali_client.safe_get(f"api/session/{session_id}/context")

    # ========================================================================
    # FILE MANAGEMENT TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def upload_binary(
        session_id: str,
        filename: str,
        content_base64: str,
        executable: bool = True
    ) -> Dict[str, Any]:
        """
        Upload a binary file to the session workspace for analysis. File content must be base64 encoded.

        Args:
            session_id: Session ID from create_analysis_session()
            filename: Name of the file to create (e.g., 'challenge.bin')
            content_base64: Base64 encoded file content
            executable: Set executable permission on the file (default: True)

        Returns:
            File path, size, and upload status
        """
        return kali_client.safe_post("api/file/upload", {
            "session_id": session_id,
            "filename": filename,
            "content": content_base64,
            "executable": executable
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def list_session_files(
        session_id: str
    ) -> Dict[str, Any]:
        """
        List all files in the session workspace.

        Args:
            session_id: Session ID from create_analysis_session()

        Returns:
            List of files with name, size, permissions, and modification time
        """
        return kali_client.safe_post("api/file/list", {"session_id": session_id})

    # ========================================================================
    # INTERACTIVE SESSION TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def start_interactive_shell(
        session_id: str,
        command: str
    ) -> Dict[str, Any]:
        """
        Start an interactive shell session for bidirectional communication (e.g., nc, ssh, or running exploits). WARNING: Creates persistent connection.

        Args:
            session_id: Session ID from create_analysis_session()
            command: Command to execute interactively (e.g., 'nc 127.0.0.1 9000' or 'python3 exploit.py')

        Returns:
            Interactive session ID for sending input and reading output
        """
        return kali_client.safe_post("api/interactive/start", {
            "session_id": session_id,
            "command": command
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def send_to_shell(
        interactive_id: str,
        text: str
    ) -> Dict[str, Any]:
        """
        Send input to an interactive shell session. Use this to interact with running programs.

        Args:
            interactive_id: Interactive session ID from start_interactive_shell()
            text: Text to send (include '\n' for newline if needed)

        Returns:
            Success status
        """
        return kali_client.safe_post("api/interactive/send", {
            "interactive_id": interactive_id,
            "text": text
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def read_shell_output(
        interactive_id: str
    ) -> Dict[str, Any]:
        """
        Read accumulated output from an interactive shell session. Output buffer is cleared after reading.

        Args:
            interactive_id: Interactive session ID from start_interactive_shell()

        Returns:
            Shell output and process alive status
        """
        return kali_client.safe_post("api/interactive/read", {
            "interactive_id": interactive_id
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def close_shell(
        interactive_id: str
    ) -> Dict[str, Any]:
        """
        Close an interactive shell session and free resources.

        Args:
            interactive_id: Interactive session ID from start_interactive_shell()

        Returns:
            Success status
        """
        return kali_client.safe_post("api/interactive/close", {
            "interactive_id": interactive_id
        })

    # ========================================================================
    # BINARY ANALYSIS TOOLS (PWNABLE)
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def checksec_binary(
        session_id: str,
        binary_filename: str
    ) -> Dict[str, Any]:
        """
        Analyze binary security protections (RELRO, Stack Canary, NX, PIE, Symbols). Essential first step for pwnable challenges.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace

        Returns:
            Protection mechanisms enabled/disabled with parsed boolean values
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/checksec", {"binary_path": binary_path})

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def find_rop_gadgets(
        session_id: str,
        binary_filename: str,
        search_string: str = ""
    ) -> Dict[str, Any]:
        """
        Search for ROP gadgets in binary using ROPgadget. Use this to build ROP chains for NX bypass.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            search_string: Optional search filter (e.g., 'pop rdi' or 'syscall')

        Returns:
            List of gadget addresses and instructions
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/ropgadget", {
            "binary_path": binary_path,
            "search": search_string
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def analyze_with_radare2(
        session_id: str,
        binary_filename: str,
        commands: list = None
    ) -> Dict[str, Any]:
        """
        Analyze binary with radare2. Default commands: analyze all, disassemble main.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            commands: List of r2 commands (default: ['aaa', 'pdf @ main']). Common commands: 'afl' (list functions), 'iz' (strings), 'pdf @ func' (disassemble)

        Returns:
            Radare2 analysis output
        """
        if commands is None:
            commands = ["aaa", "pdf @ main"]

        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/radare2", {
            "binary_path": binary_path,
            "commands": commands
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def disassemble_binary(
        session_id: str,
        binary_filename: str,
        mode: str = "disassemble"
    ) -> Dict[str, Any]:
        """
        Disassemble binary with objdump. Modes: disassemble (code), headers (sections), symbols (functions/variables), all (everything).

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            mode: Analysis mode - 'disassemble', 'headers', 'symbols', or 'all'

        Returns:
            Objdump output in Intel syntax
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/objdump", {
            "binary_path": binary_path,
            "mode": mode
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def trace_syscalls(
        session_id: str,
        binary_filename: str,
        arguments: str = ""
    ) -> Dict[str, Any]:
        """
        Trace system calls with strace. Useful for understanding binary behavior and finding vulnerabilities.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            arguments: Command line arguments to pass to binary

        Returns:
            System call trace output
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/strace", {
            "binary_path": binary_path,
            "arguments": arguments
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def trace_library_calls(
        session_id: str,
        binary_filename: str,
        arguments: str = ""
    ) -> Dict[str, Any]:
        """
        Trace library calls with ltrace. Reveals functions like strcpy, malloc, printf being called.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            arguments: Command line arguments to pass to binary

        Returns:
            Library call trace output
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/ltrace", {
            "binary_path": binary_path,
            "arguments": arguments
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def extract_strings(
        session_id: str,
        binary_filename: str,
        min_length: int = 4
    ) -> Dict[str, Any]:
        """
        Extract printable strings from binary. Look for flags, passwords, or interesting data.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace
            min_length: Minimum string length to extract (default: 4)

        Returns:
            Extracted strings
        """
        session = kali_client.safe_get(f"api/session/{session_id}/context")
        if "error" in session:
            return session
        workspace = session.get("workspace", "")
        binary_path = f"{workspace}/{binary_filename}"

        return kali_client.safe_post("api/tools/strings", {
            "binary_path": binary_path,
            "min_length": min_length
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def run_pwntools_exploit(
        session_id: str,
        exploit_script: str,
        script_name: str = "exploit.py"
    ) -> Dict[str, Any]:
        """
        Execute a pwntools exploit script. Script should use 'from pwn import *' and can use process() or remote().

        Args:
            session_id: Session ID from create_analysis_session()
            exploit_script: Complete Python exploit code using pwntools
            script_name: Filename to save script as (default: 'exploit.py')

        Returns:
            Exploit execution output including any captured flags
        """
        return kali_client.safe_post("api/tools/pwntools", {
            "session_id": session_id,
            "script": exploit_script,
            "script_name": script_name
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def auto_detect_vulnerabilities(
        session_id: str,
        binary_filename: str
    ) -> Dict[str, Any]:
        """
        AI-powered automatic vulnerability detection. Analyzes protections, dangerous functions, and infers potential exploits.

        Args:
            session_id: Session ID from create_analysis_session()
            binary_filename: Filename of binary in session workspace

        Returns:
            Comprehensive findings including protections, dangerous functions, interesting strings, and potential vulnerabilities with severity
        """
        return kali_client.safe_post("api/analyze/auto_detect", {
            "session_id": session_id,
            "binary_filename": binary_filename
        })

    # ========================================================================
    # CRYPTOGRAPHY TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def hashcat_crack(
        hash_value: str = "",
        hash_file: str = "",
        hash_type: str = "0",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        attack_mode: str = "0",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Crack password hashes using hashcat GPU-accelerated cracking. Supports 300+ hash types.

        Args:
            hash_value: Single hash to crack (alternative to hash_file)
            hash_file: Path to file containing hashes on Kali server
            hash_type: Hash type mode - '0' for MD5, '100' for SHA1, '1000' for NTLM, '1400' for SHA256, '3200' for bcrypt (default: '0')
            wordlist: Path to wordlist file (default: '/usr/share/wordlists/rockyou.txt')
            attack_mode: Attack mode - '0' for straight, '1' for combination, '3' for brute-force (default: '0')
            additional_args: Additional hashcat args like '--rules-file' or '--increment'

        Returns:
            Cracked passwords and cracking statistics
        """
        return kali_client.safe_post("api/crypto/hashcat", {
            "hash": hash_value,
            "hash_file": hash_file,
            "hash_type": hash_type,
            "wordlist": wordlist,
            "attack_mode": attack_mode,
            "additional_args": additional_args
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def factordb_query(
        number: str
    ) -> Dict[str, Any]:
        """
        Query FactorDB for integer factorization. Essential for RSA attacks with weak primes.

        Args:
            number: Large integer to factor (RSA modulus N)

        Returns:
            Factorization results from FactorDB
        """
        return kali_client.safe_post("api/crypto/factordb", {"number": number})

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def rsa_attack(
        session_id: str,
        n: str = "",
        e: str = "",
        c: str = "",
        attack: str = "all"
    ) -> Dict[str, Any]:
        """
        Perform RSA attacks using RsaCtfTool. Includes factorization, Wiener's attack, Hastad's attack, and more.

        Args:
            session_id: Session ID from create_analysis_session()
            n: RSA modulus (N)
            e: Public exponent (e)
            c: Ciphertext to decrypt
            attack: Attack type - 'all', 'wiener', 'fermat', 'factordb', 'noveltyprimes' (default: 'all')

        Returns:
            Attack results including private key or plaintext if successful
        """
        return kali_client.safe_post("api/crypto/rsactftool", {
            "session_id": session_id,
            "n": n,
            "e": e,
            "c": c,
            "attack": attack
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def sage_execute(
        session_id: str,
        script: str,
        script_name: str = "crypto_solve.sage"
    ) -> Dict[str, Any]:
        """
        Execute SageMath script for advanced cryptographic attacks (elliptic curves, lattices, number theory).

        Args:
            session_id: Session ID from create_analysis_session()
            script: Complete SageMath script code
            script_name: Filename to save script as (default: 'crypto_solve.sage')

        Returns:
            SageMath execution output including mathematical results
        """
        return kali_client.safe_post("api/crypto/sage", {
            "session_id": session_id,
            "script": script,
            "script_name": script_name
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def openssl_operation(
        operation: str,
        args: str = ""
    ) -> Dict[str, Any]:
        """
        Perform OpenSSL cryptographic operations (encryption, decryption, key generation, certificate parsing).

        Args:
            operation: OpenSSL operation - 'enc', 'dec', 'rsa', 'genrsa', 'x509', 'dgst', etc.
            args: Operation arguments (e.g., '-aes-256-cbc -d -in cipher.txt -out plain.txt -k password')

        Returns:
            OpenSSL command output
        """
        return kali_client.safe_post("api/crypto/openssl", {
            "operation": operation,
            "args": args
        })

    # ========================================================================
    # FORENSICS TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def volatility_analyze(
        dump_file: str,
        plugin: str = "windows.info",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze memory dumps with Volatility 3 for malware analysis, incident response, and forensics.

        Args:
            dump_file: Path to memory dump file on Kali server
            plugin: Volatility plugin - 'windows.info', 'windows.pslist', 'windows.netscan', 'windows.malfind', 'linux.bash', etc.
            additional_args: Additional volatility args like '--pid 1234'

        Returns:
            Memory analysis results including processes, network connections, or malware artifacts
        """
        return kali_client.safe_post("api/forensics/volatility", {
            "dump_file": dump_file,
            "plugin": plugin,
            "additional_args": additional_args
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def binwalk_analyze(
        file_path: str,
        extract: bool = False,
        session_id: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze firmware and binaries with binwalk to identify embedded files and filesystems.

        Args:
            file_path: Path to file on Kali server
            extract: Extract found files (default: False)
            session_id: Session ID for organizing extracted files (required if extract=True)

        Returns:
            Identified file signatures, offsets, and extracted file locations
        """
        return kali_client.safe_post("api/forensics/binwalk", {
            "file_path": file_path,
            "extract": extract,
            "session_id": session_id
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def steghide_extract(
        cover_file: str,
        passphrase: str = "",
        output_file: str = ""
    ) -> Dict[str, Any]:
        """
        Extract hidden data from images/audio using steghide steganography tool.

        Args:
            cover_file: Path to cover file (JPG, BMP, WAV, AU) on Kali server
            passphrase: Steganography passphrase (leave empty to try without passphrase)
            output_file: Output filename for extracted data

        Returns:
            Extraction results and hidden file contents
        """
        return kali_client.safe_post("api/forensics/steghide", {
            "operation": "extract",
            "cover_file": cover_file,
            "passphrase": passphrase,
            "output_file": output_file
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def foremost_carve(
        session_id: str,
        file_path: str,
        types: str = ""
    ) -> Dict[str, Any]:
        """
        Carve files from disk images or corrupted data using foremost.

        Args:
            session_id: Session ID from create_analysis_session()
            file_path: Path to disk image or file on Kali server
            types: File types to carve - 'jpg,png,pdf,doc,zip' or empty for all types

        Returns:
            Carved files location and recovery statistics
        """
        return kali_client.safe_post("api/forensics/foremost", {
            "session_id": session_id,
            "file_path": file_path,
            "types": types
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def exiftool_analyze(
        file_path: str
    ) -> Dict[str, Any]:
        """
        Extract metadata from images, documents, and media files using exiftool.

        Args:
            file_path: Path to file on Kali server

        Returns:
            Complete metadata including GPS coordinates, camera info, creation dates, author info
        """
        return kali_client.safe_post("api/forensics/exiftool", {
            "file_path": file_path
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def tesseract_ocr(
        image_path: str,
        lang: str = "eng"
    ) -> Dict[str, Any]:
        """
        Perform OCR (Optical Character Recognition) on images using tesseract.

        Args:
            image_path: Path to image file on Kali server
            lang: Language code - 'eng', 'fra', 'deu', 'jpn', 'kor', etc. (default: 'eng')

        Returns:
            Extracted text from image
        """
        return kali_client.safe_post("api/forensics/tesseract", {
            "image_path": image_path,
            "lang": lang
        })

    # ========================================================================
    # CLOUD SECURITY TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def aws_enumerate(
        profile: str = "default",
        service: str = "s3",
        command: str = "list"
    ) -> Dict[str, Any]:
        """
        Enumerate AWS resources using AWS CLI. Requires configured AWS credentials.

        Args:
            profile: AWS CLI profile name (default: 'default')
            service: AWS service - 's3', 'ec2', 'iam', 'lambda', etc.
            command: Command type - 'list' for listing resources

        Returns:
            Enumerated AWS resources (buckets, instances, users, etc.)
        """
        return kali_client.safe_post("api/cloud/aws_enumerate", {
            "profile": profile,
            "service": service,
            "command": command
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def s3_bucket_scan(
        bucket_name: str = "",
        wordlist: str = ""
    ) -> Dict[str, Any]:
        """
        Scan S3 buckets for misconfigurations and public access.

        Args:
            bucket_name: Specific S3 bucket name to test
            wordlist: Path to wordlist file for bucket name enumeration (alternative to bucket_name)

        Returns:
            S3 bucket accessibility and contents
        """
        return kali_client.safe_post("api/cloud/s3_scan", {
            "bucket_name": bucket_name,
            "wordlist": wordlist
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def cloud_metadata_query(
        provider: str = "aws",
        endpoint: str = ""
    ) -> Dict[str, Any]:
        """
        Query cloud metadata service for credentials and instance information.

        Args:
            provider: Cloud provider - 'aws', 'gcp', or 'azure'
            endpoint: Metadata endpoint path (e.g., 'iam/security-credentials/' for AWS)

        Returns:
            Cloud metadata including potential credentials and instance info
        """
        return kali_client.safe_post("api/cloud/metadata", {
            "provider": provider,
            "endpoint": endpoint
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def pacu_aws_exploit(
        session_id: str,
        module: str,
        pacu_session: str = "default"
    ) -> Dict[str, Any]:
        """
        Execute Pacu AWS exploitation framework modules. WARNING: Can modify AWS resources.

        Args:
            session_id: Session ID from create_analysis_session()
            module: Pacu module name (e.g., 'iam__enum_permissions', 's3__download_bucket')
            pacu_session: Pacu session name (default: 'default')

        Returns:
            Pacu module execution results
        """
        return kali_client.safe_post("api/cloud/pacu", {
            "session_id": session_id,
            "module": module,
            "pacu_session": pacu_session
        })

    # ========================================================================
    # WEB3 & BLOCKCHAIN SECURITY TOOLS
    # ========================================================================

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def slither_analyze(
        contract_path: str,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze Solidity smart contracts with Slither static analysis tool. Detects vulnerabilities and code issues.

        Args:
            contract_path: Path to .sol contract file on Kali server
            additional_args: Additional slither args like '--detect reentrancy' or '--exclude-informational'

        Returns:
            Smart contract vulnerabilities, detectors results, and security findings
        """
        return kali_client.safe_post("api/web3/slither", {
            "contract_path": contract_path,
            "additional_args": additional_args
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False
    })
    def mythril_analyze(
        contract_path: str,
        timeout: int = 300,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze smart contracts with Mythril symbolic execution engine. Finds complex vulnerabilities through symbolic analysis.

        Args:
            contract_path: Path to .sol contract file on Kali server
            timeout: Analysis timeout in seconds (default: 300)
            additional_args: Additional mythril args like '--max-depth 10'

        Returns:
            Detected vulnerabilities with severity levels and exploit scenarios
        """
        return kali_client.safe_post("api/web3/mythril", {
            "contract_path": contract_path,
            "timeout": timeout,
            "additional_args": additional_args
        })

    @mcp.tool(annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False
    })
    def web3_interact(
        session_id: str,
        script: str,
        script_name: str = "web3_interact.py"
    ) -> Dict[str, Any]:
        """
        Interact with blockchain networks using web3.py. WARNING: Can execute transactions and spend gas.

        Args:
            session_id: Session ID from create_analysis_session()
            script: Complete Python script using web3.py
            script_name: Filename to save script as (default: 'web3_interact.py')

        Returns:
            Blockchain interaction results including transaction hashes and contract responses
        """
        return kali_client.safe_post("api/web3/contract_interaction", {
            "session_id": session_id,
            "script": script,
            "script_name": script_name
        })

    @mcp.tool(annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True
    })
    def solidity_compile(
        contract_path: str,
        optimize: bool = False,
        output_dir: str = "/tmp/solc_output"
    ) -> Dict[str, Any]:
        """
        Compile Solidity smart contracts using solc compiler.

        Args:
            contract_path: Path to .sol contract file on Kali server
            optimize: Enable optimizer for gas efficiency (default: False)
            output_dir: Output directory for compiled artifacts (default: '/tmp/solc_output')

        Returns:
            Compiled contract bytecode and ABI
        """
        return kali_client.safe_post("api/web3/solc", {
            "contract_path": contract_path,
            "optimize": optimize,
            "output_dir": output_dir
        })

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

    @mcp.prompt()
    def pwnable_challenge_workflow(
        session_id: str,
        binary_filename: str,
        target_host: str = "",
        target_port: int = 0
    ) -> str:
        """
        Generate a comprehensive pwnable challenge solving workflow.

        Args:
            session_id: Analysis session ID
            binary_filename: Binary file to analyze
            target_host: Remote server host (optional)
            target_port: Remote server port (optional)
        """
        return f"""# Pwnable Challenge Workflow - {binary_filename}

## Phase 1: Binary Information Gathering
1. checksec_binary(session_id="{session_id}", binary_filename="{binary_filename}")
   - Check protection mechanisms (NX, PIE, Canary, RELRO)

2. auto_detect_vulnerabilities(session_id="{session_id}", binary_filename="{binary_filename}")
   - Automatic vulnerability detection with AI

3. analyze_with_radare2(session_id="{session_id}", binary_filename="{binary_filename}",
   commands=["aaa", "afl", "pdf @ main", "iz"])
   - Function list, main disassembly, strings

4. extract_strings(session_id="{session_id}", binary_filename="{binary_filename}")
   - Look for flags, paths, interesting data

## Phase 2: Vulnerability Analysis
Based on auto_detect results:

### If Buffer Overflow detected:
1. Find overflow offset using cyclic pattern
2. Check for win() function or useful gadgets
3. trace_library_calls() to see dangerous functions

### If NX enabled:
1. find_rop_gadgets(session_id="{session_id}", binary_filename="{binary_filename}")
   - Search for "pop rdi", "pop rsi", "ret", "syscall"
2. Look for system@plt or execve for ROP chain

### If PIE enabled:
1. Need information leak to bypass ASLR
2. Look for format string vulnerability
3. Partial overwrite techniques

## Phase 3: Exploit Development
Example pwntools template:

```python
from pwn import *

binary = '{binary_filename}'
{'# Local testing' if not target_host else f'# Remote: {target_host}:{target_port}'}

{'p = process("./" + binary)' if not target_host else f'p = remote("{target_host}", {target_port})'}
elf = ELF(binary)

# Calculate offset (use cyclic pattern)
offset = 72  # TODO: Find actual offset

# Build payload
payload = b'A' * offset
# Add ROP chain or return address here

p.sendline(payload)
p.interactive()
```

## Phase 4: Execution & Debugging
1. run_pwntools_exploit(session_id="{session_id}", exploit_script=<code>)
   - Test locally first

2. If fails, use:
   - trace_syscalls() to see system behavior
   - disassemble_binary() for detailed analysis

3. Adjust exploit and retry

## Checklist
- [ ] Binary protections identified
- [ ] Vulnerability type confirmed
- [ ] Exploit offset calculated
- [ ] Required addresses found (libc, gadgets, etc.)
- [ ] Payload constructed
- [ ] Local test successful
- [ ] Remote exploitation successful
- [ ] Flag captured
"""

    @mcp.prompt()
    def reversing_challenge_workflow(
        session_id: str,
        binary_filename: str
    ) -> str:
        """
        Generate a reversing challenge solving workflow.

        Args:
            session_id: Analysis session ID
            binary_filename: Binary file to analyze
        """
        return f"""# Reversing Challenge Workflow - {binary_filename}

## Phase 1: Initial Reconnaissance
1. checksec_binary(session_id="{session_id}", binary_filename="{binary_filename}")
   - Check if stripped, packed, or obfuscated

2. extract_strings(session_id="{session_id}", binary_filename="{binary_filename}")
   - Look for hardcoded keys, flags, or hints

3. Run the binary:
   - start_interactive_shell(command="./{binary_filename}")
   - Understand expected input/output

## Phase 2: Static Analysis
1. analyze_with_radare2(session_id="{session_id}", binary_filename="{binary_filename}",
   commands=["aaa", "afl", "pdf @ main"])
   - Map out program structure
   - Identify key functions (check_password, validate, decrypt, etc.)

2. disassemble_binary(session_id="{session_id}", binary_filename="{binary_filename}", mode="symbols")
   - Find interesting function names

3. Look for:
   - Comparison operations (cmp, test, je, jne)
   - Crypto constants (0x67452301 = MD5, etc.)
   - XOR operations (common obfuscation)
   - String comparisons (strcmp, strncmp)

## Phase 3: Dynamic Analysis
1. trace_syscalls(session_id="{session_id}", binary_filename="{binary_filename}")
   - See file operations, network calls

2. trace_library_calls(session_id="{session_id}", binary_filename="{binary_filename}")
   - Identify crypto/hash functions being used

3. Interactive debugging:
   - Use gdb to set breakpoints at key functions
   - Inspect registers and memory

## Phase 4: Algorithm Reversal
Common patterns:

### Password Checking:
```
user_input == hardcoded_value
→ Extract hardcoded value
```

### Simple XOR:
```
for (i=0; i<len; i++) output[i] = input[i] ^ key
→ XOR encrypted flag with key
```

### Hash Comparison:
```
md5(input) == target_hash
→ Crack hash or reverse algorithm
```

### Custom Encoding:
```
Analyze transformation step by step
→ Write decoder script
```

## Phase 5: Solution Extraction
1. If simple comparison: extract correct value from binary
2. If encryption: reverse the algorithm
3. If hash: use rainbow tables or bruteforce
4. If complex: write keygen/decoder

## Tools Checklist
- [ ] Strings extracted and analyzed
- [ ] Main functions disassembled
- [ ] Algorithm identified
- [ ] Key/flag location found
- [ ] Reversal method determined
- [ ] Solution verified
"""

    @mcp.prompt()
    def ctf_strategy(
        challenge_type: str,
        difficulty: str = "medium"
    ) -> str:
        """
        Generate strategy for CTF challenges across various platforms (HackTheBox, PicoCTF, CTFtime, etc.).

        Args:
            challenge_type: Type of challenge (pwnable, reversing, web, crypto, etc.)
            difficulty: Challenge difficulty (easy, medium, hard)
        """
        strategies = {
            "pwnable": """
## CTF Pwnable Strategy

### Easy Level:
- Buffer overflow without protections
- ret2win (jump to win function)
- Basic ROP with system() or execve()

### Medium Level:
- Buffer overflow with Canary (need leak)
- PIE enabled (need ASLR bypass)
- ret2libc attacks
- Format string vulnerabilities

### Hard Level:
- Full protections (NX+PIE+Canary+RELRO)
- Heap exploitation (UAF, double free)
- Advanced ROP (SROP, ret2csu)
- Seccomp sandbox bypass

### Recommended Tools:
1. create_analysis_session() - Start fresh workspace
2. upload_binary() - Upload challenge file
3. auto_detect_vulnerabilities() - Quick assessment
4. checksec_binary() + find_rop_gadgets() - Protection analysis
5. run_pwntools_exploit() - Test exploits
""",
            "reversing": """
## CTF Reversing Strategy

### Easy Level:
- Hardcoded password/flag
- Simple XOR encoding
- strcmp comparisons

### Medium Level:
- Custom encryption algorithms
- Anti-debugging techniques
- Obfuscated code

### Hard Level:
- VM-based obfuscation
- Multiple encryption layers
- Advanced anti-analysis

### Recommended Tools:
1. extract_strings() - Find low-hanging fruit
2. analyze_with_radare2() - Full disassembly
3. trace_library_calls() - Identify crypto libs
4. disassemble_binary() - Detailed analysis
""",
            "web": """
## CTF Web Strategy

### Easy Level:
- SQL injection
- XSS (reflected/stored)
- Command injection

### Medium Level:
- Blind SQLi
- CSRF
- LFI/RFI

### Hard Level:
- Type juggling
- XXE
- SSRF to internal services

### Recommended Tools:
1. gobuster_scan() - Directory enumeration
2. sqlmap_scan() - SQL injection
3. nikto_scan() - Vulnerability scanning
"""
        }

        return strategies.get(challenge_type.lower(), "Unknown challenge type")

    @mcp.prompt()
    def crypto_challenge_workflow(
        session_id: str,
        challenge_description: str = ""
    ) -> str:
        """
        Generate a cryptography challenge solving workflow.

        Args:
            session_id: Analysis session ID
            challenge_description: Description of the crypto challenge
        """
        return f"""# Cryptography Challenge Workflow

## Phase 1: Problem Analysis
1. Read challenge description carefully
2. Identify crypto algorithm/system:
   - RSA, AES, DES, XOR, Caesar cipher?
   - Hash functions (MD5, SHA, bcrypt)?
   - Custom encoding/encryption?

## Phase 2: Information Gathering
Based on algorithm type:

### RSA Challenges:
1. Extract n, e, c (modulus, exponent, ciphertext)
2. factordb_query(number=n)
   - Check if N is already factored
3. rsa_attack(session_id="{session_id}", n=n, e=e, c=c, attack="all")
   - Try Wiener, Fermat, Hastad, common modulus attacks

### Hash Challenges:
1. Identify hash type (length, format)
   - MD5: 32 hex chars
   - SHA1: 40 hex chars
   - SHA256: 64 hex chars
2. hashcat_crack(hash_value=hash, hash_type=<type>)
   - Use appropriate hash type code
3. john_crack(hash_file=path) as alternative

### Classical Ciphers:
1. Frequency analysis
2. Pattern recognition
3. Known plaintext attacks

### Custom Crypto:
1. sage_execute() for mathematical analysis
2. Look for weaknesses:
   - Small key space
   - Reused keys/IVs
   - ECB mode patterns
   - Weak randomness

## Phase 3: Tool Selection

### For RSA:
```python
# Example RsaCtfTool usage
session = create_analysis_session()
result = rsa_attack(
    session_id=session['session_id'],
    n="<large_number>",
    e="65537",
    c="<ciphertext>",
    attack="all"
)
```

### For Hashes:
```python
# Hashcat for fast cracking
hashcat_crack(
    hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
    hash_type="0",  # MD5
    wordlist="/usr/share/wordlists/rockyou.txt"
)
```

### For Mathematical Attacks:
```python
# SageMath for number theory
sage_script = '''
n = <modulus>
factors = factor(n)
print(factors)
'''
sage_execute(session_id=session_id, script=sage_script)
```

## Phase 4: Common Attack Patterns

### Weak RSA:
- e = 3 with small message (cube root attack)
- Common factors in multiple N values
- Wiener's attack (d < N^0.25)

### Hash Attacks:
- Dictionary/wordlist attacks
- Rainbow tables
- Length extension (MD5, SHA1)

### Block Cipher Attacks:
- ECB penguin detection
- Padding oracle attacks
- IV reuse

## Checklist
- [ ] Algorithm identified
- [ ] Parameters extracted
- [ ] Known attacks attempted
- [ ] Factorization checked
- [ ] Hashes cracked
- [ ] Custom analysis if needed
- [ ] Flag obtained
"""

    @mcp.prompt()
    def forensics_challenge_workflow(
        session_id: str,
        file_path: str = ""
    ) -> str:
        """
        Generate a forensics challenge solving workflow.

        Args:
            session_id: Analysis session ID
            file_path: Path to forensics artifact
        """
        return f"""# Forensics Challenge Workflow

## Phase 1: File Identification
1. Check file type:
   ```bash
   file {file_path}
   xxd {file_path} | head  # Check magic bytes
   ```

2. exiftool_analyze(file_path="{file_path}")
   - Extract metadata
   - Look for hidden info in EXIF

## Phase 2: Steganography Detection

### Image Files (JPG, PNG, BMP):
1. steghide_extract(cover_file="{file_path}")
   - Try without password first
   - Try common passwords: "password", "flag", "secret"

2. Check LSB steganography:
   ```python
   from PIL import Image
   img = Image.open("{file_path}")
   # Extract LSB from RGB channels
   ```

3. binwalk_analyze(file_path="{file_path}", extract=True, session_id="{session_id}")
   - Look for embedded files

### Audio Files (WAV, MP3):
1. Spectrogram analysis:
   ```bash
   sox audio.wav -n spectrogram
   ```

2. steghide_extract(cover_file="{file_path}")

## Phase 3: File Carving & Recovery
1. foremost_carve(session_id="{session_id}", file_path="{file_path}")
   - Recover deleted/hidden files

2. binwalk_analyze() for firmware:
   - Extract filesystems
   - Find embedded binaries

## Phase 4: Memory Forensics
If dealing with memory dump:

1. volatility_analyze(dump_file=path, plugin="windows.info")
   - Get system information

2. volatility_analyze(dump_file=path, plugin="windows.pslist")
   - List running processes

3. volatility_analyze(dump_file=path, plugin="windows.netscan")
   - Network connections

4. volatility_analyze(dump_file=path, plugin="windows.filescan")
   - Find interesting files

5. volatility_analyze(dump_file=path, plugin="windows.cmdline")
   - Command line arguments

## Phase 5: Document Analysis
For PDFs, Office docs:

1. exiftool_analyze() - metadata
2. binwalk_analyze() - embedded objects
3. strings command - hidden text
4. PDF streams analysis

## Phase 6: OCR & Visual Analysis
If flag is in image as text:

1. tesseract_ocr(image_path="{file_path}", lang="eng")
   - Extract visible text

2. Check for:
   - QR codes
   - Barcodes
   - Hidden patterns
   - Color channel separation

## Common Techniques

### Steganography:
- LSB encoding
- EOF data
- Metadata hiding
- Whitespace encoding

### File Analysis:
- Magic byte checking
- Entropy analysis
- String extraction
- Hex analysis

### Memory Forensics:
- Process analysis
- Network artifacts
- Registry hives
- Cached credentials

## Checklist
- [ ] File type identified
- [ ] Metadata extracted
- [ ] Steganography checked
- [ ] File carving performed
- [ ] Embedded files extracted
- [ ] Memory analyzed (if applicable)
- [ ] OCR performed (if applicable)
- [ ] Flag found
"""

    @mcp.prompt()
    def cloud_security_workflow(
        target_type: str = "aws",
        access_level: str = "anonymous"
    ) -> str:
        """
        Generate a cloud security testing workflow.

        Args:
            target_type: Cloud provider (aws, gcp, azure)
            access_level: Access level (anonymous, credentials, compromised)
        """
        return f"""# Cloud Security Testing Workflow - {target_type.upper()}

## Phase 1: Reconnaissance

### AWS Enumeration:
1. s3_bucket_scan(bucket_name=<target>)
   - Test for public S3 buckets
   - Common naming: company-backups, company-data, company-logs

2. s3_bucket_scan(wordlist="/path/to/bucket_names.txt")
   - Enumerate buckets from wordlist

3. cloud_metadata_query(provider="aws", endpoint="")
   - Check metadata service (SSRF exploitation)

### With AWS Credentials:
1. aws_enumerate(profile="default", service="s3", command="list")
   - List all S3 buckets

2. aws_enumerate(profile="default", service="ec2", command="list")
   - List EC2 instances

3. aws_enumerate(profile="default", service="iam", command="list")
   - List IAM users/roles

## Phase 2: Vulnerability Assessment

### S3 Misconfiguration:
- Public read/write access
- ACL misconfigurations
- Bucket policies allowing *

### IAM Issues:
- Overly permissive policies
- Hardcoded credentials
- Unused access keys

### Metadata Exploitation:
```bash
# SSRF to metadata service
cloud_metadata_query(provider="aws", endpoint="iam/security-credentials/")
```

## Phase 3: Exploitation (Authorized Testing Only)

### With Compromised Credentials:
1. pacu_aws_exploit(session_id=session, module="iam__enum_permissions")
   - Enumerate IAM permissions

2. pacu_aws_exploit(session_id=session, module="s3__download_bucket")
   - Download S3 bucket contents

3. pacu_aws_exploit(session_id=session, module="ec2__enum")
   - Enumerate EC2 resources

## Phase 4: Common Attack Vectors

### S3 Bucket Attacks:
1. Check for public access
2. Test object ACLs
3. Look for sensitive files:
   - .git directories
   - .env files
   - backup files
   - database dumps

### Metadata Service (SSRF):
```python
# From compromised instance/SSRF
endpoints = [
    "iam/security-credentials/",
    "iam/info",
    "identity-credentials/ec2/security-credentials/ec2-instance"
]

for endpoint in endpoints:
    result = cloud_metadata_query(provider="aws", endpoint=endpoint)
    print(result)
```

### IAM Privilege Escalation:
- PassRole to Lambda
- Update assume role policy
- Create access keys for other users

## Phase 5: GCP-Specific

### GCP Metadata:
```bash
cloud_metadata_query(
    provider="gcp",
    endpoint="instance/service-accounts/default/token"
)
```

### GCP Storage:
- Check GCS bucket permissions
- Look for public buckets

## Phase 6: Azure-Specific

### Azure Metadata:
```bash
cloud_metadata_query(
    provider="azure",
    endpoint=""
)
```

### Azure Storage:
- Check Blob storage permissions
- Test SAS tokens

## Tools Summary

### Anonymous Reconnaissance:
- s3_bucket_scan() - Find public S3 buckets
- cloud_metadata_query() - Metadata service

### With Credentials:
- aws_enumerate() - Resource enumeration
- pacu_aws_exploit() - Advanced exploitation

### Web Application Testing:
- Check for SSRF to metadata service
- Look for hardcoded credentials
- Test IAM role assumptions

## Checklist
- [ ] Public cloud resources enumerated
- [ ] S3/GCS/Blob storage checked
- [ ] Metadata service tested (if applicable)
- [ ] IAM permissions analyzed (with creds)
- [ ] Sensitive data identified
- [ ] Privilege escalation paths found
- [ ] Findings documented
"""

    @mcp.prompt()
    def web3_challenge_workflow(
        session_id: str,
        contract_address: str = "",
        network: str = "mainnet"
    ) -> str:
        """
        Generate a Web3/blockchain security testing workflow.

        Args:
            session_id: Analysis session ID
            contract_address: Smart contract address
            network: Blockchain network (mainnet, testnet, local)
        """
        return f"""# Web3 Smart Contract Security Workflow

## Phase 1: Contract Analysis

### Static Analysis:
1. slither_analyze(contract_path="/path/to/contract.sol")
   - Automated vulnerability detection
   - Check for common patterns:
     * Reentrancy
     * Integer overflow/underflow
     * Unchecked call return values
     * Access control issues

2. mythril_analyze(contract_path="/path/to/contract.sol", timeout=300)
   - Symbolic execution
   - Deep vulnerability analysis

### Manual Code Review:
Look for:
- Unchecked external calls
- Delegatecall to user-controlled address
- tx.origin authentication
- Block timestamp manipulation
- Front-running vulnerabilities

## Phase 2: Common Vulnerabilities

### Reentrancy:
```solidity
// Vulnerable pattern
function withdraw(uint amount) public {{
    require(balances[msg.sender] >= amount);
    msg.sender.call.value(amount)("");  // VULNERABLE
    balances[msg.sender] -= amount;
}}
```

### Integer Overflow/Underflow:
```solidity
// Before Solidity 0.8.0
uint256 balance = 0;
balance -= 1;  // Underflows to 2^256-1
```

### Access Control:
```solidity
// Missing modifier
function withdraw() public {{  // Should be onlyOwner
    msg.sender.transfer(balance);
}}
```

## Phase 3: Dynamic Analysis

### Compile Contract:
```python
result = solidity_compile(
    contract_path="/path/to/contract.sol",
    optimize=True
)
```

### Interact with Contract:
```python
script = '''
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('{network}'))
contract_address = "{contract_address}"
contract_abi = <abi_here>

contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Read contract state
balance = contract.functions.balanceOf(address).call()
print(f"Balance: {{balance}}")

# Call vulnerable function
tx = contract.functions.exploit().build_transaction({{
    'from': attacker_address,
    'nonce': w3.eth.get_transaction_count(attacker_address),
    'gas': 200000,
    'gasPrice': w3.eth.gas_price
}})

signed_tx = w3.eth.account.sign_transaction(tx, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
'''

web3_interact(session_id="{session_id}", script=script)
```

## Phase 4: Exploit Development

### Reentrancy Exploit:
```solidity
contract Attacker {{
    VulnerableContract target;

    function attack() public {{
        target.withdraw(1 ether);
    }}

    receive() external payable {{
        if (address(target).balance >= 1 ether) {{
            target.withdraw(1 ether);
        }}
    }}
}}
```

### Integer Overflow:
```solidity
// Exploit underflow
contract.transfer(address(0), 0);  // Balance becomes huge
```

## Phase 5: Testing Environment

### Local Blockchain:
```bash
# Ganache for local testing
ganache-cli --fork mainnet_url
```

### Test Exploit Locally:
1. Deploy contract to local chain
2. Test exploit script
3. Verify flag capture
4. Deploy to challenge network

## Phase 6: Common CTF Patterns

### Storage Manipulation:
- Direct storage writes
- Uninitialized storage pointers

### Delegatecall Vulnerabilities:
- Proxy contracts
- Library calls

### Blockchain Properties:
- Block hash prediction
- Timestamp manipulation
- Block number requirements

## Tools Checklist

### Static Analysis:
- [ ] slither_analyze() - Quick scan
- [ ] mythril_analyze() - Deep analysis
- [ ] Manual code review

### Compilation & Deployment:
- [ ] solidity_compile() - Get bytecode/ABI
- [ ] web3_interact() - Deploy/interact

### Exploitation:
- [ ] Exploit contract written
- [ ] Local testing completed
- [ ] Remote exploitation successful

## Common Vulnerability Checklist
- [ ] Reentrancy checked
- [ ] Integer overflow/underflow tested
- [ ] Access control verified
- [ ] External calls validated
- [ ] Delegatecall usage reviewed
- [ ] Storage layout analyzed
- [ ] Gas optimization issues noted
- [ ] Front-running possibilities assessed
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
