#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import uuid
import base64
import shutil
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
import pexpect

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result

    Args:
        command: The command to execute

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


class SessionManager:
    """Manage analysis sessions with persistent workspaces"""

    def __init__(self):
        self.sessions = {}  # session_id -> session_data
        self.base_workspace = "/tmp/mcp_sessions"
        os.makedirs(self.base_workspace, exist_ok=True)
        logger.info(f"SessionManager initialized with workspace: {self.base_workspace}")

    def create_session(self, user_id: str = "anonymous") -> str:
        """Create a new analysis session"""
        session_id = str(uuid.uuid4())
        workspace = os.path.join(self.base_workspace, f"session_{session_id}")

        self.sessions[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
            "workspace": workspace,
            "context": {},  # Store analysis results, variables, etc.
            "history": []   # Command history
        }

        os.makedirs(workspace, exist_ok=True)
        logger.info(f"Created session {session_id} for user {user_id}")

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data"""
        return self.sessions.get(session_id)

    def update_context(self, session_id: str, key: str, value: Any):
        """Update session context"""
        if session_id in self.sessions:
            self.sessions[session_id]["context"][key] = value
            logger.debug(f"Updated context for session {session_id}: {key}")

    def add_to_history(self, session_id: str, command: str, result: Dict):
        """Add command to session history"""
        if session_id in self.sessions:
            self.sessions[session_id]["history"].append({
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "success": result.get("success", False)
            })

    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Clean up old sessions"""
        now = datetime.now()
        to_delete = []

        for sid, data in self.sessions.items():
            if now - data["created_at"] > timedelta(hours=max_age_hours):
                to_delete.append(sid)
                # Remove workspace
                try:
                    shutil.rmtree(data["workspace"], ignore_errors=True)
                    logger.info(f"Cleaned up old session {sid}")
                except Exception as e:
                    logger.error(f"Error cleaning up session {sid}: {str(e)}")

        for sid in to_delete:
            del self.sessions[sid]

    def delete_session(self, session_id: str) -> bool:
        """Manually delete a session"""
        if session_id in self.sessions:
            try:
                shutil.rmtree(self.sessions[session_id]["workspace"], ignore_errors=True)
                del self.sessions[session_id]
                logger.info(f"Deleted session {session_id}")
                return True
            except Exception as e:
                logger.error(f"Error deleting session {session_id}: {str(e)}")
                return False
        return False


class InteractiveSession:
    """Handle interactive shell sessions with pexpect"""

    def __init__(self, session_id: str, command: str):
        self.session_id = session_id
        self.command = command
        self.process = None
        self.output_buffer = []
        self.lock = threading.Lock()

    def start(self):
        """Start the interactive process"""
        try:
            self.process = pexpect.spawn(
                self.command,
                encoding='utf-8',
                timeout=300,
                echo=False
            )
            # Capture output in a thread
            self.output_thread = threading.Thread(target=self._capture_output, daemon=True)
            self.output_thread.start()
            logger.info(f"Started interactive session for {self.session_id}: {self.command}")
        except Exception as e:
            logger.error(f"Failed to start interactive session: {str(e)}")
            raise

    def _capture_output(self):
        """Continuously capture output from the process"""
        try:
            while self.is_alive():
                try:
                    line = self.process.read_nonblocking(size=1024, timeout=0.1)
                    if line:
                        with self.lock:
                            self.output_buffer.append(line)
                except pexpect.TIMEOUT:
                    continue
                except pexpect.EOF:
                    break
        except Exception as e:
            logger.error(f"Error capturing output: {str(e)}")

    def send(self, text: str):
        """Send input to the process"""
        if self.process and self.is_alive():
            self.process.send(text)
            logger.debug(f"Sent to interactive session: {text[:50]}...")

    def read_output(self, clear: bool = True) -> str:
        """Read buffered output"""
        with self.lock:
            output = "".join(self.output_buffer)
            if clear:
                self.output_buffer = []
            return output

    def is_alive(self) -> bool:
        """Check if process is still running"""
        return self.process and self.process.isalive()

    def close(self):
        """Close the session"""
        if self.process:
            try:
                self.process.close(force=True)
                logger.info(f"Closed interactive session for {self.session_id}")
            except Exception as e:
                logger.error(f"Error closing interactive session: {str(e)}")


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# ============================================================================
# SESSION MANAGEMENT ENDPOINTS
# ============================================================================

@app.route("/api/session/create", methods=["POST"])
def create_session():
    """Create a new analysis session"""
    try:
        params = request.json or {}
        user_id = params.get("user_id", "anonymous")
        session_id = session_manager.create_session(user_id)

        session = session_manager.get_session(session_id)
        return jsonify({
            "success": True,
            "session_id": session_id,
            "workspace": session["workspace"]
        })
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/session/<session_id>/context", methods=["GET", "POST"])
def session_context(session_id):
    """Get or update session context"""
    try:
        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Session not found"}), 404

        if request.method == "GET":
            return jsonify({
                "success": True,
                "context": session["context"],
                "workspace": session["workspace"],
                "created_at": session["created_at"].isoformat()
            })

        elif request.method == "POST":
            params = request.json
            key = params.get("key")
            value = params.get("value")

            if not key:
                return jsonify({"error": "Key is required"}), 400

            session_manager.update_context(session_id, key, value)
            return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Error in session context: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/session/<session_id>/delete", methods=["POST"])
def delete_session(session_id):
    """Delete a session"""
    try:
        success = session_manager.delete_session(session_id)
        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Session not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting session: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# FILE MANAGEMENT ENDPOINTS
# ============================================================================

@app.route("/api/file/upload", methods=["POST"])
def upload_file():
    """Upload a file to session workspace (base64 encoded)"""
    try:
        params = request.json
        session_id = params.get("session_id")
        filename = params.get("filename")
        content_base64 = params.get("content")
        executable = params.get("executable", False)

        if not all([session_id, filename, content_base64]):
            return jsonify({"error": "session_id, filename, and content are required"}), 400

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        # Decode and save file
        filepath = os.path.join(session["workspace"], filename)
        content = base64.b64decode(content_base64)

        with open(filepath, "wb") as f:
            f.write(content)

        # Set executable permission if requested
        if executable:
            os.chmod(filepath, 0o755)

        logger.info(f"Uploaded file {filename} to session {session_id}")

        return jsonify({
            "success": True,
            "filepath": filepath,
            "size": len(content),
            "executable": executable
        })
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/file/download", methods=["POST"])
def download_file():
    """Download a file from session workspace (base64 encoded)"""
    try:
        params = request.json
        session_id = params.get("session_id")
        filename = params.get("filename")

        if not all([session_id, filename]):
            return jsonify({"error": "session_id and filename are required"}), 400

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        filepath = os.path.join(session["workspace"], filename)

        if not os.path.exists(filepath):
            return jsonify({"error": "File not found"}), 404

        with open(filepath, "rb") as f:
            content = f.read()

        return jsonify({
            "success": True,
            "filename": filename,
            "content": base64.b64encode(content).decode('utf-8'),
            "size": len(content)
        })
    except Exception as e:
        logger.error(f"File download error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/file/list", methods=["POST"])
def list_files():
    """List files in session workspace"""
    try:
        params = request.json
        session_id = params.get("session_id")

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        workspace = session["workspace"]
        files = []

        for root, dirs, filenames in os.walk(workspace):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                stat = os.stat(filepath)
                relative_path = os.path.relpath(filepath, workspace)

                files.append({
                    "name": filename,
                    "path": relative_path,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "executable": os.access(filepath, os.X_OK)
                })

        return jsonify({
            "success": True,
            "workspace": workspace,
            "files": files
        })
    except Exception as e:
        logger.error(f"File list error: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# INTERACTIVE SESSION ENDPOINTS
# ============================================================================

@app.route("/api/interactive/start", methods=["POST"])
def start_interactive():
    """Start an interactive shell session"""
    try:
        params = request.json
        session_id = params.get("session_id")
        command = params.get("command")

        if not all([session_id, command]):
            return jsonify({"error": "session_id and command are required"}), 400

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        # Create interactive session ID
        interactive_id = f"{session_id}_{len(interactive_sessions)}"

        # Start interactive session
        interactive_session = InteractiveSession(session_id, command)
        interactive_session.start()
        interactive_sessions[interactive_id] = interactive_session

        logger.info(f"Started interactive session {interactive_id}")

        return jsonify({
            "success": True,
            "interactive_id": interactive_id
        })
    except Exception as e:
        logger.error(f"Interactive start error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/interactive/send", methods=["POST"])
def send_interactive():
    """Send input to an interactive session"""
    try:
        params = request.json
        interactive_id = params.get("interactive_id")
        text = params.get("text")

        if not all([interactive_id, text is not None]):
            return jsonify({"error": "interactive_id and text are required"}), 400

        if interactive_id not in interactive_sessions:
            return jsonify({"error": "Interactive session not found"}), 404

        interactive_sessions[interactive_id].send(text)

        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Interactive send error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/interactive/read", methods=["POST"])
def read_interactive():
    """Read output from an interactive session"""
    try:
        params = request.json
        interactive_id = params.get("interactive_id")

        if not interactive_id:
            return jsonify({"error": "interactive_id is required"}), 400

        if interactive_id not in interactive_sessions:
            return jsonify({"error": "Interactive session not found"}), 404

        interactive_session = interactive_sessions[interactive_id]
        output = interactive_session.read_output()
        is_alive = interactive_session.is_alive()

        return jsonify({
            "success": True,
            "output": output,
            "is_alive": is_alive
        })
    except Exception as e:
        logger.error(f"Interactive read error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/interactive/close", methods=["POST"])
def close_interactive():
    """Close an interactive session"""
    try:
        params = request.json
        interactive_id = params.get("interactive_id")

        if not interactive_id:
            return jsonify({"error": "interactive_id is required"}), 400

        if interactive_id not in interactive_sessions:
            return jsonify({"error": "Interactive session not found"}), 404

        interactive_sessions[interactive_id].close()
        del interactive_sessions[interactive_id]

        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Interactive close error: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ============================================================================
# PWNABLE TOOLS ENDPOINTS
# ============================================================================

@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check binary security protections"""
    try:
        params = request.json
        binary_path = params.get("binary_path")

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        command = f"checksec --file={binary_path}"
        result = execute_command(command)

        # Parse protections
        output = result["stdout"]
        protections = {
            "relro": "Full RELRO" if "Full RELRO" in output else ("Partial RELRO" if "Partial RELRO" in output else "No RELRO"),
            "canary": "Canary found" in output,
            "nx": "NX enabled" in output,
            "pie": "PIE enabled" in output,
            "rpath": "No RPATH" not in output,
            "runpath": "No RUNPATH" not in output,
            "symbols": "No Symbols" not in output,
            "fortify": "Fortify" in output
        }

        result["protections"] = protections
        return jsonify(result)
    except Exception as e:
        logger.error(f"Checksec error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Find ROP gadgets in binary"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        search = params.get("search", "")
        additional_args = params.get("additional_args", "")

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        command = f"ROPgadget --binary {binary_path}"

        if search:
            command += f" --string '{search}'"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"ROPgadget error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/radare2", methods=["POST"])
def radare2_analyze():
    """Analyze binary with radare2"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        commands = params.get("commands", ["aaa", "pdf @ main"])

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        # Join r2 commands
        commands_str = "; ".join(commands)
        command = f"r2 -q -c '{commands_str}' {binary_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Radare2 error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/objdump", methods=["POST"])
def objdump_analyze():
    """Disassemble binary with objdump"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        mode = params.get("mode", "disassemble")

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        if mode == "disassemble":
            command = f"objdump -d -M intel {binary_path}"
        elif mode == "headers":
            command = f"objdump -h {binary_path}"
        elif mode == "symbols":
            command = f"objdump -t {binary_path}"
        elif mode == "all":
            command = f"objdump -x {binary_path}"
        else:
            return jsonify({"error": "Invalid mode"}), 400

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Objdump error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/strace", methods=["POST"])
def strace_analyze():
    """Trace system calls"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        arguments = params.get("arguments", "")

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        command = f"strace -f -s 1000 {binary_path} {arguments}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Strace error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/ltrace", methods=["POST"])
def ltrace_analyze():
    """Trace library calls"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        arguments = params.get("arguments", "")

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        command = f"ltrace -s 1000 {binary_path} {arguments}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ltrace error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/pwntools", methods=["POST"])
def run_pwntools():
    """Execute pwntools script"""
    try:
        params = request.json
        session_id = params.get("session_id")
        script_content = params.get("script")
        script_name = params.get("script_name", "exploit.py")

        if not all([session_id, script_content]):
            return jsonify({"error": "session_id and script are required"}), 400

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        # Save script
        script_path = os.path.join(session["workspace"], script_name)
        with open(script_path, "w") as f:
            f.write(script_content)

        # Execute
        command = f"cd {session['workspace']} && python3 {script_name}"
        result = execute_command(command)

        return jsonify(result)
    except Exception as e:
        logger.error(f"Pwntools execution error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/strings", methods=["POST"])
def strings_analyze():
    """Extract strings from binary"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        min_length = params.get("min_length", 4)

        if not binary_path:
            return jsonify({"error": "binary_path is required"}), 400

        command = f"strings -n {min_length} {binary_path}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Strings error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/auto_detect", methods=["POST"])
def auto_detect_vulnerability():
    """AI-powered automatic vulnerability detection"""
    try:
        params = request.json
        session_id = params.get("session_id")
        binary_filename = params.get("binary_filename")

        if not all([session_id, binary_filename]):
            return jsonify({"error": "session_id and binary_filename are required"}), 400

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 404

        workspace = session["workspace"]
        binary_path = os.path.join(workspace, binary_filename)

        if not os.path.exists(binary_path):
            return jsonify({"error": "Binary not found"}), 404

        findings = {
            "protections": {},
            "dangerous_functions": [],
            "strings_of_interest": [],
            "potential_vulns": []
        }

        # 1. Check security protections
        checksec_result = execute_command(f"checksec --file={binary_path}")
        output = checksec_result["stdout"]
        findings["protections"] = {
            "relro": "Full RELRO" if "Full RELRO" in output else ("Partial RELRO" if "Partial RELRO" in output else "No RELRO"),
            "canary": "Canary found" in output,
            "nx": "NX enabled" in output,
            "pie": "PIE enabled" in output
        }

        # 2. Find dangerous functions
        dangerous_funcs = ["strcpy", "gets", "sprintf", "scanf", "system", "exec", "popen"]
        objdump_result = execute_command(f"objdump -d {binary_path}")
        for func in dangerous_funcs:
            if f"{func}@" in objdump_result["stdout"] or f"call.*{func}" in objdump_result["stdout"]:
                findings["dangerous_functions"].append(func)

        # 3. Find interesting strings
        strings_result = execute_command(f"strings {binary_path}")
        interesting_patterns = ["flag", "password", "key", "/bin/sh", "admin", "secret"]
        for pattern in interesting_patterns:
            if pattern in strings_result["stdout"].lower():
                findings["strings_of_interest"].append(pattern)

        # 4. Infer vulnerabilities
        if "gets" in findings["dangerous_functions"]:
            findings["potential_vulns"].append({
                "type": "Buffer Overflow",
                "function": "gets",
                "severity": "HIGH",
                "description": "gets() does not check input length, allowing buffer overflow"
            })

        if "strcpy" in findings["dangerous_functions"] or "sprintf" in findings["dangerous_functions"]:
            findings["potential_vulns"].append({
                "type": "Buffer Overflow",
                "function": "strcpy/sprintf",
                "severity": "MEDIUM",
                "description": "Unsafe string copy functions without bounds checking"
            })

        if not findings["protections"].get("nx", True):
            findings["potential_vulns"].append({
                "type": "Shellcode Injection",
                "severity": "HIGH",
                "description": "NX disabled - stack is executable, shellcode injection possible"
            })

        if not findings["protections"].get("canary", False) and findings["dangerous_functions"]:
            findings["potential_vulns"].append({
                "type": "Stack Smashing",
                "severity": "HIGH",
                "description": "No stack canary and dangerous functions present"
            })

        if "system" in findings["dangerous_functions"] or "/bin/sh" in findings["strings_of_interest"]:
            findings["potential_vulns"].append({
                "type": "Command Injection / Shell Spawn",
                "severity": "HIGH",
                "description": "Binary uses system() or contains /bin/sh string"
            })

        # Save to context
        session_manager.update_context(session_id, "auto_analysis", findings)

        return jsonify({
            "success": True,
            "findings": findings
        })
    except Exception as e:
        logger.error(f"Auto detect error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass


# ============================================================================
# INITIALIZATION
# ============================================================================

# Initialize global managers
session_manager = SessionManager()
interactive_sessions = {}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
