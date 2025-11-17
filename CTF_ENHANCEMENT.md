# CTF platform 고난이도 문제 해결을 위한 MCP Kali Server 고도화 방안

## 🎯 현재 시스템의 한계점

### 1. 상태 관리 부재
- **문제**: 각 API 호출이 독립적으로 실행되어 이전 컨텍스트를 유지하지 못함
- **영향**: 멀티스텝 익스플로잇, 인터랙티브 세션 불가
- **예시**: Pwnable 문제에서 바이너리 분석 → 익스플로잇 작성 → 실행 과정이 연결되지 않음

### 2. 바이너리 분석 도구 부족
- **문제**: 현재 웹 취약점 스캐닝 도구만 제공
- **부족한 도구**:
  - `pwntools` - Python 익스플로잇 프레임워크
  - `gdb` + `peda`/`gef`/`pwndbg` - 디버거
  - `radare2`/`ghidra` - 리버싱 도구
  - `ROPgadget`, `ropper` - ROP 체인 생성
  - `checksec` - 바이너리 보안 메커니즘 확인
  - `strace`, `ltrace` - 시스템/라이브러리 콜 추적

### 3. 인터랙티브 세션 미지원
- **문제**: netcat, ssh 등 대화형 프로그램 실행 불가
- **영향**: 원격 서버와 상호작용 필요한 문제 해결 불가
- **필요 기능**:
  - 양방향 통신 (stdin/stdout)
  - 세션 유지 및 재개
  - 타임아웃 관리

### 4. 파일 관리 시스템 부재
- **문제**: 바이너리/스크립트 업로드, 결과 다운로드 불가
- **필요 기능**:
  - 파일 업로드/다운로드 API
  - 작업 디렉토리 관리
  - 임시 파일 자동 정리
  - 바이너리 실행 권한 관리

### 5. 메모리 및 컨텍스트 관리 부재
- **문제**: AI가 이전 분석 결과를 재사용하지 못함
- **영향**: 중복 작업, 비효율적 문제 해결
- **필요 기능**:
  - 세션별 작업 공간
  - 중간 결과 저장/불러오기
  - 익스플로잇 스크립트 버전 관리

### 6. 고급 분석 기능 부족
- **문제**: 단순 명령 실행만 가능
- **필요 기능**:
  - 바이너리 자동 분석 (보호 기법, 취약점 탐지)
  - 메모리 덤프 분석
  - 암호 알고리즘 자동 식별
  - 패턴 인식 및 힌트 제공

---

## 🚀 고도화 방안

### Phase 1: 핵심 인프라 개선 (우선순위: 높음)

#### 1.1 세션 관리 시스템 구축

**구현 사항**:
```python
# kali_server.py에 추가
import uuid
from datetime import datetime, timedelta

class SessionManager:
    def __init__(self):
        self.sessions = {}  # session_id -> session_data

    def create_session(self, user_id: str) -> str:
        """새 세션 생성"""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
            "workspace": f"/tmp/mcp_session_{session_id}",
            "context": {},  # 분석 결과, 변수 등 저장
            "history": []   # 명령 히스토리
        }
        os.makedirs(self.sessions[session_id]["workspace"], exist_ok=True)
        return session_id

    def get_session(self, session_id: str) -> dict:
        """세션 데이터 조회"""
        return self.sessions.get(session_id)

    def update_context(self, session_id: str, key: str, value: any):
        """세션 컨텍스트 업데이트"""
        if session_id in self.sessions:
            self.sessions[session_id]["context"][key] = value

    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """오래된 세션 정리"""
        now = datetime.now()
        to_delete = []
        for sid, data in self.sessions.items():
            if now - data["created_at"] > timedelta(hours=max_age_hours):
                to_delete.append(sid)
                # 작업 공간 삭제
                import shutil
                shutil.rmtree(data["workspace"], ignore_errors=True)

        for sid in to_delete:
            del self.sessions[sid]

# API 엔드포인트
@app.route("/api/session/create", methods=["POST"])
def create_session():
    user_id = request.json.get("user_id", "anonymous")
    session_id = session_manager.create_session(user_id)
    return jsonify({"session_id": session_id, "success": True})

@app.route("/api/session/<session_id>/context", methods=["GET", "POST"])
def session_context(session_id):
    if request.method == "GET":
        session = session_manager.get_session(session_id)
        if session:
            return jsonify({"context": session["context"], "success": True})
        return jsonify({"error": "Session not found"}), 404

    elif request.method == "POST":
        key = request.json.get("key")
        value = request.json.get("value")
        session_manager.update_context(session_id, key, value)
        return jsonify({"success": True})
```

**MCP 도구 추가**:
```python
# src/my_server/mcp_server.py
@mcp.tool()
def create_analysis_session() -> Dict[str, Any]:
    """
    새로운 분석 세션을 생성합니다. 멀티스텝 분석이 필요한 경우 사용하세요.

    Returns:
        세션 ID와 작업 공간 경로
    """
    return kali_client.safe_post("api/session/create", {"user_id": "mcp_client"})

@mcp.tool()
def save_analysis_result(
    session_id: str,
    key: str,
    value: str
) -> Dict[str, Any]:
    """
    분석 결과를 세션에 저장합니다.

    Args:
        session_id: 세션 ID
        key: 저장할 데이터의 키 (예: "binary_protections", "exploit_script")
        value: 저장할 값
    """
    return kali_client.safe_post(f"api/session/{session_id}/context", {
        "key": key,
        "value": value
    })

@mcp.tool()
def load_analysis_result(
    session_id: str
) -> Dict[str, Any]:
    """
    세션에 저장된 분석 결과를 불러옵니다.

    Args:
        session_id: 세션 ID

    Returns:
        저장된 모든 컨텍스트 데이터
    """
    return kali_client.safe_get(f"api/session/{session_id}/context")
```

#### 1.2 파일 관리 시스템

**구현 사항**:
```python
# kali_server.py
import base64

@app.route("/api/file/upload", methods=["POST"])
def upload_file():
    """파일 업로드 (base64 인코딩)"""
    try:
        params = request.json
        session_id = params.get("session_id")
        filename = params.get("filename")
        content_base64 = params.get("content")
        executable = params.get("executable", False)

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 400

        # 파일 저장
        filepath = os.path.join(session["workspace"], filename)
        content = base64.b64decode(content_base64)

        with open(filepath, "wb") as f:
            f.write(content)

        # 실행 권한 부여
        if executable:
            os.chmod(filepath, 0o755)

        return jsonify({
            "success": True,
            "filepath": filepath,
            "size": len(content)
        })
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/download", methods=["POST"])
def download_file():
    """파일 다운로드 (base64 인코딩)"""
    try:
        params = request.json
        session_id = params.get("session_id")
        filename = params.get("filename")

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 400

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
    """세션 작업 공간의 파일 목록 조회"""
    try:
        params = request.json
        session_id = params.get("session_id")

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 400

        workspace = session["workspace"]
        files = []

        for root, dirs, filenames in os.walk(workspace):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                stat = os.stat(filepath)
                files.append({
                    "name": filename,
                    "path": filepath,
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
```

#### 1.3 인터랙티브 세션 관리

**구현 사항** (pexpect 사용):
```python
# kali_server.py
import pexpect
import threading

class InteractiveSession:
    def __init__(self, session_id: str, command: str):
        self.session_id = session_id
        self.command = command
        self.process = None
        self.output_buffer = []
        self.lock = threading.Lock()

    def start(self):
        """인터랙티브 프로세스 시작"""
        self.process = pexpect.spawn(self.command, encoding='utf-8')
        self.process.logfile_read = self  # output을 버퍼로 리다이렉트

    def write(self, text):
        """출력 버퍼에 추가 (logfile_read 인터페이스)"""
        with self.lock:
            self.output_buffer.append(text)

    def send(self, text: str):
        """입력 전송"""
        if self.process and self.process.isalive():
            self.process.send(text)

    def read_output(self, clear=True) -> str:
        """버퍼된 출력 읽기"""
        with self.lock:
            output = "".join(self.output_buffer)
            if clear:
                self.output_buffer = []
            return output

    def is_alive(self) -> bool:
        """프로세스 생존 확인"""
        return self.process and self.process.isalive()

    def close(self):
        """세션 종료"""
        if self.process:
            self.process.close()

# 인터랙티브 세션 매니저
interactive_sessions = {}

@app.route("/api/interactive/start", methods=["POST"])
def start_interactive():
    """인터랙티브 세션 시작"""
    try:
        params = request.json
        session_id = params.get("session_id")
        command = params.get("command")

        interactive_id = f"{session_id}_{len(interactive_sessions)}"
        interactive_session = InteractiveSession(session_id, command)
        interactive_session.start()
        interactive_sessions[interactive_id] = interactive_session

        return jsonify({
            "success": True,
            "interactive_id": interactive_id
        })
    except Exception as e:
        logger.error(f"Interactive start error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/interactive/send", methods=["POST"])
def send_interactive():
    """인터랙티브 세션에 입력 전송"""
    try:
        params = request.json
        interactive_id = params.get("interactive_id")
        text = params.get("text")

        if interactive_id not in interactive_sessions:
            return jsonify({"error": "Session not found"}), 404

        interactive_sessions[interactive_id].send(text)

        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Interactive send error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/interactive/read", methods=["POST"])
def read_interactive():
    """인터랙티브 세션 출력 읽기"""
    try:
        params = request.json
        interactive_id = params.get("interactive_id")

        if interactive_id not in interactive_sessions:
            return jsonify({"error": "Session not found"}), 404

        output = interactive_sessions[interactive_id].read_output()
        is_alive = interactive_sessions[interactive_id].is_alive()

        return jsonify({
            "success": True,
            "output": output,
            "is_alive": is_alive
        })
    except Exception as e:
        logger.error(f"Interactive read error: {str(e)}")
        return jsonify({"error": str(e)}), 500
```

---

### Phase 2: Pwnable 도구 추가 (우선순위: 높음)

#### 2.1 바이너리 분석 도구

**추가할 도구들**:
```python
@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """바이너리 보호 기법 확인"""
    try:
        params = request.json
        binary_path = params.get("binary_path")

        command = f"checksec --file={binary_path}"
        result = execute_command(command)

        # 결과 파싱
        protections = {
            "relro": "Partial RELRO" in result["stdout"] or "Full RELRO" in result["stdout"],
            "canary": "Canary found" in result["stdout"],
            "nx": "NX enabled" in result["stdout"],
            "pie": "PIE enabled" in result["stdout"],
            "rpath": "No RPATH" not in result["stdout"],
            "runpath": "No RUNPATH" not in result["stdout"]
        }

        result["protections"] = protections
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """ROP 가젯 검색"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        search = params.get("search", "")
        additional_args = params.get("additional_args", "")

        command = f"ROPgadget --binary {binary_path}"

        if search:
            command += f" --string '{search}'"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/radare2", methods=["POST"])
def radare2_analyze():
    """Radare2 바이너리 분석"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        r2_commands = params.get("commands", ["aaa", "pdf @ main"])

        # r2 명령을 파이프로 전달
        commands_str = "; ".join(r2_commands)
        command = f"r2 -q -c '{commands_str}' {binary_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/strace", methods=["POST"])
def strace_analyze():
    """시스템 콜 추적"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        arguments = params.get("arguments", "")

        command = f"strace -f -s 1000 {binary_path} {arguments}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/objdump", methods=["POST"])
def objdump_analyze():
    """바이너리 디스어셈블"""
    try:
        params = request.json
        binary_path = params.get("binary_path")
        mode = params.get("mode", "disassemble")  # disassemble, headers, symbols

        if mode == "disassemble":
            command = f"objdump -d -M intel {binary_path}"
        elif mode == "headers":
            command = f"objdump -h {binary_path}"
        elif mode == "symbols":
            command = f"objdump -t {binary_path}"
        else:
            return jsonify({"error": "Invalid mode"}), 400

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

#### 2.2 Pwntools 통합

**Python 스크립트 실행 기능**:
```python
@app.route("/api/tools/pwntools", methods=["POST"])
def run_pwntools():
    """Pwntools 스크립트 실행"""
    try:
        params = request.json
        session_id = params.get("session_id")
        script_content = params.get("script")
        script_name = params.get("script_name", "exploit.py")

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 400

        # 스크립트 저장
        script_path = os.path.join(session["workspace"], script_name)
        with open(script_path, "w") as f:
            f.write(script_content)

        # 실행
        command = f"cd {session['workspace']} && python3 {script_name}"
        result = execute_command(command)

        return jsonify(result)
    except Exception as e:
        logger.error(f"Pwntools execution error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/one_gadget", methods=["POST"])
def one_gadget():
    """One-gadget RCE 검색"""
    try:
        params = request.json
        libc_path = params.get("libc_path")

        command = f"one_gadget {libc_path}"
        result = execute_command(command)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

**MCP 도구 래퍼**:
```python
# src/my_server/mcp_server.py

@mcp.tool()
def checksec_binary(
    session_id: str,
    binary_filename: str
) -> Dict[str, Any]:
    """
    바이너리의 보호 기법을 확인합니다 (RELRO, Canary, NX, PIE 등).

    Args:
        session_id: 세션 ID
        binary_filename: 세션 작업공간 내의 바이너리 파일명

    Returns:
        활성화된 보호 기법 목록
    """
    session = kali_client.safe_get(f"api/session/{session_id}/context")
    workspace = session.get("workspace", "")
    binary_path = f"{workspace}/{binary_filename}"

    return kali_client.safe_post("api/tools/checksec", {"binary_path": binary_path})

@mcp.tool()
def find_rop_gadgets(
    session_id: str,
    binary_filename: str,
    search_string: str = ""
) -> Dict[str, Any]:
    """
    바이너리에서 ROP 가젯을 검색합니다.

    Args:
        session_id: 세션 ID
        binary_filename: 바이너리 파일명
        search_string: 특정 가젯 검색 (예: "pop rdi")

    Returns:
        발견된 ROP 가젯 목록
    """
    session = kali_client.safe_get(f"api/session/{session_id}/context")
    workspace = session.get("workspace", "")
    binary_path = f"{workspace}/{binary_filename}"

    return kali_client.safe_post("api/tools/ropgadget", {
        "binary_path": binary_path,
        "search": search_string
    })

@mcp.tool()
def analyze_with_radare2(
    session_id: str,
    binary_filename: str,
    commands: list[str] = ["aaa", "pdf @ main"]
) -> Dict[str, Any]:
    """
    Radare2로 바이너리를 분석합니다.

    Args:
        session_id: 세션 ID
        binary_filename: 바이너리 파일명
        commands: 실행할 r2 명령 리스트 (예: ["aaa", "pdf @ main", "iz"])

    Returns:
        Radare2 분석 결과
    """
    session = kali_client.safe_get(f"api/session/{session_id}/context")
    workspace = session.get("workspace", "")
    binary_path = f"{workspace}/{binary_filename}"

    return kali_client.safe_post("api/tools/radare2", {
        "binary_path": binary_path,
        "commands": commands
    })

@mcp.tool()
def run_pwntools_exploit(
    session_id: str,
    exploit_script: str,
    script_name: str = "exploit.py"
) -> Dict[str, Any]:
    """
    Pwntools 익스플로잇 스크립트를 실행합니다.

    Args:
        session_id: 세션 ID
        exploit_script: Python 익스플로잇 코드
        script_name: 저장할 스크립트 파일명

    Returns:
        익스플로잇 실행 결과
    """
    return kali_client.safe_post("api/tools/pwntools", {
        "session_id": session_id,
        "script": exploit_script,
        "script_name": script_name
    })

@mcp.tool()
def start_interactive_shell(
    session_id: str,
    command: str
) -> Dict[str, Any]:
    """
    인터랙티브 셸을 시작합니다 (nc, ssh 등).

    Args:
        session_id: 세션 ID
        command: 실행할 명령 (예: "nc 127.0.0.1 9000")

    Returns:
        인터랙티브 세션 ID
    """
    return kali_client.safe_post("api/interactive/start", {
        "session_id": session_id,
        "command": command
    })

@mcp.tool()
def send_to_interactive(
    interactive_id: str,
    text: str
) -> Dict[str, Any]:
    """
    인터랙티브 셸에 입력을 전송합니다.

    Args:
        interactive_id: 인터랙티브 세션 ID
        text: 전송할 텍스트 (개행 문자 포함 가능)

    Returns:
        전송 성공 여부
    """
    return kali_client.safe_post("api/interactive/send", {
        "interactive_id": interactive_id,
        "text": text
    })

@mcp.tool()
def read_interactive_output(
    interactive_id: str
) -> Dict[str, Any]:
    """
    인터랙티브 셸의 출력을 읽습니다.

    Args:
        interactive_id: 인터랙티브 세션 ID

    Returns:
        셸 출력 및 생존 여부
    """
    return kali_client.safe_post("api/interactive/read", {
        "interactive_id": interactive_id
    })
```

---

### Phase 3: Reversing 도구 추가

#### 3.1 디컴파일 및 정적 분석

**Ghidra 통합** (Ghidra Headless Analyzer 사용):
```python
@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra_analyze():
    """Ghidra 자동 분석"""
    try:
        params = request.json
        session_id = params.get("session_id")
        binary_filename = params.get("binary_filename")

        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid session"}), 400

        workspace = session["workspace"]
        binary_path = os.path.join(workspace, binary_filename)
        project_path = os.path.join(workspace, "ghidra_project")

        # Ghidra Headless 실행
        command = f"""
        analyzeHeadless {project_path} TempProject \
            -import {binary_path} \
            -postScript GhidraDecompile.py \
            -scriptPath /opt/ghidra_scripts
        """

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

#### 3.2 안티디버깅 탐지

```python
@app.route("/api/tools/detect_anti_debug", methods=["POST"])
def detect_anti_debug():
    """안티디버깅 기법 탐지"""
    try:
        params = request.json
        binary_path = params.get("binary_path")

        # 여러 도구 조합 사용
        commands = [
            f"strings {binary_path} | grep -i 'ptrace\\|debug\\|trace'",
            f"objdump -d {binary_path} | grep -i 'ptrace\\|int3'",
            f"rabin2 -zz {binary_path} | grep -i 'debug'"
        ]

        results = []
        for cmd in commands:
            result = execute_command(cmd)
            if result["stdout"]:
                results.append({
                    "command": cmd,
                    "findings": result["stdout"]
                })

        return jsonify({
            "success": True,
            "anti_debug_found": len(results) > 0,
            "findings": results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

---

### Phase 4: AI 강화 기능

#### 4.1 자동 익스플로잇 템플릿 생성

**MCP 프롬프트 추가**:
```python
@mcp.prompt()
def pwnable_workflow(
    session_id: str,
    binary_filename: str,
    target_host: str = "",
    target_port: int = 0
) -> str:
    """
    Pwnable 문제 해결 워크플로우를 생성합니다.

    Args:
        session_id: 분석 세션 ID
        binary_filename: 분석할 바이너리 파일명
        target_host: 원격 서버 주소 (옵션)
        target_port: 원격 서버 포트 (옵션)
    """
    return f"""# Pwnable 문제 해결 워크플로우 - {binary_filename}

## Phase 1: 바이너리 정보 수집
1. checksec_binary(session_id="{session_id}", binary_filename="{binary_filename}")
   - 보호 기법 확인 (NX, PIE, Canary, RELRO)

2. analyze_with_radare2(session_id="{session_id}", binary_filename="{binary_filename}",
   commands=["aaa", "afl", "pdf @ main", "iz", "izz"])
   - 함수 목록, main 함수 디스어셈블, 문자열 추출

3. run_command(session_id="{session_id}",
   command="file {binary_filename} && ldd {binary_filename}")
   - 파일 타입 및 의존 라이브러리 확인

## Phase 2: 취약점 분석
1. analyze_with_radare2(commands=["aaa", "pdf @ <vulnerable_func>"])
   - 의심되는 함수 상세 분석

2. 취약점 타입 판단:
   - Buffer Overflow: strcpy, gets, scanf 등 사용 여부
   - Format String: printf, sprintf 등에 사용자 입력 직접 전달
   - Use-After-Free: free 후 포인터 재사용
   - Integer Overflow: 산술 연산 시 경계 체크 없음

## Phase 3: 익스플로잇 전략 수립
보호 기법에 따른 우회 방법:
- **NX enabled**: ROP 체인 구성 필요
  → find_rop_gadgets(session_id="{session_id}", binary_filename="{binary_filename}")

- **PIE enabled**: 주소 릭 필요
  → 포맷 스트링 또는 다른 정보 노출 취약점 찾기

- **Canary enabled**: 카나리 릭 또는 우회 필요
  → 포맷 스트링으로 카나리 값 읽기

- **RELRO**: GOT overwrite 가능 여부 확인

## Phase 4: 익스플로잇 코드 작성
Pwntools 템플릿:
```python
from pwn import *

# 설정
binary = './{binary_filename}'
{'# 로컬 테스트' if not target_host else f'# 원격 서버: {target_host}:{target_port}'}

# 프로세스 시작
{'p = process(binary)' if not target_host else f'p = remote("{target_host}", {target_port})'}

# 바이너리 정보
elf = ELF(binary)
{'libc = ELF("./libc.so.6")  # 원격 서버 libc 버전 확인 필요' if target_host else ''}

# 익스플로잇 페이로드
payload = b''
payload += b'A' * offset  # 오프셋 계산 필요
# ... 페이로드 구성

# 전송
p.sendline(payload)

# 셸 획득
p.interactive()
```

## Phase 5: 실행 및 디버깅
1. run_pwntools_exploit(session_id="{session_id}", exploit_script=<작성한 코드>)
   - 로컬에서 테스트

2. 필요시 gdb로 디버깅:
   - start_interactive_shell(command="gdb ./{binary_filename}")
   - 브레이크포인트 설정 및 레지스터/메모리 확인

3. 성공 후 원격 서버 공략

## 주요 체크포인트
- [ ] 바이너리 보호 기법 확인 완료
- [ ] 취약 함수 식별 완료
- [ ] 취약점 타입 파악 완료
- [ ] 오프셋 계산 완료
- [ ] 필요한 주소 획득 (libc, gadgets 등)
- [ ] 익스플로잇 코드 작성 완료
- [ ] 로컬 테스트 성공
- [ ] 원격 서버 공략 성공
"""

@mcp.prompt()
def reversing_workflow(
    session_id: str,
    binary_filename: str
) -> str:
    """
    Reversing 문제 해결 워크플로우를 생성합니다.

    Args:
        session_id: 분석 세션 ID
        binary_filename: 분석할 바이너리 파일명
    """
    return f"""# Reversing 문제 해결 워크플로우 - {binary_filename}

## Phase 1: 기본 정보 수집
1. file, strings 분석
2. checksec으로 보호 기법 확인
3. 실행 테스트로 동작 파악

## Phase 2: 정적 분석
1. Radare2/Ghidra로 디컴파일
2. main 함수부터 코드 흐름 추적
3. 중요 함수 식별 (check_password, validate 등)
4. 암호화/난독화 로직 파악

## Phase 3: 동적 분석
1. strace/ltrace로 시스템/라이브러리 콜 추적
2. gdb로 실행 중 메모리/레지스터 확인
3. 안티디버깅 기법 우회

## Phase 4: 키/플래그 추출
1. 하드코딩된 키 찾기
2. 알고리즘 역계산
3. 브루트포스 (필요시)

## 사용할 도구
- analyze_with_radare2()
- run_command(command="strings", "ltrace", "strace")
- start_interactive_shell(command="gdb")
"""
```

#### 4.2 자동 패턴 인식

```python
@app.route("/api/analyze/auto_detect", methods=["POST"])
def auto_detect_vulnerability():
    """AI 기반 취약점 자동 탐지"""
    try:
        params = request.json
        session_id = params.get("session_id")
        binary_filename = params.get("binary_filename")

        session = session_manager.get_session(session_id)
        workspace = session["workspace"]
        binary_path = os.path.join(workspace, binary_filename)

        findings = {
            "protections": {},
            "dangerous_functions": [],
            "strings_of_interest": [],
            "potential_vulns": []
        }

        # 1. 보호 기법 확인
        checksec_result = execute_command(f"checksec --file={binary_path}")
        findings["protections"] = parse_checksec_output(checksec_result["stdout"])

        # 2. 위험 함수 탐지
        dangerous_funcs = ["strcpy", "gets", "sprintf", "scanf", "system", "exec"]
        for func in dangerous_funcs:
            result = execute_command(f"objdump -d {binary_path} | grep '{func}@'")
            if result["stdout"]:
                findings["dangerous_functions"].append(func)

        # 3. 흥미로운 문자열 검색
        strings_result = execute_command(f"strings {binary_path}")
        interesting_patterns = ["flag", "password", "key", "/bin/sh", "admin"]
        for pattern in interesting_patterns:
            if pattern in strings_result["stdout"].lower():
                findings["strings_of_interest"].append(pattern)

        # 4. 취약점 추론
        if "gets" in findings["dangerous_functions"]:
            findings["potential_vulns"].append({
                "type": "Buffer Overflow",
                "function": "gets",
                "severity": "HIGH",
                "description": "gets() 함수는 입력 길이를 제한하지 않아 버퍼 오버플로우 발생 가능"
            })

        if not findings["protections"].get("nx", True):
            findings["potential_vulns"].append({
                "type": "Shellcode Injection",
                "severity": "HIGH",
                "description": "NX가 비활성화되어 스택에서 코드 실행 가능"
            })

        return jsonify({
            "success": True,
            "findings": findings
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def parse_checksec_output(output: str) -> dict:
    """checksec 출력 파싱"""
    return {
        "relro": "Full RELRO" if "Full RELRO" in output else ("Partial RELRO" if "Partial RELRO" in output else "No RELRO"),
        "canary": "Canary found" in output,
        "nx": "NX enabled" in output,
        "pie": "PIE enabled" in output
    }
```

---

### Phase 5: Web 고급 취약점 도구

#### 5.1 고급 웹 도구 추가

```python
@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Fast web fuzzer"""
    try:
        params = request.json
        url = params.get("url")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = params.get("mode", "dir")  # dir, vhost, param
        additional_args = params.get("additional_args", "")

        if mode == "dir":
            command = f"ffuf -u {url}/FUZZ -w {wordlist}"
        elif mode == "vhost":
            command = f"ffuf -u {url} -H 'Host: FUZZ' -w {wordlist}"
        elif mode == "param":
            command = f"ffuf -u {url}?FUZZ=test -w {wordlist}"

        command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/jwt_tool", methods=["POST"])
def jwt_tool():
    """JWT 분석 및 공격"""
    try:
        params = request.json
        jwt_token = params.get("token")
        mode = params.get("mode", "decode")  # decode, crack, tamper
        wordlist = params.get("wordlist", "")

        if mode == "decode":
            command = f"jwt_tool {jwt_token}"
        elif mode == "crack":
            command = f"jwt_tool {jwt_token} -C -d {wordlist}"
        elif mode == "tamper":
            command = f"jwt_tool {jwt_token} -T"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/burp_proxy", methods=["POST"])
def configure_burp_proxy():
    """Burp Suite 프록시 설정 도우미"""
    # 실제 Burp Suite API와 연동하거나
    # curl에 프록시 옵션 추가하는 방식
    pass
```

---

## 📈 기대 효과

### 개선 전후 비교

| 기능 | 개선 전 | 개선 후 |
|------|---------|---------|
| **Pwnable 문제** | ❌ 분석 불가 | ✅ 자동 분석 + 익스플로잇 생성 |
| **Reversing** | ❌ 도구 없음 | ✅ Ghidra/r2 통합, 자동 디컴파일 |
| **멀티스텝 공격** | ❌ 불가능 | ✅ 세션 관리로 컨텍스트 유지 |
| **인터랙티브 셸** | ❌ 불가능 | ✅ pexpect 기반 양방향 통신 |
| **파일 관리** | ❌ 없음 | ✅ 업로드/다운로드/버전 관리 |
| **자동화 수준** | 🟡 단순 명령 실행 | 🟢 워크플로우 자동 생성 |

### CTF platform 문제 대응 능력

**현재 해결 가능한 난이도**: Easy ~ Medium (웹 위주)
**개선 후 해결 가능한 난이도**: Easy ~ Hard (Pwnable, Reversing 포함)

**해결 가능한 문제 유형**:
- ✅ Buffer Overflow (NX, ASLR, PIE 우회)
- ✅ Format String Bug
- ✅ Return-to-libc, ROP
- ✅ Heap Exploitation
- ✅ Reversing (기본 ~ 중급 난독화)
- ✅ 고급 웹 취약점 (SSRF, XXE, Deserialization)
- ✅ Crypto 기초 (XOR, 간단한 암호 분석)

---

## 🛠️ 구현 우선순위 및 로드맵

### Week 1-2: 핵심 인프라 (Must Have)
- [x] 세션 관리 시스템 구현
- [x] 파일 업로드/다운로드 API
- [x] 인터랙티브 세션 (pexpect)

### Week 3-4: Pwnable 도구 (Must Have)
- [x] checksec, ROPgadget 통합
- [x] Radare2 API 래퍼
- [x] Pwntools 스크립트 실행
- [x] strace, ltrace, objdump 지원

### Week 5-6: AI 강화 (Should Have)
- [x] 자동 취약점 탐지
- [x] Pwnable/Reversing 워크플로우 프롬프트
- [x] 익스플로잇 템플릿 자동 생성

### Week 7-8: 고급 기능 (Nice to Have)
- [ ] Ghidra Headless 통합
- [ ] GDB Python API 통합 (pwndbg)
- [ ] 자동 libc 버전 탐지
- [ ] Heap 익스플로잇 도구 (patchelf, ld preload)

### Week 9-10: 최적화 및 테스트
- [ ] CTF platform 문제 테스트 (난이도별)
- [ ] 성능 최적화 (캐싱, 병렬 처리)
- [ ] 문서화 및 예제 추가

---

## 💡 추가 아이디어

### 1. 문제 자동 분류 시스템
```python
@mcp.tool()
def classify_challenge(session_id: str, binary_filename: str) -> dict:
    """
    CTF 문제를 자동으로 분류합니다.

    Returns:
        {"category": "Pwnable", "sub_type": "Buffer Overflow", "difficulty": "Medium"}
    """
    # 바이너리 특성 분석하여 자동 분류
    pass
```

### 2. 익스플로잇 데이터베이스 연동
```python
@mcp.tool()
def search_exploit_db(keyword: str) -> dict:
    """ExploitDB에서 유사 익스플로잇 검색"""
    # searchsploit 통합
    pass
```

### 3. 자동 보고서 생성
```python
@mcp.tool()
def generate_writeup(session_id: str) -> str:
    """세션의 모든 활동을 기반으로 writeup 자동 생성"""
    # 실행한 명령, 발견한 취약점, 익스플로잇 코드 등을 정리
    pass
```

### 4. 학습 모드
```python
@mcp.resource("kali://learning/pwnable-basics")
def pwnable_tutorial() -> str:
    """Pwnable 기초 학습 자료"""
    return "Buffer Overflow, ROP, Format String 등의 기초 개념 설명"
```

---

## 🎓 사용 예시 (CTF platform Pwnable 문제)

### 시나리오: "basic_exploitation_001" 문제 해결

```python
# Step 1: 세션 생성
session = create_analysis_session()
session_id = session["session_id"]

# Step 2: 바이너리 업로드 (AI가 자동으로 base64 인코딩)
upload_file(session_id, "basic_exploitation_001", binary_content)

# Step 3: 자동 분석
protections = checksec_binary(session_id, "basic_exploitation_001")
# Output: {"nx": true, "pie": false, "canary": false, "relro": "Partial"}

auto_analysis = auto_detect_vulnerability(session_id, "basic_exploitation_001")
# Output: {"potential_vulns": [{"type": "Buffer Overflow", "function": "gets"}]}

# Step 4: 상세 분석
disasm = analyze_with_radare2(session_id, "basic_exploitation_001",
    ["aaa", "pdf @ main", "pdf @ vulnerable_func"])

# Step 5: ROP 가젯 검색 (NX 우회용)
gadgets = find_rop_gadgets(session_id, "basic_exploitation_001")

# Step 6: 익스플로잇 작성 (AI가 자동 생성)
exploit_code = """
from pwn import *

p = remote('host.CTF.games', 12345)
elf = ELF('./basic_exploitation_001')

# 오프셋: 72 (AI가 자동 계산)
payload = b'A' * 72
payload += p64(elf.symbols['win'])  # win 함수 주소

p.sendline(payload)
p.interactive()
"""

# Step 7: 익스플로잇 실행
result = run_pwntools_exploit(session_id, exploit_code)

# Step 8: 성공 시 플래그 획득
# Output: "DH{y0u_h4ck3d_th3_b1n4ry!}"
```

---

## 🔐 보안 고려사항

### 추가 개선 사항

1. **샌드박스 환경**
   - Docker 컨테이너로 각 세션 격리
   - 리소스 제한 (CPU, 메모리, 디스크)
   - 네트워크 격리 (필요시에만 외부 통신 허용)

2. **인증 및 권한**
   - API 키 기반 인증
   - 세션별 권한 관리
   - 민감한 명령 실행 시 추가 확인

3. **감사 로그**
   - 모든 명령 실행 기록
   - 파일 업로드/다운로드 로그
   - 익스플로잇 시도 추적

---

## 📚 참고 자료

- **Pwntools Documentation**: https://docs.pwntools.com/
- **Radare2 Book**: https://book.rada.re/
- **Ghidra**: https://ghidra-sre.org/
- **CTF platform**: https://CTF.io/
- **CTF Wiki**: https://ctf-wiki.org/

---

**작성일**: 2025-11-17
**버전**: 1.0
**상태**: 설계 완료, 구현 대기
