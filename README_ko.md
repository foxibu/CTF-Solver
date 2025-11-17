# 🛡️ MCP Kali Server

<div align="center">

**AI 기반 공격적 보안 도구킷**

Model Context Protocol을 통해 AI 어시스턴트를 55개 이상의 Kali Linux 보안 도구와 연결하세요

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg?logo=docker&logoColor=white)](#-docker-배포)
[![Security Tools](https://img.shields.io/badge/Security_Tools-55+-green.svg)](KALI_TOOLS_INSTALLATION.md)
[![CTF Categories](https://img.shields.io/badge/CTF_Categories-7-orange.svg)](#-지원되는-ctf-카테고리)

[기능](#-기능) • [빠른 시작](#-빠른-시작) • [문서](#-문서) • [아키텍처](#-아키텍처) • [법적 고지](#%EF%B8%8F-법적-고지)

**언어**: [English](README.md) | **한국어**

</div>

---

## 📖 개요

**MCP Kali Server**는 Kali Linux의 전문적인 침투 테스트 및 CTF 문제 해결 도구에 원활하게 접근할 수 있게 하여 AI 어시스턴트를 강력한 공격적 보안 동반자로 변환합니다.

**Model Context Protocol (MCP)**을 기반으로 구축된 이 서버는 Claude, ChatGPT 등의 AI 어시스턴트가 복잡한 보안 워크플로우를 조율하고, CTF 챌린지 해결을 자동화하며, 자연어를 통해 지능적인 침투 테스트를 수행할 수 있게 합니다.

### 🎯 무엇을 할 수 있나요?

```
사용자: "RSA 문제가 있어요: n=12345..., e=65537. 복호화할 수 있나요?"

AI: *자동으로 FactorDB 조회 → RsaCtfTool 실행 → 암호문 복호화 → 플래그 추출*
    "플래그 발견: CTF{...}"
```

```
사용자: "이 웹 앱의 취약점을 스캔해주세요: http://target.com"

AI: *nmap 실행 → gobuster → nikto → sqlmap → 종합 보안 보고서 제공*
```

---

## ✨ 기능

### 🎓 **7개 주요 CTF 카테고리 지원**

<table>
<tr>
<td width="50%">

**🔓 Pwnable** (80% 커버리지)
- 버퍼 오버플로우 익스플로잇
- ROP 체인 구축
- 포맷 스트링 공격
- 힙 익스플로잇
- 도구: `checksec`, `ROPgadget`, `pwntools`, `radare2`

**🔐 암호학** (50-80% 커버리지)
- RSA 공격 (인수분해, Wiener, Hastad)
- 해시 크래킹 (MD5, SHA, bcrypt)
- 수학적 암호 분석
- 도구: `hashcat`, `RsaCtfTool`, `SageMath`, `john`

**🔍 포렌식** (43-70% 커버리지)
- **자동화된 메모리 분석** (Volatility 워크플로우)
- **자동화된 디스크 포렌식** (SleuthKit 워크플로우)
- **자동화된 멀웨어 헌팅** (YARA + IOC 추출)
- 메모리 덤프 분석 및 스테가노그래피 탐지
- 파일 카빙 및 복구
- 도구: `Volatility3`, `SleuthKit`, `YARA`, `binwalk`, `steghide`, `foremost`

**🌐 웹 보안** (90% 커버리지)
- SQL 인젝션 테스트
- 디렉터리 열거
- 취약점 스캔
- 도구: `sqlmap`, `gobuster`, `nikto`, `wpscan`

</td>
<td width="50%">

**☁️ 클라우드 보안** (52-85% 커버리지)
- AWS/GCP/Azure 열거
- S3 버킷 스캔
- IAM 권한 상승
- 도구: `aws-cli`, `pacu`, `s3scanner`

**⛓️ Web3 & 블록체인** (40-75% 커버리지)
- 스마트 컨트랙트 분석
- 재진입 공격
- 정수 오버플로우 탐지
- 도구: `Slither`, `Mythril`, `web3.py`, `solc`

**🔄 리버싱** (67% 커버리지)
- 바이너리 디스어셈블리
- 동적 분석
- 난독화 해제
- 도구: `radare2`, `ltrace`, `strace`, `objdump`

</td>
</tr>
</table>

### 🛠️ **55개 이상의 전문 보안 도구**

- **네트워크 정찰**: nmap, masscan, enum4linux
- **웹 테스트**: gobuster, dirb, nikto, sqlmap, wpscan, ffuf
- **비밀번호 공격**: hydra, john, hashcat
- **바이너리 분석**: checksec, ROPgadget, radare2, pwntools, Ghidra
- **포렌식**: Volatility3, SleuthKit (mmls, fls, mactime), YARA, binwalk, foremost, steghide, exiftool, tesseract, md5deep
- **암호학**: RsaCtfTool, SageMath, hashcat, openssl
- **클라우드**: AWS CLI, Pacu, s3scanner, ScoutSuite
- **Web3**: Slither, Mythril, web3.py, solc, Ganache
- **익스플로잇**: metasploit, searchsploit
- **그 외 다수...**

### 🤖 **AI 기반 자동화**

- **자동 취약점 탐지**: AI가 바이너리를 분석하고 익스플로잇 가능한 약점 식별
- **다단계 공격 체인**: 복잡한 익스플로잇 워크플로우 조율
- **자동화된 포렌식 워크플로우**: 다단계 메모리 분석, 디스크 포렌식, 멀웨어 헌팅
- **세션 관리**: 다단계 분석을 위한 영구 작업 공간
- **대화형 셸**: 실행 중인 익스플로잇과 양방향 통신
- **지능적 도구 선택**: AI가 컨텍스트에 따라 적절한 도구 선택

### 📚 **종합 가이드**

- **워크플로우 프롬프트**: 일반적인 CTF 시나리오를 위한 사전 구축 템플릿
- **문제 해결 가이드**: 각 카테고리별 즉시 사용 가능한 프롬프트
- **도구 설치**: Kali Linux용 자동화된 설정 스크립트
- **모범 사례**: 보안 테스트 지침 및 윤리

---

## 🚀 빠른 시작

### 사전 요구사항

**옵션 1: Docker (권장)** 🐳
- **Docker** 및 **Docker Compose** 설치
- **MCP 지원 AI 어시스턴트** (Claude Desktop, 5ire 등)

**옵션 2: 네이티브 설치**
- **Kali Linux** (또는 보안 도구가 설치된 Linux)
- **Python 3.12+**
- **MCP 지원 AI 어시스턴트** (Claude Desktop, 5ire 등)

---

### 옵션 1: Docker 설치 (권장) 🐳

**한 줄 명령어 설정 - 모든 도구 포함!**

**1. 클론 및 시작**
```bash
git clone https://github.com/foxibu/CTF-Solver.git
cd CTF-Solver
docker-compose up -d
```

이게 전부입니다! 서버가 이제 `http://localhost:5000`에서 55개 이상의 보안 도구가 사전 설치된 상태로 실행됩니다.

**2. MCP 클라이언트 구성**

**Claude Desktop의 경우** (`~/.config/Claude/claude_desktop_config.json` 편집):
```json
{
  "mcpServers": {
    "kali_mcp": {
      "command": "python3",
      "args": [
        "/절대/경로/src/my_server/mcp_server.py",
        "--server",
        "http://localhost:5000/"
      ]
    }
  }
}
```

**3. CTF 문제 해결 시작!** 🎉

---

### 옵션 2: 네이티브 설치

**1. 저장소 클론**
```bash
git clone https://github.com/foxibu/CTF-Solver.git
cd CTF-Solver
```

**2. 의존성 설치**
```bash
pip install -e .
# 또는 더 빠른 설치를 위해 uv 사용
uv pip install -e .
```

**3. 보안 도구 설치** ([KALI_TOOLS_INSTALLATION.md](KALI_TOOLS_INSTALLATION.md) 참조)
```bash
# 필수 도구 빠른 설치
sudo apt install -y nmap gobuster dirb nikto sqlmap wpscan hydra john \
    checksec binwalk steghide volatility3 radare2

# 완전한 설정은 설치 가이드 참조
```

**4. Kali 서버 시작**
```bash
python3 kali_server.py
# 서버가 http://0.0.0.0:5000 에서 실행됩니다
```

**5. MCP 클라이언트 구성**

**Claude Desktop의 경우** (`~/.config/Claude/claude_desktop_config.json` 편집):
```json
{
  "mcpServers": {
    "kali_mcp": {
      "command": "python3",
      "args": [
        "/절대/경로/src/my_server/mcp_server.py",
        "--server",
        "http://KALI_IP:5000/"
      ]
    }
  }
}
```

**5ire Desktop의 경우**:
- 명령어로 MCP 서버 추가: `python3 /경로/src/my_server/mcp_server.py --server http://KALI_IP:5000`

**6. CTF 문제 해결 시작!** 🎉

---

## 🏗️ 아키텍처

```
┌─────────────────────┐         HTTP/JSON        ┌─────────────────────┐
│  MCP 클라이언트      │◄──────────────────────────│  Kali Linux 서버    │
│  (Claude Desktop,   │        Port 5000          │  (Flask API)        │
│   5ire 등)          │                           │                     │
│                     │                           │  - 명령 실행기      │
│  - FastMCP 서버     │                           │  - 도구 엔드포인트  │
│  - 도구 정의        │                           │  - 세션 관리자      │
│  - 워크플로우 프롬프트│                          │  - 타임아웃 핸들러  │
└─────────────────────┘                           └─────────────────────┘
     Windows/Mac/Linux                                Kali Linux
```

### 구성 요소

**Kali 서버** (`kali_server.py`)
- Flask HTTP API 서버 (포트 5000)
- 73개 이상의 보안 도구 엔드포인트
- 고급 포렌식 자동화 (메모리, 디스크, 멀웨어)
- 세션 기반 작업 공간
- 대화형 셸 관리
- 우아한 타임아웃 처리 (기본 180초)

**MCP 클라이언트** (`src/my_server/mcp_server.py`)
- FastMCP 프로토콜 구현
- 55개 이상의 MCP 도구 래퍼
- AI 가이드 워크플로우 프롬프트
- 리소스 (서버 상태, 워드리스트, 가이드)

---

## 💡 사용 예시

### 예시 1: RSA 암호학 챌린지

```
사용자: "RSA 문제가 있어요:
       n = 85188995949975973...
       e = 65537
       c = 34577152691579622...
       복호화할 수 있나요?"

AI 어시스턴트:
1. 분석 세션 생성
2. n의 인수분해를 위해 FactorDB 쿼리
3. 여러 공격 방법으로 RsaCtfTool 실행
4. Wiener 공격으로 성공적으로 복호화
5. 반환: "평문: CTF{weak_rsa_exponent}"
```

### 예시 2: 웹 애플리케이션 테스트

```
사용자: "http://target.com의 취약점을 테스트해주세요"

AI 어시스턴트:
1. nmap 포트 스캔 실행
2. 80, 443 포트에서 웹 서버 발견
3. 디렉터리 열거를 위해 gobuster 실행
4. /admin, /backup, /api 엔드포인트 발견
5. 취약점 스캔을 위해 nikto 실행
6. 로그인 폼에서 sqlmap으로 SQLi 테스트
7. 종합 보안 보고서 제공
```

### 예시 3: 바이너리 익스플로잇 (Pwnable)

```
사용자: "이 바이너리를 분석해주세요: challenge.bin"

AI 어시스턴트:
1. 세션 작업 공간에 바이너리 업로드
2. checksec 실행 (발견: 카나리 없음, NX 활성화, PIE 없음)
3. 버퍼 오버플로우 취약점 자동 탐지
4. NX 우회를 위한 ROP 가젯 발견
5. system() 및 "/bin/sh" 위치 확인
6. pwntools 익스플로잇 스크립트 생성
7. 로컬에서 테스트하고 플래그 획득
```

### 예시 4: 메모리 포렌식

```
사용자: "이 메모리 덤프를 분석해주세요: memory.dmp (Windows)"

AI 어시스턴트:
1. Volatility3 windows.info 실행
2. 실행 중인 프로세스 목록화 (windows.pslist)
3. 의심스러운 프로세스 식별: malware.exe
4. 프로세스 메모리 덤프
5. 네트워크 연결 스캔
6. 명령줄 인수 추출
7. 프로세스 메모리에서 숨겨진 플래그 발견
```

### 예시 5: 자동화된 포렌식 워크플로우

```
사용자: "이 메모리 덤프에 대해 자동화된 포렌식 분석을 실행해주세요"

AI 어시스턴트 (auto_memory_analysis 사용):
✓ 1단계: OS 탐지 - Windows 10 x64 식별
✓ 2단계: 프로세스 분석 - 47개 프로세스 발견
✓ 3단계: 네트워크 연결 - 12개 활성 연결
✓ 4단계: 멀웨어 탐지 - 2개 의심스러운 인젝션 발견
✓ 5단계: 레지스트리 분석 - 지속성 메커니즘 탐지
✓ 6단계: DLL 분석 - 악성 DLL 식별

요약: Run 키에서 멀웨어 지속성 발견, C2 서버 추출: 192.168.1.100:4444
```

```
사용자: "이 의심스러운 실행 파일에서 멀웨어를 헌팅해주세요"

AI 어시스턴트 (auto_malware_hunt 사용):
✓ 1단계: YARA 스캔 - 일치: Trojan.Generic
✓ 2단계: IOC 추출 - 3개 IP, 5개 도메인, 2개 레지스트리 키 발견
✓ 3단계: 파일 유형 - PE32 실행 파일 (stripped)
✓ 4단계: 엔트로피 분석 - 높은 엔트로피 (7.8) - 패킹 가능성
✓ 5단계: 해시 생성 - MD5: a1b2c3..., SHA256: d4e5f6...
✓ 6단계: 메타데이터 - 컴파일: 2024-01-15, 언어: C++
✓ 7단계: 바이너리 분석 - 0x2000에서 임베디드 ELF 탐지

위협 평가: 임베디드 페이로드가 있는 고위험 패킹 멀웨어
```

---

## 📚 문서

- **[PROBLEM_SOLVING_PROMPTS.md](PROBLEM_SOLVING_PROMPTS.md)** - 각 CTF 카테고리를 위한 즉시 사용 가능한 AI 프롬프트
- **[KALI_TOOLS_INSTALLATION.md](KALI_TOOLS_INSTALLATION.md)** - 자동화된 스크립트가 포함된 완전한 도구 설치 가이드
- **[CTF_ENHANCEMENT.md](CTF_ENHANCEMENT.md)** - 고급 기능 및 능력 분석
- **[CLAUDE.md](CLAUDE.md)** - 이 코드베이스와 작업하는 AI 어시스턴트를 위한 종합 가이드

---

## 🎮 지원되는 CTF 플랫폼

이 도구는 **모든 주요 CTF 플랫폼**과 호환됩니다:

- **HackTheBox** (HTB)
- **TryHackMe** (THM)
- **PicoCTF**
- **CTFtime** 대회
- **OverTheWire**
- **pwnable.kr** / **pwnable.tw**
- **Root-Me**
- **RingZer0 CTF**
- **VulnHub**
- 그 외 다수!

---

## 🎯 사용 사례

### ✅ **승인 및 합법적**

- CTF 대회 및 워게임
- 승인된 침투 테스트 (서면 허가 필요)
- 버그 바운티 프로그램 (범위 내)
- 보안 연구 및 교육
- 개인 랩 환경
- Capture The Flag 훈련

### ❌ **금지**

- 시스템에 대한 무단 접근
- 악의적인 해킹 또는 공격
- 명시적인 허가 없는 테스트
- 모든 불법 활동

---

## 🐳 Docker 배포

### Docker로 빠른 시작

**Docker Compose 사용 (권장)**
```bash
# 서버 시작
docker-compose up -d

# 로그 보기
docker-compose logs -f

# 서버 중지
docker-compose down

# 코드 변경 후 재빌드
docker-compose up -d --build
```

**Docker 직접 사용**
```bash
# 이미지 빌드
docker build -t foxibu/ctf-solver:latest .

# 컨테이너 실행
docker run -d \
  --name ctf-solver \
  -p 5000:5000 \
  -v $(pwd)/sessions:/app/sessions \
  -v $(pwd)/workspaces:/app/workspaces \
  foxibu/ctf-solver:latest

# 로그 보기
docker logs -f ctf-solver

# 중지 및 제거
docker stop ctf-solver && docker rm ctf-solver
```

### Docker 명령어

```bash
# 컨테이너 상태 확인
docker ps
docker exec ctf-solver curl http://localhost:5000/health

# 컨테이너 셸 접근
docker exec -it ctf-solver /bin/bash

# 리소스 사용량 보기
docker stats ctf-solver

# 이미지 내보내기/가져오기
docker save foxibu/ctf-solver:latest | gzip > ctf-solver.tar.gz
docker load < ctf-solver.tar.gz
```

### Docker 배포의 이점

✅ **제로 구성** - 55개 이상의 도구 사전 설치
✅ **크로스 플랫폼** - Windows, Mac, Linux에서 작동
✅ **격리된 환경** - 안전한 멀웨어 분석
✅ **버전 관리** - 재현 가능한 CTF 환경
✅ **쉬운 업데이트** - `docker-compose pull && docker-compose up -d`
✅ **리소스 제한** - CPU/메모리 사용량 제어

### 영구 데이터

Docker 설정은 자동으로 다음을 유지합니다:
- **세션**: `./sessions/` - 활성 분석 세션
- **작업 공간**: `./workspaces/` - 챌린지 파일 및 결과
- **커스텀 워드리스트**: `./wordlists/` (직접 마운트)

---

## 🔧 구성

### 환경 변수

```bash
export KALI_SERVER_URL="http://localhost:5000"
export KALI_REQUEST_TIMEOUT=300  # 5분
export DEBUG_MODE=1  # 디버그 로깅 활성화
```

### 커스텀 포트

```bash
# 커스텀 포트로 Kali 서버 실행
python3 kali_server.py --port 8080

# 커스텀 서버로 MCP 클라이언트 실행
python3 src/my_server/mcp_server.py --server http://localhost:8080
```

### 원격 접근 (SSH 터널)

```bash
# 클라이언트 머신에서
ssh -L 5000:localhost:5000 user@kali-server.example.com

# MCP 클라이언트를 localhost:5000으로 구성
```

---

## 🤝 기여

기여를 환영합니다! Pull Request를 자유롭게 제출해주세요.

### 개발 설정

```bash
# 저장소 클론
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server

# 개발 모드로 설치
pip install -e .

# 테스트 실행
python3 kali_server.py --debug
```

---

## 📰 미디어 & 아티클

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

📝 **[How MCP is Revolutionizing Offensive Security](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)** - 저자의 Medium 아티클

---

## ⚠️ 법적 고지

### 승인된 보안 테스트 전용

이 도구는 다음 용도로만 설계되었습니다:

✅ **승인된 침투 테스트** (서면 허가 필요)
✅ **CTF 대회** 및 교육용 워게임
✅ **보안 연구** (통제된 환경)
✅ **버그 바운티 프로그램** (정의된 범위 내)
✅ **개인 랩 환경** (소유한 환경)

❌ **시스템에 대한 무단 접근**
❌ **악의적인 해킹** 또는 공격
❌ **명시적 허가 없는 테스트**
❌ **모든 불법 활동**

**이 도구를 사용함으로써 다음에 동의합니다:**
- 시스템 테스트 전 적절한 승인 획득
- 모든 관련 법률 및 규정 준수
- 책임감 있고 윤리적인 도구 사용
- 자신의 행동에 대한 완전한 책임 수용

**저자는 오용에 대해 책임을 지지 않습니다.** 컴퓨터 시스템에 대한 무단 접근은 불법이며 법률에 의해 처벌받을 수 있습니다.

---

## 📄 라이선스

이 프로젝트는 **MIT 라이선스**를 따릅니다 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---

## 🙏 크레딧

- **저자**: [Yousof Nahya](https://github.com/Wh0am123)
- **영감**: [Project Astro](https://github.com/whit3rabbit0/project_astro)
- **빌드**: [FastMCP](https://github.com/jlowin/fastmcp), Flask, 공격적 보안 커뮤니티
- **제공**: Kali Linux, Model Context Protocol

---

## 🔗 링크

- **GitHub 저장소**: [github.com/Wh0am123/MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server)
- **Model Context Protocol**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **Kali Linux**: [kali.org](https://www.kali.org/)
- **FastMCP**: [github.com/jlowin/fastmcp](https://github.com/jlowin/fastmcp)

---

## 📊 통계

- **55개 이상의 보안 도구** 통합
- **7개 CTF 카테고리** 지원
- **73개 이상의 API 엔드포인트** 사용 가능
- **3개 고급 포렌식 워크플로우** 자동화
- **4개 워크플로우 프롬프트** 포함
- **100페이지 이상**의 문서

---

<div align="center">

**⭐ 유용하다고 생각되시면 이 저장소에 스타를 눌러주세요!**

공격적 보안 커뮤니티가 ❤️로 만들었습니다

</div>
