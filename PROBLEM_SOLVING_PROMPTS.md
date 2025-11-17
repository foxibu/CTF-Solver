# CTF 문제 풀이 프롬프트 가이드

이 문서는 각 CTF 분야별로 AI에게 문제 풀이를 요청할 때 사용할 수 있는 효과적인 프롬프트 템플릿을 제공합니다.

## 목차

- [암호학 (Cryptography)](#암호학-cryptography)
- [포렌식 (Forensics)](#포렌식-forensics)
- [클라우드 보안 (Cloud Security)](#클라우드-보안-cloud-security)
- [Web3 & 블록체인](#web3--블록체인)
- [Pwnable](#pwnable)
- [리버싱 (Reversing)](#리버싱-reversing)
- [웹 해킹 (Web)](#웹-해킹-web)

---

## 암호학 (Cryptography)

### 1. RSA 문제 풀이 프롬프트

```
RSA 암호학 문제를 풀어야 해. 다음 정보가 주어졌어:

문제 설명: [문제 설명 붙여넣기]

주어진 값:
- n (모듈러스): [N 값]
- e (공개 지수): [e 값]
- c (암호문): [암호문 값]

목표: 평문을 복호화해서 플래그를 찾아야 해.

단계별로 다음과 같이 진행해줘:
1. 먼저 세션을 생성하고
2. factordb_query()로 N이 이미 인수분해되어 있는지 확인
3. 안되면 rsa_attack()으로 모든 공격 시도
4. 성공하면 복호화된 평문 출력

각 단계의 결과를 보여주고, 플래그를 찾으면 알려줘.
```

**실제 사용 예시:**
```
"Baby RSA" 문제를 풀어야 해.

주어진 값:
- n: 85188995949975973882030588091827042986832597534618294804398478969133005944907116982056396054535842707589380954015865361051554526469116277628254426267757199
- e: 65537
- c: 34577152691579622127706154480884897287896805981872459257748376838912182049809506013649959599927732959113724699252882097865164533984706907700507149722179157

목표: 평문을 복호화해서 플래그를 찾아야 해.

단계별로 진행해줘:
1. create_analysis_session()으로 세션 생성
2. factordb_query(number=n)로 소인수분해 시도
3. 실패하면 rsa_attack()으로 Wiener, Fermat 등 모든 공격 시도
4. 성공하면 복호화된 평문을 출력하고 플래그 찾기

각 단계의 결과를 자세히 보여줘.
```

### 2. 해시 크래킹 문제 프롬프트

```
해시 크래킹 문제야. 다음 해시값이 주어졌어:

해시: [해시값]
해시 타입: [MD5/SHA1/SHA256/등]

목표: 해시의 원본 평문을 찾아야 해.

다음과 같이 진행해줘:
1. 해시 타입을 확인하고 hashcat 모드 번호 결정
2. hashcat_crack()으로 rockyou.txt 사용해서 크래킹 시도
3. 실패하면 john_crack()도 시도
4. 크래킹된 평문 출력

빠르게 결과를 보여줘.
```

**실제 사용 예시:**
```
다음 MD5 해시의 평문을 찾아야 해:

해시: 5f4dcc3b5aa765d61d8327deb882cf99

단계:
1. hashcat_crack(hash_value="5f4dcc3b5aa765d61d8327deb882cf99", hash_type="0", wordlist="/usr/share/wordlists/rockyou.txt")
2. 결과 없으면 john_crack()도 시도
3. 크래킹된 평문이 플래그인지 확인

결과를 바로 보여줘.
```

### 3. 복합 암호학 문제 프롬프트

```
복잡한 암호학 문제야. 문제 설명은 다음과 같아:

[문제 설명]

주어진 파일/데이터:
- [파일1]: [설명]
- [파일2]: [설명]

목표: [목표 설명]

다음 순서로 분석해줘:
1. 먼저 crypto_challenge_workflow() 프롬프트를 참고해서 문제 유형 파악
2. 사용된 암호 알고리즘 식별
3. 적절한 도구 선택 (RsaCtfTool, hashcat, sage 등)
4. 단계별로 공격 수행
5. 플래그 추출

각 단계마다 결과를 보여주고, 막히면 대안 방법 제시해줘.
```

### 4. SageMath를 사용한 수학적 공격 프롬프트

```
타원 곡선 암호 / 격자 기반 암호 문제야.

문제: [문제 설명]
주어진 값: [파라미터들]

SageMath를 사용해서 다음을 수행해줘:
1. 세션 생성
2. SageMath 스크립트 작성:
   - 주어진 파라미터로 수학적 구조 생성
   - 취약점 분석 (약한 곡선, 작은 부분군 등)
   - 이산 로그 문제 해결 또는 격자 기반 공격
3. sage_execute()로 실행
4. 결과 해석하고 플래그 추출

각 단계의 수학적 원리도 간단히 설명해줘.
```

---

## 포렌식 (Forensics)

### 1. 이미지 스테가노그래피 문제 프롬프트

```
이미지 파일에 숨겨진 플래그를 찾아야 해.

파일: [파일명]
파일 위치: [경로]

다음 순서로 분석해줘:
1. exiftool_analyze()로 메타데이터 확인
2. steghide_extract()로 스테가노그래피 추출 시도 (비밀번호 없이)
3. 실패하면 일반적인 비밀번호 시도: "password", "flag", "secret", "admin"
4. binwalk_analyze()로 숨겨진 파일 찾기
5. 필요하면 LSB 분석

각 단계의 출력을 보여주고, 플래그를 찾으면 알려줘.
```

**실제 사용 예시:**
```
"hidden_message.jpg" 파일에 플래그가 숨겨져 있어.

파일 위치: /tmp/hidden_message.jpg

단계별로:
1. exiftool_analyze(file_path="/tmp/hidden_message.jpg")
2. steghide_extract(cover_file="/tmp/hidden_message.jpg", passphrase="")
3. 실패하면:
   - steghide_extract(cover_file="/tmp/hidden_message.jpg", passphrase="flag")
   - steghide_extract(cover_file="/tmp/hidden_message.jpg", passphrase="password")
4. binwalk_analyze(file_path="/tmp/hidden_message.jpg", extract=True, session_id=<session>)

모든 결과를 보여주고 플래그 찾아줘.
```

### 2. 메모리 덤프 분석 프롬프트

```
메모리 덤프 파일 분석 문제야.

파일: [메모리 덤프 경로]
OS: [Windows/Linux]

다음을 단계별로 수행해줘:
1. volatility_analyze(plugin="[os].info") - 시스템 정보
2. volatility_analyze(plugin="[os].pslist") - 프로세스 목록
3. 의심스러운 프로세스 찾기
4. volatility_analyze(plugin="[os].cmdline") - 명령줄 인자 확인
5. volatility_analyze(plugin="[os].filescan") - 흥미로운 파일 찾기
6. 필요하면 메모리에서 파일 추출

각 단계마다 중요한 발견사항을 요약해서 알려줘.
```

**실제 사용 예시:**
```
Windows 메모리 덤프 분석:

파일: /tmp/challenge.dmp

순서:
1. volatility_analyze(dump_file="/tmp/challenge.dmp", plugin="windows.info")
2. volatility_analyze(dump_file="/tmp/challenge.dmp", plugin="windows.pslist")
3. 의심스러운 프로세스 PID 확인
4. volatility_analyze(dump_file="/tmp/challenge.dmp", plugin="windows.cmdline")
5. volatility_analyze(dump_file="/tmp/challenge.dmp", plugin="windows.filescan") | grep -i "flag"
6. 플래그가 있는 파일 찾기

의심스러운 프로세스와 플래그 위치를 알려줘.
```

### 3. 파일 카빙 문제 프롬프트

```
손상된 디스크 이미지에서 파일을 복구해야 해.

파일: [디스크 이미지 경로]
찾아야 할 파일 타입: [jpg, png, pdf, doc 등]

다음을 수행해줘:
1. 세션 생성
2. foremost_carve()로 파일 카빙
3. 복구된 파일 목록 확인
4. 각 파일을 exiftool_analyze()로 분석
5. 이미지 파일이면 tesseract_ocr()로 텍스트 추출
6. 플래그 찾기

복구된 파일 개수와 플래그 위치를 알려줘.
```

### 4. 펌웨어 분석 프롬프트

```
IoT 펌웨어 파일 분석 문제야.

파일: [펌웨어 경로]

분석 순서:
1. binwalk_analyze(file_path="<path>") - 파일 시그니처 확인
2. binwalk_analyze(file_path="<path>", extract=True, session_id=<session>) - 파일시스템 추출
3. 추출된 파일 탐색
4. 설정 파일, 스크립트, 바이너리 찾기
5. 하드코딩된 비밀번호, API 키, 플래그 찾기

각 단계의 발견사항을 정리해서 보여줘.
```

---

## 클라우드 보안 (Cloud Security)

### 1. AWS S3 버킷 열거 프롬프트

```
AWS S3 버킷 취약점 문제야.

대상: [회사명 또는 도메인]

다음을 수행해줘:
1. 일반적인 버킷 명명 규칙으로 버킷 이름 추측:
   - [company]-backups
   - [company]-data
   - [company]-logs
   - [company]-assets
   - [domain]-files
2. 각 버킷에 대해 s3_bucket_scan() 실행
3. 접근 가능한 버킷 찾기
4. 버킷 내용 나열하고 민감한 파일 찾기
5. 플래그 파일 다운로드

발견된 버킷과 내용을 정리해서 보여줘.
```

**실제 사용 예시:**
```
"acmecorp" 회사의 S3 버킷을 찾아야 해.

시도할 버킷 이름:
1. s3_bucket_scan(bucket_name="acmecorp-backups")
2. s3_bucket_scan(bucket_name="acmecorp-data")
3. s3_bucket_scan(bucket_name="acmecorp-logs")
4. s3_bucket_scan(bucket_name="acmecorp-public")
5. s3_bucket_scan(bucket_name="acmecorp-assets")

접근 가능한 버킷이 발견되면:
- 파일 목록 확인
- .env, backup, flag, secret 등의 키워드가 포함된 파일 찾기
- 플래그 다운로드

결과를 요약해서 보여줘.
```

### 2. 클라우드 메타데이터 SSRF 공격 프롬프트

```
웹 애플리케이션에 SSRF 취약점이 있어서 클라우드 메타데이터 서비스에 접근할 수 있어.

취약한 엔드포인트: [URL]
클라우드 제공자: [AWS/GCP/Azure]

다음을 수행해줘:
1. 메타데이터 서비스 접근 확인
2. cloud_metadata_query()로 주요 엔드포인트 조회:
   AWS의 경우:
   - "" (루트)
   - "iam/security-credentials/"
   - "iam/security-credentials/[role-name]"
3. 임시 자격증명 획득
4. aws_enumerate()로 리소스 열거
5. 플래그 찾기

각 단계의 응답을 보여주고 자격증명을 정리해줘.
```

### 3. AWS IAM 권한 상승 프롬프트

```
AWS 자격증명을 획득했어.

Access Key ID: [키]
Secret Access Key: [비밀키]

다음을 수행해줘:
1. aws_enumerate()로 현재 권한 확인:
   - s3 버킷 목록
   - ec2 인스턴스 목록
   - iam 사용자 목록
2. 각 서비스에서 읽을 수 있는 리소스 확인
3. pacu_aws_exploit()로 권한 열거:
   - module="iam__enum_permissions"
4. 민감한 데이터가 있는 S3 버킷 찾기
5. 플래그 다운로드

발견된 리소스와 플래그를 보고해줘.
```

---

## Web3 & 블록체인

### 1. 스마트 컨트랙트 재진입 공격 프롬프트

```
Solidity 스마트 컨트랙트 취약점 문제야.

컨트랙트 주소: [주소]
네트워크: [mainnet/testnet/로컬]
컨트랙트 소스: [소스 코드 또는 경로]

다음을 수행해줘:
1. slither_analyze()로 자동 취약점 탐지
2. 재진입 취약점이 있는지 확인
3. 취약한 함수 식별
4. 공격 컨트랙트 작성:
   - receive() 또는 fallback() 함수에서 재귀 호출
5. solidity_compile()로 컴파일
6. web3_interact()로 배포 및 공격 실행
7. 플래그 획득

각 단계를 설명하면서 진행해줘.
```

**실제 사용 예시:**
```
재진입 취약점이 있는 컨트랙트 공격:

컨트랙트: /tmp/VulnerableBank.sol

단계:
1. slither_analyze(contract_path="/tmp/VulnerableBank.sol")
   - 재진입 취약점 확인
2. 취약한 withdraw() 함수 분석
3. 공격 컨트랙트 작성:

```solidity
contract Attacker {
    VulnerableBank target;

    constructor(address _target) {
        target = VulnerableBank(_target);
    }

    function attack() external payable {
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}
```

4. 로컬 테스트넷에서 실행
5. 플래그 확인

결과를 단계별로 보여줘.
```

### 2. 스마트 컨트랙트 정수 오버플로우 공격 프롬프트

```
Solidity 0.7.x 컨트랙트 (SafeMath 미사용):

컨트랙트 주소: [주소]
소스: [경로]

다음을 확인하고 공격해줘:
1. mythril_analyze()로 정수 오버플로우/언더플로우 취약점 찾기
2. 취약한 변수/함수 식별
3. 공격 시나리오 작성:
   - 언더플로우로 잔액을 최대값으로 만들기
   - 또는 오버플로우로 검사 우회
4. web3_interact()로 트랜잭션 실행
5. 플래그 획득

공격 과정을 자세히 설명해줘.
```

### 3. 블록체인 타임스탬프 조작 문제 프롬프트

```
블록 타임스탬프에 의존하는 컨트랙트 문제:

컨트랙트: [주소]
취약점: block.timestamp 사용

다음을 수행해줘:
1. 컨트랙트 소스 분석
2. 타임스탬프 기반 로직 찾기
3. 로컬 테스트넷에서:
   - 타임스탬프 조작
   - 조건 우회
4. 플래그 획득

단계별로 설명해줘.
```

---

## Pwnable

### 1. 버퍼 오버플로우 문제 프롬프트

```
바이너리 버퍼 오버플로우 문제야.

바이너리: [파일명]
원격 서버: [호스트:포트] (옵션)

다음 순서로 진행해줘:
1. 세션 생성 및 바이너리 업로드
2. checksec_binary()로 보호 기법 확인
3. auto_detect_vulnerabilities()로 자동 분석
4. 취약점 있으면:
   - extract_strings()로 win 함수나 "/bin/sh" 찾기
   - analyze_with_radare2()로 함수 주소 확인
5. pwntools 익스플로잇 작성:
   - cyclic 패턴으로 오프셋 찾기
   - 페이로드 구성
6. run_pwntools_exploit()로 실행
7. 플래그 획득

각 단계의 출력을 보여줘.
```

**실제 사용 예시:**
```
"bof" 바이너리 공략:

바이너리 위치: /tmp/bof
원격: nc 127.0.0.1 9000

단계:
1. session = create_analysis_session()
2. upload_binary(session_id=session['session_id'], filename="bof", content_base64=<base64>)
3. checksec_binary(session_id=session['session_id'], binary_filename="bof")
4. auto_detect_vulnerabilities(session_id=session['session_id'], binary_filename="bof")
5. extract_strings(session_id=session['session_id'], binary_filename="bof") | grep -i "win\|shell\|flag"
6. 익스플로잇 작성 및 실행

각 결과를 확인하면서 진행해줘.
```

### 2. ROP 체인 구성 문제 프롬프트

```
NX가 활성화된 바이너리:

바이너리: [파일명]
보호 기법: NX enabled, No PIE

ROP 공격을 수행해줘:
1. checksec_binary()로 확인
2. find_rop_gadgets()로 가젯 찾기:
   - "pop rdi; ret"
   - "ret"
3. extract_strings()로 "/bin/sh" 주소 찾기
4. analyze_with_radare2()로 system@plt 주소 찾기
5. ROP 체인 구성:
   - pop_rdi_gadget
   - "/bin/sh" 주소
   - system 주소
6. run_pwntools_exploit()로 실행

ROP 체인 구성을 자세히 설명해줘.
```

---

## 리버싱 (Reversing)

### 1. 간단한 패스워드 체크 프롬프트

```
바이너리가 패스워드를 확인하는 문제야.

바이너리: [파일명]

다음을 수행해줘:
1. extract_strings()로 하드코딩된 문자열 찾기
2. 플래그 형식 문자열 있는지 확인
3. analyze_with_radare2()로 main 함수 분석:
   - strcmp, strncmp 호출 찾기
   - 비교 대상 확인
4. 없으면 trace_library_calls()로 동적 분석
5. 올바른 패스워드 찾기

단계별 결과를 보여줘.
```

### 2. XOR 암호화 리버싱 프롬프트

```
XOR로 암호화된 플래그를 복호화해야 해.

바이너리: [파일명]

분석 순서:
1. extract_strings()로 암호화된 데이터 찾기
2. analyze_with_radare2()로 main 함수 디스어셈블:
   - XOR 연산 찾기 (xor 명령어)
   - 키 값 확인
3. trace_library_calls()로 실행 추적
4. XOR 키 추출
5. Python으로 복호화 스크립트 작성
6. 플래그 획득

XOR 키와 복호화 과정을 설명해줘.
```

---

## 웹 해킹 (Web)

### 1. SQL 인젝션 문제 프롬프트

```
웹 애플리케이션 SQL 인젝션 문제:

URL: [타겟 URL]
취약한 파라미터: [파라미터명]

다음을 수행해줘:
1. sqlmap_scan()으로 자동 탐지:
   - 데이터베이스 타입 확인
   - 주입 가능 여부 확인
2. 데이터베이스 열거:
   - --dbs로 데이터베이스 목록
   - --tables로 테이블 목록
   - --columns로 컬럼 목록
3. 플래그 테이블에서 데이터 덤프
4. 플래그 추출

각 단계의 결과를 보여줘.
```

### 2. 디렉토리 열거 및 LFI 프롬프트

```
웹 서버 디렉토리 열거 문제:

URL: [타겟 URL]

순서:
1. gobuster_scan()으로 디렉토리 스캔
2. dirb_scan()으로 추가 경로 찾기
3. nikto_scan()으로 취약점 스캔
4. LFI 취약점 있으면:
   - /etc/passwd 읽기
   - 로그 파일 확인
   - 플래그 파일 찾기
5. 플래그 획득

발견된 경로와 취약점을 정리해줘.
```

---

## 종합 문제 풀이 프롬프트

### 복합적인 CTF 문제

```
CTF 문제를 풀어야 해. 문제 정보:

제목: [문제 제목]
카테고리: [Pwnable/Reversing/Web/Crypto/Forensics/Cloud/Web3]
난이도: [Easy/Medium/Hard]

문제 설명:
[전체 문제 설명 붙여넣기]

주어진 파일:
- [파일1]: [설명]
- [파일2]: [설명]

접속 정보 (있는 경우):
- 호스트: [호스트]
- 포트: [포트]
- URL: [URL]

다음과 같이 진행해줘:
1. 먼저 문제 카테고리에 맞는 workflow 프롬프트 확인
2. 세션 생성
3. 초기 정찰 및 분석
4. 취약점 식별
5. 익스플로잇 개발/실행
6. 플래그 획득

각 단계마다:
- 무엇을 하는지 설명
- 사용하는 도구와 명령어
- 출력 결과
- 다음 단계로 가는 이유

막히면 대안 방법을 제시하고, 최종적으로 플래그를 찾아줘.
```

---

## 프롬프트 작성 팁

### 1. 효과적인 프롬프트 구조

```
[문제 유형] + [구체적 정보] + [단계별 요청] + [출력 형식]

예시:
"RSA 암호학 문제인데, n=12345..., e=65537, c=67890...이 주어졌어.
factordb로 확인하고, 안되면 RsaCtfTool로 공격해줘.
각 단계의 결과를 보여주고, 성공하면 복호화된 평문을 알려줘."
```

### 2. 필수 포함 정보

- **문제 유형**: Pwnable, Crypto, Forensics 등
- **주어진 데이터**: 파일, 값, URL 등
- **목표**: 플래그 형식, 찾아야 할 것
- **제약사항**: 시간 제한, 특별한 조건

### 3. 단계별 요청

```
"다음 순서로 진행해줘:"로 시작하고
1. 첫 번째 단계
2. 두 번째 단계
3. ...
```

### 4. 출력 요청

```
"각 단계마다 결과를 보여주고"
"성공하면 플래그를 강조해서 알려줘"
"막히면 대안을 제시해줘"
```

---

## 자주 사용하는 프롬프트 패턴

### 패턴 1: 빠른 분석

```
"[파일/URL]을 빠르게 분석해줘.
자동화 도구(auto_detect, slither, sqlmap 등)로 먼저 스캔하고,
발견된 취약점을 요약해서 알려줘."
```

### 패턴 2: 단계별 가이드

```
"[문제]를 단계별로 풀어줘.
각 단계마다:
1. 무엇을 하는지
2. 왜 하는지
3. 결과가 무엇인지
설명하면서 진행해줘."
```

### 패턴 3: 학습 모드

```
"[문제]를 풀면서 각 기법을 설명해줘.
- 사용하는 공격 기법의 원리
- 왜 이 도구를 선택했는지
- 결과를 어떻게 해석하는지
자세히 알려줘."
```

---

## 문제 유형별 핵심 키워드

### 암호학
- "RSA 공격", "해시 크래킹", "소인수분해", "Wiener 공격"
- "factordb", "hashcat", "RsaCtfTool", "SageMath"

### 포렌식
- "스테가노그래피", "메모리 덤프", "파일 카빙", "메타데이터"
- "steghide", "volatility", "binwalk", "exiftool"

### 클라우드
- "S3 버킷", "메타데이터 서비스", "SSRF", "IAM 권한"
- "aws-cli", "pacu", "버킷 열거"

### Web3
- "재진입", "정수 오버플로우", "스마트 컨트랙트"
- "slither", "mythril", "solidity"

### Pwnable
- "버퍼 오버플로우", "ROP", "NX 우회", "셸코드"
- "checksec", "ROPgadget", "pwntools"

### 리버싱
- "디스어셈블", "동적 분석", "패커", "난독화"
- "radare2", "ltrace", "strings"

### 웹
- "SQL 인젝션", "XSS", "디렉토리 열거", "LFI"
- "sqlmap", "gobuster", "nikto"

---

## 마무리

이 가이드의 프롬프트를 사용할 때:

1. **문제 정보를 정확히 제공**: 파일명, 경로, 값 등을 명확히
2. **단계별로 요청**: 한 번에 모든 것을 요구하지 말고 단계별로
3. **결과 확인**: 각 단계의 출력을 확인하고 다음 단계 결정
4. **대안 준비**: 첫 번째 방법이 실패하면 다른 접근 시도

프롬프트를 상황에 맞게 수정하여 사용하세요!
