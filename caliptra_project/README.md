# caliptra_project

[CHIPS Alliance Caliptra](https://github.com/chipsalliance/Caliptra) 2.x SoC 통합 연구.  
Caliptra는 서버/엣지 SoC를 위한 오픈소스 하드웨어 신뢰 루트(RoT)입니다.

## 디렉토리 구조

```
caliptra_project/
├── caliptra-sw/          # upstream 서브모듈 (수정 금지)
├── Caliptra/             # upstream 서브모듈 (수정 금지)
├── caliptra_comms/       # Caliptra mailbox 통신 테스트 (Rust)
├── docs/                 # API 분석 문서
├── include/              # C 헤더 (SoC 통합 레이어)
└── src/                  # C 구현 (SoC 통합 레이어)
```

## 서브모듈

| 서브모듈 | 역할 |
|----------|------|
| `caliptra-sw/` | ROM, FMC, Runtime 펌웨어 + 소프트웨어 에뮬레이터 + libcaliptra |
| `Caliptra/` | RTL 사양 및 하드웨어 명세 |

초기화:
```bash
git submodule update --init
```

## caliptra_comms — mailbox 통신 테스트

`caliptra-hw-model`을 사용해 Caliptra를 in-process로 부팅하고 mailbox 명령을 테스트하는 Rust 바이너리.

### 사전 준비

```bash
# 1. ROM 빌드
cd caliptra-sw
cargo run -p caliptra-builder -- --rom-with-log /tmp/caliptra-rom-with-log.bin

# 2. FMC+Runtime 펌웨어 빌드
cargo run -p caliptra-builder -- --fw /tmp/caliptra-fw.bin --pqc-key-type 1
```

### 빌드 및 실행

```bash
cd caliptra_comms
cargo build
./target/debug/caliptra-comms-test [ROM_PATH] [FW_PATH]
```

기본값: `ROM_PATH=/tmp/caliptra-rom-with-log.bin`, `FW_PATH=/tmp/caliptra-fw.bin`

### 테스트 명령

| # | 명령 | cmd ID | 설명 |
|---|------|--------|------|
| 1 | FIPS_VERSION | `0x46505652` | FIPS 버전 및 모드 조회 |
| 2 | FW_INFO | `0x494E464F` | 펌웨어 SVN, revision, PQC 타입 |
| 3 | GET_LDEV_ECC384_CERT | `0x4C444556` | LDevID ECC384 DER 인증서 |
| 4 | GET_FMC_ALIAS_ECC384_CERT | `0x43455246` | FMC Alias ECC384 DER 인증서 |
| 5 | GET_RT_ALIAS_ECC384_CERT | `0x43455252` | RT Alias ECC384 DER 인증서 |

### Cargo.lock 동기화

`caliptra_comms/Cargo.lock`은 `caliptra-sw/Cargo.lock`을 복사한 것입니다.  
caliptra-sw 서브모듈 업데이트 시 아래 명령으로 동기화해야 합니다:

```bash
cp caliptra-sw/Cargo.lock caliptra_comms/Cargo.lock
```

### 의존성 구조 메모

`caliptra_project/Cargo.toml`을 **만들지 않는** 것이 중요합니다.  
상위에 `[workspace]`가 생기면 Cargo가 `caliptra-sw` 내부 크레이트의  
`workspace = true` 의존성을 잘못된 workspace root에서 해석합니다.

## docs — API 분석 문서

| 문서 | 내용 |
|------|------|
| `docs/api_overview.md` | Caliptra SoC API 전체 구조 |
| `docs/api_boot.md` | 부팅 시퀀스 및 펌웨어 업로드 |
| `docs/api_attestation.md` | 증명(Attestation) 및 인증서 체인 |
| `docs/api_crypto.md` | 암호화 mailbox 명령 |
| `docs/api_measurement.md` | PCR, DPE 측정값 관리 |
| `docs/api_auth.md` | 이미지 인증 및 매니페스트 |
| `docs/api_lock.md` | OCP L.O.C.K. (HEK ratchet) |
| `docs/caliptra_api_reference.md` | 전체 API 레퍼런스 |

## include / src — C SoC 통합 레이어

`libcaliptra`를 기반으로 한 SoC 통합 레이어 구현 예시.

| 파일 | 내용 |
|------|------|
| `include/caliptra_driver.h` | 플랫폼 HAL 인터페이스 (3개 필수 함수) |
| `include/caliptra_mbox.h` | Mailbox 레지스터 접근 |
| `include/caliptra_lock.h` | OCP L.O.C.K. 커맨드 래퍼 |
| `src/caliptra_driver.c` | HAL 구현 템플릿 |
| `src/caliptra_example.c` | 통합 사용 예제 |

빌드:
```makefile
CFLAGS += -I caliptra-sw/libcaliptra/inc -I include/
SRCS   += caliptra-sw/libcaliptra/src/caliptra_api.c src/caliptra_driver.c
```
