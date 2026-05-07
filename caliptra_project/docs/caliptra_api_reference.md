# Caliptra 2.x API Reference for SoC C/C++ Integration

> **스펙 버전**: Caliptra 2.1  
> **대상**: SoC 펌웨어 개발자 (C/C++)  
> **원본 스펙**: `Caliptra/doc/Caliptra.md`  
> **공식 레지스터 참조**: https://ereg.caliptra.org  
> **Runtime 명령어 참조**: https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md

---

## 목차

1. [아키텍처 개요](#1-아키텍처-개요)
2. [인터페이스 신호 (Logic IOs)](#2-인터페이스-신호-logic-ios)
3. [부트 플로우](#3-부트-플로우)
4. [메일박스 (Mailbox) API](#4-메일박스-mailbox-api)
5. [Runtime 펌웨어 커맨드](#5-runtime-펌웨어-커맨드)
6. [MMIO 아키텍처 레지스터](#6-mmio-아키텍처-레지스터)
7. [Fuse 맵](#7-fuse-맵)
8. [DICE / DPE API](#8-dice--dpe-api)
9. [PCR (측정값 저장소)](#9-pcr-측정값-저장소)
10. [암호화 서비스 (2.0 신규)](#10-암호화-서비스-20-신규)
11. [OCP Recovery / Streaming Boot (서브시스템 모드)](#11-ocp-recovery--streaming-boot-서브시스템-모드)
12. [보안 상태 (Security State)](#12-보안-상태-security-state)
13. [오류 처리](#13-오류-처리)
14. [JTAG 디버그 레지스터](#14-jtag-디버그-레지스터)
15. [C/C++ 통합 가이드](#15-cc-통합-가이드)

---

## 1. 아키텍처 개요

Caliptra는 데이터센터급 SoC에 내장되는 **Silicon Root of Trust (RoT)** 블록입니다.

```
┌─────────────────────────────────────────────────────────┐
│                    Caliptra Core 2.x                     │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  VeeR    │  │  ICCM    │  │  DCCM    │  │  Key   │  │
│  │ EL2 uC   │  │ (Instr)  │  │ (Data)   │  │ Vault  │  │
│  │ (RISC-V) │  │  SRAM    │  │  SRAM    │  │32 슬롯  │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Mailbox  │  │  SHA384  │  │  ECC384  │  │  AES   │  │
│  │ SRAM     │  │ (+ DMA)  │  │ (ECDSA)  │  │        │  │
│  │ 128 KiB  │  └──────────┘  └──────────┘  └────────┘  │
│  └──────────┘                                            │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  HMAC    │  │   TRNG   │  │  ML-DSA  │  │ ML-KEM │  │
│  │  (SHA)   │  │ (내부)   │  │  (Adams  │  │        │  │
│  └──────────┘  └──────────┘  │  Bridge) │  └────────┘  │
│                               └──────────┘               │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │        AXI Manager Interface (DMA용)                │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │        AXI Subordinate Interface (SoC → Caliptra)  │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
          ↕ AXI (MMIO + Mailbox)        ↕ 신호선
    ┌─────────────────────────────────────────────────┐
    │                    SoC                           │
    └─────────────────────────────────────────────────┘
```

### 동작 모드

| 모드 | 설명 | 사용 사례 |
|------|------|----------|
| **Passive 모드** | SoC ROM이 Caliptra FW를 메일박스로 로드 | CPU, GPU, NIC 등 |
| **Subsystem 모드** | MCU + I3C Streaming Boot + OCP Recovery | 전체 서브시스템 RoT 구성 |

---

## 2. 인터페이스 신호 (Logic IOs)

### SoC → Caliptra 입력 신호

| 신호명 | 방향 | 설명 |
|--------|------|------|
| `cptra_pwrgood` | SoC→Caliptra | 전원 공급 신호. 이 신호가 어설션된 상태에서만 Fuse가 읽힘 |
| `cptra_rst_b` | SoC→Caliptra | 리셋 신호 (active low). 디어설션 시점에 보안 상태 래치됨 |
| `security_state[2:0]` | SoC→Caliptra | Caliptra 보안 상태 인코딩 (부팅 시 래치) |
| `BootFSMBrk` | SoC→Caliptra | Boot FSM 중단 요청 (디버그/제조 모드) |
| `scan_mode` | SoC→Caliptra | 스캔 모드 (어설션 시 모든 시크릿 소거) |
| `GENERIC_INPUT_WIRES[1:0]` | SoC→Caliptra | SoC가 ROM에 전달하는 범용 입력 신호 |

> **주의**: `cptra_rst_b` 디어설션 시점에 `security_state`가 래치됩니다. 이후 변경은 다음 리셋까지 무효.

### Caliptra → SoC 출력 신호

| 신호명 | 방향 | 설명 |
|--------|------|------|
| `ready_for_fuse` | Caliptra→SoC | Fuse 쓰기 가능 신호. 어설션 시 SoC는 Fuse 레지스터 프로그래밍 후 `CPTRA_FUSE_WR_DONE` 설정 |
| `ready_for_fw` | Caliptra→SoC | FW 로드 준비 완료. Passive 모드에서 SoC는 이 신호 후 메일박스로 FW 전송 |
| `ready_for_rtflows` | Caliptra→SoC | Runtime FW 실행 완료. 이 신호 이후 모든 RT 커맨드 사용 가능 |
| `cptra_error_fatal` | Caliptra→SoC | Fatal 오류 발생. SoC는 `cptra_rst_b`로 Caliptra 리셋 필요 |
| `cptra_error_non_fatal` | Caliptra→SoC | Non-fatal 오류 발생 |
| `mbox_data_avail` | Caliptra→SoC | Caliptra가 메일박스에 데이터 준비 완료 (Caliptra→SoC 방향) |
| `GENERIC_OUTPUT_WIRES[1:0]` | Caliptra→SoC | ROM이 SoC에 전달하는 범용 출력 신호 |

---

## 3. 부트 플로우

### 3.1 Passive 모드 Cold Boot

```
      SoC                              Caliptra ROM/FW
       │                                     │
       │── cptra_pwrgood assert ─────────────→│
       │── cptra_rst_b deassert ──────────────→│
       │                                     │ UDS decrypt (HW)
       │                                     │ IDevID 파생 (HW)
       │                                     │ TRNG 초기화
       │←── ready_for_fuse ─────────────────→│
       │── [Fuse 레지스터 프로그래밍] ──────→│
       │── CPTRA_FUSE_WR_DONE 쓰기 ──────────→│
       │                                     │ 메일박스 활성화
       │←── ready_for_fw ───────────────────→│
       │── [FW 이미지를 메일박스로 전송] ────→│
       │   (FIRMWARE_LOAD 커맨드)             │ FW 서명 검증
       │                                     │ FMC 로드 및 실행
       │                                     │ Runtime 로드 및 실행
       │←── ready_for_rtflows ──────────────→│
       │── [측정값 stash, RT 커맨드 사용] ────→│
```

### 3.2 Warm Reset (CPU/PCIe 핫 리셋)

```
      SoC                              Caliptra
       │                                     │
       │── cptra_rst_b assert ───────────────→│ (리셋)
       │── cptra_rst_b deassert ──────────────→│
       │── CPTRA_FUSE_WR_DONE 쓰기 ──────────→│
       │                                     │ Warm reset 감지
       │                                     │ DICE 키 생성 스킵
       │                                     │ FW 로드 스킵 (ICCM 재사용)
       │←── ready_for_rtflows ──────────────→│ (빠른 부팅)
```

> **Note**: Cold reset = Cold boot 플로우와 동일. Warm reset은 키 파생과 FW 로드를 건너뜀.

### 3.3 부팅 시 SoC의 필수 조치

1. `cptra_pwrgood` → `cptra_rst_b` 순서로 어설션
2. `ready_for_fuse` 신호 감지 후 모든 Fuse 레지스터 쓰기
3. `CPTRA_FUSE_WR_DONE` 레지스터에 1 쓰기
4. `ready_for_fw` 신호 감지 후 FW 이미지 전송 (Passive 모드)
5. `ready_for_rtflows` 신호 감지 후 Runtime 커맨드 사용

---

## 4. 메일박스 (Mailbox) API

### 4.1 기본 특성

| 항목 | 내용 |
|------|------|
| 크기 | 128 KiB (Passive 모드) / 16 KiB (Subsystem 모드에서 Core 기준) |
| 인터페이스 | AXI Subordinate |
| 동시 접근 | LOCK 기반 상호 배제 |
| 사용자 식별 | AXI_USER 필드 (예약값: `0xFFFF_FFFF` = Caliptra 내부 전용) |

### 4.2 SoC → Caliptra 커맨드 전송 프로토콜 (8단계)

```c
/* Step 1: LOCK 획득 (읽기 시 0이면 LOCK 획득 성공, 1이면 타 디바이스 사용 중) */
while (MBOX_LOCK != 0);  /* LOCK = 0 반환 시 자동으로 LOCK = 1로 설정됨 */

/* Step 2: 커맨드 코드 설정 */
MBOX_CMD = command_code;

/* Step 3: 입력 데이터 길이 설정 (바이트 단위) */
MBOX_DLEN = input_data_length;

/* Step 4: 입력 데이터 쓰기 (32비트 단위, FIFO 방식) */
for (i = 0; i < ALIGN4(input_data_length) / 4; i++)
    MBOX_DATAIN = data_dwords[i];

/* Step 5: 실행 시작 */
MBOX_EXECUTE = 1;

/* Step 6: 완료 대기 (폴링 또는 인터럽트) */
do { status = MBOX_STATUS; } while (status == MBOX_STATUS_CMD_BUSY);

/* Step 7: 응답 데이터 읽기 (DATA_READY인 경우) */
if (status == MBOX_STATUS_DATA_READY) {
    uint32_t resp_len = MBOX_DLEN;
    for (i = 0; i < ALIGN4(resp_len) / 4; i++)
        resp_dwords[i] = MBOX_DATAOUT;
}

/* Step 8: LOCK 해제 */
MBOX_EXECUTE = 0;
```

### 4.3 MBOX_STATUS 값

| 값 | 상수명 | 의미 |
|----|--------|------|
| `0x00` | `MBOX_STATUS_CMD_BUSY` | 명령 처리 중 |
| `0x01` | `MBOX_STATUS_DATA_READY` | 응답 데이터 준비됨 (DATAOUT 읽기 필요) |
| `0x02` | `MBOX_STATUS_CMD_COMPLETE` | 명령 완료 (응답 데이터 없음) |
| `0x03` | `MBOX_STATUS_CMD_FAILURE` | 명령 실패 |

### 4.4 Caliptra → SoC 방향 (수신 프로토콜)

```c
/* mbox_data_avail 신호 또는 MBOX_STATUS 폴링으로 감지 */
cmd  = MBOX_CMD;
dlen = MBOX_DLEN;
for (i = 0; i < ALIGN4(dlen) / 4; i++)
    data[i] = MBOX_DATAOUT;

/* 응답 필요 시 (Caliptra→SoC 방향은 응답 불가) */
MBOX_STATUS = MBOX_STATUS_CMD_COMPLETE;  /* 또는 CMD_FAILURE */
```

> **제약**: SoC는 Caliptra 개시 커맨드에 대해 응답 데이터를 제공할 수 없습니다.

---

## 5. Runtime 펌웨어 커맨드

> **전체 커맨드 목록과 정확한 요청/응답 구조체**:  
> https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md

### 5.1 FW 로드 커맨드 (ROM 단계)

| 커맨드 | 코드 | 방향 | 설명 |
|--------|------|------|------|
| `FIRMWARE_LOAD` | `0x4657_4C44` | SoC→Caliptra | FW 이미지 전송. DLEN = FW 이미지 크기 |

FW 이미지 구조 (패키지 헤더 + TOC + 이미지):
```
[Manifest Header (magic: 'CMAN')]
[TOC Entry: FMC  (type 0x0000_0001)]
[TOC Entry: RT   (type 0x0000_0002)]
[FMC 섹션 (type 0x0000_0001 = Executable)]
[Runtime 섹션 (type 0x0000_0001 = Executable)]
```

### 5.2 측정 관련 커맨드 (Runtime)

| 커맨드 | 설명 |
|--------|------|
| `STASH_MEASUREMENT` | SoC 펌웨어 측정값을 Caliptra에 저장 (최대 8개, ROM/RT 모두 지원) |
| `EXTEND_PCR` | PCR4~PCR30에 측정값 확장 (RT 전용) |
| `GET_PCR_QUOTE` | PCR 값에 대한 서명된 Quote 생성 |
| `GET_FMC_ALIAS_CERT` | FMC Alias 인증서 반환 |
| `GET_RT_ALIAS_CERT` | Runtime Alias 인증서 반환 |

### 5.3 인증서 / 신원 커맨드

| 커맨드 | 설명 |
|--------|------|
| `GET_IDEVID_CSR` | IDevID Certificate Signing Request 반환 (1.2+) |
| `GET_FMC_ALIAS_CSR` | FMC Alias Key CSR 반환 (1.2+) |
| `CERTIFY_KEY` | DPE 리프 키 인증서 생성 |
| `CERTIFY_KEY_EXTENDED` | 확장 CERTIFY_KEY (1.1+) |

### 5.4 DPE 커맨드

| 커맨드 | 설명 |
|--------|------|
| `INVOKE_DPE_COMMAND` | DPE 커맨드 전달 (DeriveContext, CertifyKey, Sign, GetProfile 등) |

### 5.5 Authorization Manifest (1.2+)

| 커맨드 | 설명 |
|--------|------|
| `SET_AUTH_MANIFEST` | SoC 인증 매니페스트 설정 |
| `AUTHORIZE_AND_STASH` | 이미지 인증 및 측정값 stash |

### 5.6 암호화 커맨드 (2.0+ 신규)

| 커맨드 | 설명 |
|--------|------|
| `CRYPTO_IMPORT_KEY` | 암호화 키 임포트 (Key Handle 반환) |
| `CRYPTO_EXPORT_ECDH_KEY` | ECDH 공개키 익스포트 |
| `CRYPTO_ECDH_KEY_AGREE` | ECDH 키 합의 |
| `CRYPTO_SIGN` | ECDSA/ML-DSA 서명 |
| `CRYPTO_VERIFY` | 서명 검증 |
| `CRYPTO_HASH` | SHA384/SHA512 해시 계산 |
| `CRYPTO_HMAC` | HMAC 계산 |
| `CRYPTO_HKDF` | HKDF 키 파생 |
| `CRYPTO_ENCRYPT_AES` | AES-GCM/CCM 암호화 |
| `CRYPTO_DECRYPT_AES` | AES-GCM/CCM 복호화 |
| `CRYPTO_RNG` | 난수 생성 |
| `CRYPTO_ML_KEM_ENCAP` | ML-KEM 캡슐화 |
| `CRYPTO_ML_KEM_DECAP` | ML-KEM 탈캡슐화 |

---

## 6. MMIO 아키텍처 레지스터

> **정확한 주소**: https://ereg.caliptra.org 또는 https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraHardwareSpecification.md

Caliptra MMIO 레지스터는 SoC 통합 시 할당된 **베이스 주소**로부터의 오프셋으로 접근합니다.

### 6.1 메일박스 레지스터 오프셋

| 레지스터 | 오프셋 | R/W | 설명 |
|---------|--------|-----|------|
| `MBOX_LOCK` | `0x0000_1000` | RO | 읽기 시 0=LOCK 획득, 1=사용 중 |
| `MBOX_CMD` | `0x0000_1004` | RW | 커맨드 코드 |
| `MBOX_DLEN` | `0x0000_1008` | RW | 데이터 길이 (바이트) |
| `MBOX_DATAIN` | `0x0000_100C` | WO | 입력 데이터 (FIFO, 32비트 단위) |
| `MBOX_DATAOUT` | `0x0000_1010` | RO | 출력 데이터 (FIFO, 32비트 단위) |
| `MBOX_EXECUTE` | `0x0000_1014` | RW | 1=실행 시작, 0=LOCK 해제 |
| `MBOX_STATUS` | `0x0000_1018` | RO | 상태 (CMD_BUSY/DATA_READY/COMPLETE/FAILURE) |

### 6.2 핵심 제어 레지스터 오프셋

| 레지스터 | 오프셋 | R/W | 설명 |
|---------|--------|-----|------|
| `CPTRA_HW_ERROR_FATAL` | `0x0000_0000` | RW1C | 치명적 HW 오류 비트맵 (W1C 클리어) |
| `CPTRA_HW_ERROR_NON_FATAL` | `0x0000_0004` | RW1C | 비치명적 HW 오류 비트맵 |
| `CPTRA_FW_ERROR_FATAL` | `0x0000_0008` | RW1C | 치명적 FW 오류 비트맵 |
| `CPTRA_FW_ERROR_NON_FATAL` | `0x0000_000C` | RW1C | 비치명적 FW 오류 비트맵 |
| `CPTRA_HW_ERROR_ENC` | `0x0000_0010` | RO | 인코딩된 HW 오류 코드 |
| `CPTRA_FW_ERROR_ENC` | `0x0000_0014` | RO | 인코딩된 FW 오류 코드 |
| `CPTRA_FW_EXTENDED_ERROR_INFO` | `0x0000_0018` | RO | 확장 오류 정보 [7:0] |
| `CPTRA_BOOT_STATUS` | `0x0000_0038` | RO | 부트 상태 |
| `CPTRA_FLOW_STATUS` | `0x0000_003C` | RW | 플로우 상태 |
| `CPTRA_RESET_REASON` | `0x0000_0040` | RO | 리셋 원인 |
| `CPTRA_SECURITY_STATE` | `0x0000_0044` | RO | 현재 보안 상태 |
| `CPTRA_FUSE_WR_DONE` | `0x0000_00AC` | RW | 1=Fuse 쓰기 완료 (LOCK 설정) |
| `CPTRA_TIMER_CONFIG` | `0x0000_00B0` | RW | WDT 타이머 설정 |
| `CPTRA_BOOTFSM_GO` | `0x0000_00B4` | RW | 1=Boot FSM 진행 허용 (BootFSMBrk 해제용) |
| `CPTRA_DBG_MANUF_SERVICE_REG` | `0x0000_00B8` | RW | 제조/디버그 서비스 요청 |
| `CPTRA_CLKGATING_EN` | `0x0000_00C4` | RW | 클록 게이팅 활성화 |
| `CPTRA_GENERIC_INPUT_WIRES` | `0x0000_00C8` | RO | GENERIC_INPUT_WIRES[1:0] 값 읽기 |
| `CPTRA_GENERIC_OUTPUT_WIRES` | `0x0000_00D0` | RO | GENERIC_OUTPUT_WIRES[1:0] 값 읽기 |

### 6.3 Fuse 레지스터 오프셋

Fuse 레지스터는 `ready_for_fuse` 신호 이후, `CPTRA_FUSE_WR_DONE` 쓰기 전에만 기록 가능합니다.

| 레지스터 | 오프셋 | 크기 | 설명 |
|---------|--------|------|------|
| `CPTRA_FUSE_UDS_SEED` | `0x0000_0200` | 512 bit (16 DW) | UDS Seed (난독화됨) |
| `CPTRA_FUSE_FIELD_ENTROPY` | `0x0000_0240` | 256 bit (8 DW) | 필드 엔트로피 (2×128비트 슬롯) |
| `CPTRA_FUSE_VENDOR_PK_HASH` | `0x0000_0260` | 384 bit (12 DW) | 벤더 ECC+PQC 공개키 해시 |
| `CPTRA_FUSE_ECC_REVOCATION` | `0x0000_0290` | 4 bit | ECC 키 폐기 비트맵 (one-hot) |
| `CPTRA_FUSE_OWNER_PK_HASH` | `0x0000_02A0` | 384 bit (12 DW) | 소유자 공개키 해시 |
| `CPTRA_FUSE_FMC_KEY_MANIFEST_SVN` | `0x0000_02D0` | 32 bit | FMC SVN (Deprecated in 2.0) |
| `CPTRA_FUSE_RUNTIME_SVN` | `0x0000_02E0` | 128 bit (4 DW) | Runtime SVN (one-hot) |
| `CPTRA_FUSE_ANTI_ROLLBACK_DISABLE` | `0x0000_02F0` | 1 bit | Anti-rollback 비활성화 |
| `CPTRA_FUSE_IDEVID_CERT_ATTR` | `0x0000_02F4` | 768 bit (24 DW) | IDevID 인증서 속성 (352 bit 사용) |
| `CPTRA_FUSE_IDEVID_MANUF_HSM_ID` | `0x0000_0334` | 128 bit (4 DW) | 제조 HSM 식별자 (미사용) |
| `CPTRA_FUSE_LIFE_CYCLE` | `0x0000_0344` | 2 bit | 라이프사이클 상태 (Boot Media Integrated only) |
| `CPTRA_FUSE_LMS_REVOCATION` | `0x0000_0348` | 32 bit | LMS 키 폐기 (one-hot) |
| `CPTRA_FUSE_MLDSA_REVOCATION` | `0x0000_034C` | 4 bit | ML-DSA 키 폐기 (one-hot, 2.0+) |
| `CPTRA_FUSE_SOC_STEPPING_ID` | `0x0000_0350` | 16 bit | SoC 스테핑 ID |
| `CPTRA_FUSE_PQC_KEY_TYPE` | `0x0000_0360` | 2 bit | PQC 키 타입 (bit0=MLDSA, bit1=LMS) |
| `CPTRA_FUSE_SOC_MANIFEST_SVN` | `0x0000_0364` | 128 bit | SOC Manifest SVN |
| `CPTRA_FUSE_MANUF_DEBUG_UNLOCK_TOKEN` | `0x0000_0374` | 512 bit | 제조 디버그 언락 토큰 해시 |

---

## 7. Fuse 맵

### Fuse 쓰기 타이밍 규칙

```
cptra_rst_b 디어설션
    ↓
ready_for_fuse 어설션
    ↓
SoC가 모든 Fuse 레지스터 기록 (이 창에서만 가능)
    ↓
CPTRA_FUSE_WR_DONE = 1 (이후 Fuse 레지스터는 LOCK, 쓰기 무시)
    ↓
ready_for_fuse 디어설션
```

> **Warm reset 후**: LOCK은 sticky (유지됨). SoC는 다시 Fuse를 기록하고 `FUSE_WR_DONE` 설정 필요.

### Fuse 주요 항목

| 항목 | 크기 | 프로그래밍 시점 | 설명 |
|------|------|----------------|------|
| UDS Seed | 512 bit | 제조 | DICE 유일 식별자 시드. 난독화 저장. ROM만 접근 |
| Field Entropy | 256 bit | 현장 (소유자) | LDevID 갱신용. 2개 슬롯(각 128 bit) |
| Vendor PK Hash | 384 bit | 제조 | 벤더 ECDSA P384 + LMS/MLDSA 공개키 SHA384 해시 |
| Owner PK Hash | 384 bit | 현장 | 소유자 공개키 해시 |
| Runtime SVN | 128 bit | 현장 | Anti-rollback용 SVN (one-hot 인코딩) |
| PQC Key Type | 2 bit | 현장 | 사용할 PQC 알고리즘 선택 |
| Life Cycle | 2 bit | 제조 | `00`=비프로비저닝, `01`=제조, `11`=양산 |

---

## 8. DICE / DPE API

### 8.1 키 파생 체인

```
UDS Seed (Fuse, 난독화)
    │ (HW 기반 복호화 + DICE, Cold Boot에서만)
    ↓
IDevID Private Key [Key Vault, ROM만 접근]
    │ (ECDSA P384 + ML-DSA-87 이중 서명)
    ↓
IDevID 인증서 → 제조사 pCA가 서명 → IDevID Cert (DER)
    │
    │ (Field Entropy 포함 DICE 파생)
    ↓
LDevID Private Key
    │ (IDevID가 서명)
    ↓
LDevID 인증서
    │
    │ (FMC 측정값 포함 DICE 파생)
    ↓
FMC Alias Key → FMC Alias 인증서 (LDevID가 서명)
    │
    │ (RT 측정값 포함 DICE 파생)
    ↓
RT Alias Key → RT Alias 인증서 (FMC Alias가 서명)
    │
    │ (DPE Derive 통해 추가 파생)
    ↓
DPE Leaf Key → DPE Leaf 인증서 (RT Alias가 서명)
```

### 8.2 인증서 포맷

모든 Caliptra 2.0 인증서는 **ECDSA P384 + ML-DSA-87 이중 서명**을 포함합니다.

| 인증서 | 서명자 | 갱신 가능 | 용도 |
|--------|--------|----------|------|
| IDevID | 제조사 pCA | 불가 | 영구 하드웨어 신원 |
| LDevID | IDevID | 가능 (Field Entropy 재프로그래밍) | 소유자 신원 |
| FMC Alias | LDevID | 매 부팅 | FMC 코드 신원 |
| RT Alias | FMC Alias | 매 부팅 | Runtime 신원 |
| DPE Leaf | RT Alias | DPE Derive 시 | SoC 구성요소 신원 |

### 8.3 DPE (DICE Protection Environment)

DPE API는 메일박스의 `INVOKE_DPE_COMMAND` 커맨드를 통해 접근합니다.

주요 DPE 명령:
| DPE 명령 | 설명 |
|---------|------|
| `GetProfile` | 지원 프로파일 및 기능 조회 |
| `InitializeContext` | 새 DPE 컨텍스트 초기화 |
| `DeriveContext` | 측정값으로 새 컨텍스트 파생 |
| `CertifyKey` | 리프 키에 대한 인증서 발행 |
| `Sign` | 리프 키로 데이터 서명 |
| `RotateContextHandle` | 컨텍스트 핸들 갱신 |
| `DestroyContext` | 컨텍스트 폐기 |
| `ExtendTci` | TCI(측정값) 확장 |

---

## 9. PCR (측정값 저장소)

### PCR 뱅크 구조

| PCR 인덱스 | 값 크기 | 소유자 | 내용 |
|-----------|---------|--------|------|
| PCR0 | 384 bit | ROM | Caliptra ROM 측정값 |
| PCR1 | 384 bit | FMC | Caliptra FMC 측정값 |
| PCR2 | 384 bit | RT | Caliptra Runtime 측정값 |
| PCR3 | 384 bit | RT | Caliptra 구성 측정값 |
| PCR4~PCR30 | 384 bit each | RT | `EXTEND_PCR` 커맨드로 확장 |
| PCR31 | 384 bit | ROM+RT | 누적 측정값 (모든 STASH_MEASUREMENT 통합) |

### PCR 확장 방식

```
New_PCR = SHA384(Old_PCR || New_Measurement)
```

### 측정값 Stash 시 고려사항

- ROM 단계에서 최대 **8개**까지 stash 가능
- Runtime 로드 후 모두 PCR31에 통합됨
- 8개 초과 시 해당 부팅 세션의 증명(attestation)은 비활성화됨

---

## 10. 암호화 서비스 (2.0 신규)

### 지원 알고리즘

| 분류 | 알고리즘 |
|------|---------|
| 서명 | ECDSA P384, ML-DSA-87 (FIPS 204) |
| 키 교환 | ECDH P384, ML-KEM (FIPS 203) |
| 해시 | SHA-384, SHA-512 |
| MAC | HMAC-SHA384 |
| 키 파생 | HKDF |
| 대칭 암호 | AES-256-GCM, AES-256-CCM |
| 난수 | NIST SP800-90A CTR-DRBG |

### 키 관리

- 키는 **Key Handle**로 참조 (실제 키 소재는 Caliptra 내부 DCCM에 암호화 저장)
- Handle을 통해 서명/암호화 연산 수행
- SoC는 키 소재에 직접 접근 불가

---

## 11. OCP Recovery / Streaming Boot (서브시스템 모드)

### 11.1 Streaming Boot Interface 레지스터

BMC 등 외부 Recovery Agent가 I3C를 통해 접근:

| 레지스터 | 설명 |
|---------|------|
| `PROT_CAP` | 프로토콜 기능 비트맵 |
| `DEVICE_ID` | 디바이스 식별자 |
| `DEVICE_STATUS` | 현재 디바이스 상태 |
| `RECOVERY_CTRL` | 복구 제어 |
| `RECOVERY_STATUS` | 복구 진행 상태 |
| `INDIRECT_FIFO_CTRL` | FIFO 제어 (CMS, Reset, 이미지 크기) |
| `INDIRECT_FIFO_DATA` | FIFO 데이터 쓰기 포트 |
| `INDIRECT_FIFO_STATUS` | Head/Tail 포인터, 잔여 공간 |

### 11.2 스트리밍 부트 이미지 순서

```
이미지 0: Caliptra FW (ROM이 인증, ICCM 로드)
이미지 1: SoC Manifest (Caliptra RT가 인증)
이미지 2: MCU RT FW (Caliptra RT가 인증, MCU SRAM 로드)
이미지 3+: 나머지 SoC FW (MCU RT FW가 PLDM으로 수신, Caliptra로 인증)
```

### 11.3 관련 신호

| 신호 | 설명 |
|------|------|
| `payload_available` | FIFO에 256바이트 이상 적재됨 |
| `image_activated` | 이미지 활성화 완료 |

---

## 12. 보안 상태 (Security State)

`security_state[2:0]` 신호로 인코딩:

| 인코딩 | 상태 | 설명 |
|--------|------|------|
| `3'b000` | DebugUnlocked + Unprovisioned | 개발/Bring-up. UDS 없음. JTAG 오픈 |
| `3'b101` | DebugLocked + Manufacturing | 제조 단계. UDS 프로그래밍. JTAG 잠김 |
| `3'b111` | DebugLocked + Production | 양산. 모든 디버그 비활성화 |
| `3'b011` | DebugUnlocked + Production | 현장 디버그. 시크릿 Debug 키로 전환 |

> **보안 주의**: `scan_mode = 1` 어설션 시 Key Vault 포함 모든 시크릿 즉시 소거.

---

## 13. 오류 처리

### Fatal 오류 → `cptra_error_fatal` 신호 어설션

| 오류 종류 | 설명 |
|----------|------|
| ICCM/DCCM SRAM ECC | 교정 불가능한 ECC 오류 |
| Watchdog 타이머 만료 | 두 번째 WDT 만료 → NMI 발생 |
| 동시 실행 충돌 | HMAC, ECC, DOE 동시 동작 |
| CFI 오류 | Control Flow Integrity 위반 |
| KAT 실패 | Known Answer Test 실패 |
| FIPS 자체 테스트 실패 | 암호화 모듈 자체 테스트 실패 |
| FW 인증 실패 (Cold boot) | ROM 단계에서 서명 검증 실패 |

### Non-Fatal 오류 → `cptra_error_non_fatal` 신호 어설션

| 오류 종류 | 설명 |
|----------|------|
| Mailbox SRAM ECC | 교정 가능한 ECC 오류 |
| Mailbox 프로토콜 위반 | 잘못된 접근 순서, Lock 없이 접근 |
| FW 인증 실패 (Warm reset) | Warm reset 중 서명 검증 실패 |
| 암호화 처리 오류 | 연산 오류 |

### 오류 처리 시퀀스

```c
/* Fatal 오류 처리 */
if (cptra_error_fatal_detected()) {
    /* 1. 진행 중인 모든 Caliptra 커맨드를 실패로 처리 */
    abort_all_pending_commands();
    /* 2. 오류 코드 읽기 */
    uint32_t hw_err = CPTRA_HW_ERROR_FATAL;
    uint32_t fw_err = CPTRA_FW_ERROR_FATAL;
    log_caliptra_error(hw_err, fw_err);
    /* 3. Caliptra 리셋 (warm reset) */
    assert_cptra_rst_b();
    wait_microseconds(10);
    deassert_cptra_rst_b();
}

/* Non-fatal 오류 처리 */
if (cptra_error_non_fatal_detected()) {
    uint32_t hw_err = CPTRA_HW_ERROR_NON_FATAL;
    log_caliptra_non_fatal_error(hw_err);
    /* W1C: 오류 클리어 */
    CPTRA_HW_ERROR_NON_FATAL = hw_err;
}
```

---

## 14. JTAG 디버그 레지스터

JTAG TAP 레지스터 (7비트 주소):

| 레지스터 | JTAG 주소 | R/W |
|---------|-----------|-----|
| `MBOX_LOCK` | `7'h75` | RO |
| `MBOX_CMD` | `7'h76` | RW |
| `MBOX_DLEN` | `7'h50` | RW |
| `MBOX_DOUT` | `7'h51` | RO |
| `MBOX_DIN` | `7'h62` | WO |
| `MBOX_STATUS` | `7'h52` | RW |
| `MBOX_EXECUTE` | `7'h77` | WO |
| `BOOT_STATUS` | `7'h53` | RO |
| `CPTRA_HW_ERROR_ENC` | `7'h54` | RO |
| `CPTRA_FW_ERROR_ENC` | `7'h55` | RO |
| `HW_FATAL_ERROR` | `7'h58` | RO |
| `FW_FATAL_ERROR` | `7'h59` | RO |
| `HW_NON_FATAL_ERROR` | `7'h5A` | RO |
| `FW_NON_FATAL_ERROR` | `7'h5B` | RO |
| `CPTRA_DBG_MANUF_SERVICE_REG` | `7'h60` | RW |
| `BOOTFSM_GO` | `7'h61` | RW |
| `SS_DEBUG_INTENT` | `7'h63` | RW |
| `SS_CALIPTRA_BASE_ADDR_L` | `7'h64` | RW |
| `SS_CALIPTRA_BASE_ADDR_H` | `7'h65` | RW |

---

## 15. C/C++ 통합 가이드

### 15.1 최소 통합 체크리스트

- [ ] `cptra_pwrgood` → `cptra_rst_b` 타이밍 맞추기
- [ ] `security_state[2:0]` 올바른 값으로 구동
- [ ] `ready_for_fuse` 신호 감지 후 모든 Fuse 레지스터 기록
- [ ] `CPTRA_FUSE_WR_DONE = 1` 설정
- [ ] `ready_for_fw` 신호 후 FW 이미지 전송 (Passive 모드)
- [ ] `ready_for_rtflows` 신호 후 측정값 stash
- [ ] `cptra_error_fatal` 신호 핸들러 구현
- [ ] TRNG 설정 (외부 TRNG 사용 시)

### 15.2 외부 참조 (상세 레지스터/커맨드 코드)

| 문서 | 내용 |
|------|------|
| https://ereg.caliptra.org | 정확한 MMIO 레지스터 오프셋과 비트 필드 |
| https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraHardwareSpecification.md | HW 상세 스펙 |
| https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraIntegrationSpecification.md | SoC 통합 가이드 |
| https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md | Runtime 커맨드 코드 및 구조체 |
| https://github.com/chipsalliance/caliptra-sw/blob/main/error/src/lib.rs | 오류 코드 목록 |
| https://chipsalliance.github.io/caliptra-mcu-sw/ | MCU FW/SDK (서브시스템 모드) |
