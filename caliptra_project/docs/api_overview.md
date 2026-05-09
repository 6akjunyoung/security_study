# Caliptra 2.x SoC API 개요

## 핵심 참조 파일

| 파일 | 역할 |
|------|------|
| `caliptra-sw/libcaliptra/inc/caliptra_api.h` | **모든 SoC 커맨드 API** (핵심 헤더) |
| `caliptra-sw/libcaliptra/inc/caliptra_types.h` | 요청/응답 구조체, `caliptra_buffer` |
| `caliptra-sw/libcaliptra/inc/caliptra_enums.h` | 에러 코드, DPE 커맨드, lifecycle |
| `caliptra-sw/libcaliptra/inc/caliptra_if.h` | 플랫폼 HAL (3개 함수) |
| `caliptra-sw/libcaliptra/src/caliptra_api.c` | libcaliptra 구현 (링크 필수) |

## 프로젝트 구조

```
caliptra_project/
├── include/
│   ├── caliptra_driver.h       플랫폼 HAL 가이드 + 3개 함수 선언
│   ├── caliptra_lock_types.h   OCP LOCK C 구조체 (caliptra-sw Rust 타입 미러)
│   └── caliptra_lock.h         OCP LOCK 커맨드 래퍼 API
└── src/
    ├── caliptra_driver.c       HAL 구현 템플릿 (플랫폼별 수정 필요)
    ├── caliptra_lock.c         OCP LOCK 구현
    └── caliptra_example.c      사용 예제
```

## 빌드 설정

```makefile
CFLAGS += -I caliptra-sw/libcaliptra/inc
CFLAGS += -I caliptra-sw/registers/generated-src
CFLAGS += -I caliptra_project/include

SRCS += caliptra-sw/libcaliptra/src/caliptra_api.c
SRCS += caliptra_project/src/caliptra_driver.c   # HAL (플랫폼별 수정)
SRCS += caliptra_project/src/caliptra_lock.c     # OCP LOCK
```

## 플랫폼 HAL (유일한 구현 의무)

libcaliptra는 3개 함수만 플랫폼에 요구합니다 (`caliptra-sw/libcaliptra/inc/caliptra_if.h`):

```c
int  caliptra_write_u32(uint32_t address, uint32_t data);
int  caliptra_read_u32(uint32_t address, uint32_t *data);
void caliptra_wait(void);
```

`caliptra_project/src/caliptra_driver.c`에서 SoC APB 버스에 맞게 구현합니다.

## API 카테고리

| 카테고리 | 주요 함수 | 문서 |
|----------|-----------|------|
| 부팅 플로우 | `caliptra_init_fuses`, `caliptra_upload_fw`, `caliptra_bootfsm_go` | [api_boot.md](api_boot.md) |
| 측정값/PCR | `caliptra_stash_measurement`, `caliptra_extend_pcr`, `caliptra_quote_pcrs_ecc384` | [api_measurement.md](api_measurement.md) |
| 인증서/DPE | `caliptra_get_idev_ecc384_cert`, `caliptra_invoke_dpe_command` | [api_attestation.md](api_attestation.md) |
| 이미지 인증 | `caliptra_set_auth_manifest`, `caliptra_authorize_and_stash` | [api_auth.md](api_auth.md) |
| 암호 서비스 | `caliptra_ecdsa384_verify`, `caliptra_mldsa87_verify`, `caliptra_lms_verify` | [api_crypto.md](api_crypto.md) |
| OCP L.O.C.K. | `caliptra_lock_generate_mek`, `caliptra_lock_load_mek` | [api_lock.md](api_lock.md) |

## 메일박스 프로토콜 (libcaliptra가 자동 처리)

```
SoC FW                     Caliptra Runtime FW
  │── lock acquire ──────►│
  │── write CMD ─────────►│
  │── write DLEN ────────►│
  │── write data ────────►│
  │── write EXECUTE=1 ───►│  (FW 처리)
  │◄── poll STATUS ───────│
  │◄── read response ─────│
  │── write EXECUTE=0 ───►│
```

체크섬 계산, FIPS 상태 검증, FSM 전환을 libcaliptra가 자동으로 처리합니다.

### 비동기 사용

```c
caliptra_fw_info(&resp, true);               // 비동기 발행
while (!caliptra_test_for_completion()) {    // 완료 폴링
    caliptra_wait();
}
caliptra_complete();                         // 응답 수집
```

## 에러 코드 (`caliptra_enums.h`)

| 코드 | 값 | 의미 |
|------|----|------|
| `NO_ERROR` | 0 | 성공 |
| `MBX_BUSY` | 0x300 | 메일박스 사용 중 |
| `MBX_STATUS_FAILED` | 0x303 | Caliptra FW 커맨드 실패 |
| `MBX_RESP_CHKSUM_INVALID` | 0x307 | 응답 체크섬 오류 |
| `INVALID_PARAMS` | 0x100 | 잘못된 파라미터 |
| `NOT_READY_FOR_FUSES` | 0x200 | Fuse 준비 안됨 |
| `STILL_READY_FOR_FUSES` | 0x201 | Fuse 완료 미확인 |
