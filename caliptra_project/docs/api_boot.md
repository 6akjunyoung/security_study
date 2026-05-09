# Boot 시퀀스 API

> 레퍼런스: `caliptra-sw/libcaliptra/inc/caliptra_api.h`
> 실제 구현: `caliptra-sw/libcaliptra/src/caliptra_api.c`

## 부팅 흐름

```
caliptra_mbox_pauser_set_and_lock()  [선택] AXI PAUSER 설정
         │
         ▼
caliptra_ready_for_fuses()           Fuse 준비 대기
         │
         ▼
caliptra_init_fuses()                Fuse 프로그래밍 ⚠️ 시뮬레이션 전용
         │
         ▼
caliptra_bootfsm_go()                BootFSM 시작
         │
         ▼
caliptra_ready_for_firmware()        FW 업로드 준비 대기
         │
         ▼
caliptra_upload_fw()                 FW 업로드 (또는 start/send/end 분할)
         │
         ▼
caliptra_ready_for_runtime()         Runtime 준비 대기
         │
         ▼
[Runtime 커맨드 사용 가능]
```

## API 함수 목록

### PAUSER 설정

```c
// 메일박스 AXI PAUSER 슬롯 설정 및 잠금 (최대 5개 슬롯)
// 이미 잠긴 경우 PAUSER_LOCKED 반환
int caliptra_mbox_pauser_set_and_lock(uint32_t pauser);

// Fuse PAUSER 설정 및 잠금
int caliptra_fuse_pauser_set_and_lock(uint32_t pauser);
```

### WDT / itrng 설정

```c
// WDT 타임아웃 설정 (클럭 사이클 단위)
void caliptra_set_wdt_timeout(uint64_t timeout);

// iTRNG 엔트로피 임계값 설정
void caliptra_configure_itrng_entropy(uint16_t low, uint16_t high, uint16_t repetition);
```

### Fuse 프로그래밍

> ⚠️ **WARNING**: `caliptra_init_fuses()`는 시뮬레이션 전용입니다.
> 실 제품에서는 HW 상태 머신이 APB 버스로 Fuse 레지스터를 프로그래밍합니다.
> SoC FW는 Fuse 레지스터에 직접 접근하지 않습니다.

```c
// Fuse 준비 상태 확인 (논블로킹)
bool caliptra_ready_for_fuses(void);

// Fuse 프로그래밍 (시뮬레이션 전용)
// 반환: 0=성공, NOT_READY_FOR_FUSES, STILL_READY_FOR_FUSES, INVALID_PARAMS
int caliptra_init_fuses(const struct caliptra_fuses *fuses);
```

**`struct caliptra_fuses` 필드** (`caliptra_types.h`):

| 필드 | 크기 | 설명 |
|------|------|------|
| `uds_seed[16]` | 64B | UDS (Unique Device Secret) |
| `field_entropy[8]` | 32B | Field Entropy |
| `vendor_pk_hash[12]` | 48B | Vendor ECC/MLDSA 공개키 해시 |
| `ecc_revocation` | 4bit | ECC 키 폐기 마스크 |
| `owner_pk_hash[12]` | 48B | Owner 공개키 해시 |
| `fw_svn[4]` | 16B | FW 보안 버전 번호 |
| `anti_rollback_disable` | bool | Anti-rollback 비활성화 |
| `idevid_cert_attr[24]` | 96B | IDevID 인증서 속성 |
| `idevid_manuf_hsm_id[4]` | 16B | 제조 HSM ID |
| `life_cycle` | enum | 라이프사이클 (Unprovisioned/Manufacturing/Production) |
| `lms_revocation` | u32 | LMS 키 폐기 마스크 |
| `mldsa_revocation` | u32 | ML-DSA 키 폐기 마스크 |
| `fuse_pqc_key_type` | u32 | PQC 키 타입 |
| `soc_stepping_id` | u16 | SoC 스테핑 ID |

### BootFSM 제어

```c
// BootFSM Go 레지스터 설정 — Caliptra ROM 실행 시작
int caliptra_bootfsm_go(void);
```

### FW 업로드

```c
// FW 전체를 한 번에 업로드
int caliptra_upload_fw(const struct caliptra_buffer *fw_buffer, bool async);

// 대용량 FW를 청크로 나눠 업로드 (3단계)
int caliptra_upload_fw_start_req(uint32_t fw_size_in_bytes);
int caliptra_upload_fw_send_data(const struct caliptra_buffer *fw_buffer);
int caliptra_upload_fw_end_req(bool async);
```

### 상태 대기

```c
// FW 업로드 준비 대기 (블로킹, 에러 시 Caliptra 에러 코드 반환)
uint32_t caliptra_ready_for_firmware(void);

// FW 업로드 준비 확인 (논블로킹)
uint32_t caliptra_is_ready_for_firmware(void);

// Runtime 커맨드 처리 준비 대기 (블로킹)
uint32_t caliptra_ready_for_runtime(void);

// Runtime 준비 확인 (논블로킹)
uint32_t caliptra_is_ready_for_runtime(void);
```

### 에러 읽기

```c
// Non-fatal FW 에러 코드 읽기
uint32_t caliptra_read_fw_non_fatal_error(void);

// Fatal FW 에러 코드 읽기
uint32_t caliptra_read_fw_fatal_error(void);
```

### IDevID CSR 관리 (제조 단계)

```c
// IDevID CSR 요청 시작
void caliptra_req_idev_csr_start(void);

// IDevID CSR 준비 확인
bool caliptra_is_idevid_csr_ready(void);

// IDevID CSR 수신
int caliptra_retrieve_idevid_csr(struct caliptra_buffer *caliptra_idevid_csr);

// IDevID CSR 요청 완료
void caliptra_req_idev_csr_complete(void);
```

## 사용 예제

```c
#include "caliptra_api.h"
#include "caliptra_types.h"
#include "caliptra_enums.h"

int boot_caliptra(const uint8_t *fw_image, size_t fw_size)
{
    // 1. Fuse 준비 대기
    while (!caliptra_ready_for_fuses()) { caliptra_wait(); }

    // 2. Fuse 프로그래밍 (시뮬레이션 전용)
    struct caliptra_fuses fuses = {
        .life_cycle = Manufacturing,
        // ... 나머지 필드 설정
    };
    int ret = caliptra_init_fuses(&fuses);
    if (ret != NO_ERROR) return ret;

    // 3. BootFSM 시작
    caliptra_bootfsm_go();

    // 4. FW 업로드 준비 대기
    if (caliptra_ready_for_firmware() != NO_ERROR) {
        printf("Error: 0x%08X\n", caliptra_read_fw_fatal_error());
        return -1;
    }

    // 5. FW 업로드
    struct caliptra_buffer fw_buf = { .data = fw_image, .len = fw_size };
    ret = caliptra_upload_fw(&fw_buf, false);
    if (ret != NO_ERROR) return ret;

    // 6. Runtime 준비 대기
    return (int)caliptra_ready_for_runtime();
}
```
