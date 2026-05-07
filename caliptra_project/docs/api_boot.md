# Boot 시퀀스 API

> **관련 파일**
> - `include/caliptra_driver.h` — 모든 부트/초기화 API 선언
> - `include/caliptra_types.h` — `caliptra_fuse_t`, `caliptra_lifecycle_t`, `caliptra_security_state_t`

---

## 1. HAL (Hardware Abstraction Layer) 구현

Caliptra 드라이버는 플랫폼 독립적으로 설계되어 있습니다.
SoC FW는 `caliptra_hw_ops_t` 구조체의 모든 콜백을 **플랫폼에 맞게 구현**해야 합니다.

```c
typedef struct {
    uint32_t (*reg_read)(uint32_t offset);
    void     (*reg_write)(uint32_t offset, uint32_t value);
    bool     (*is_ready_for_fuse)(void);
    bool     (*is_ready_for_fw)(void);
    bool     (*is_ready_for_rtflows)(void);
    bool     (*is_error_fatal)(void);
    bool     (*is_error_non_fatal)(void);
    void     (*delay_us)(uint32_t microseconds);
    void     (*log)(const char *fmt, ...);
} caliptra_hw_ops_t;
```

### 콜백 설명

| 콜백 | 반환 타입 | 설명 |
|---|---|---|
| `reg_read(offset)` | `uint32_t` | AXI MMIO 레지스터 읽기. `offset`은 Caliptra 베이스 주소 기준 오프셋 |
| `reg_write(offset, value)` | `void` | AXI MMIO 레지스터 쓰기 |
| `is_ready_for_fuse()` | `bool` | `FLOW_STATUS.ready_for_fuse` 비트 샘플링 |
| `is_ready_for_fw()` | `bool` | `FLOW_STATUS.ready_for_fw` 비트 샘플링 |
| `is_ready_for_rtflows()` | `bool` | `FLOW_STATUS.ready_for_rtflows` 비트 샘플링 |
| `is_error_fatal()` | `bool` | `HW_ERROR_FATAL` 레지스터 비어있지 않으면 true |
| `is_error_non_fatal()` | `bool` | `HW_ERROR_NON_FATAL` 레지스터 비어있지 않으면 true |
| `delay_us(us)` | `void` | 바쁜 대기(busy-wait). 폴링 루프 사이 삽입 |
| `log(fmt, ...)` | `void` | 디버그 로그 출력. `NULL`이면 비활성화 |

### HAL 구현 예시

```c
#include "caliptra_driver.h"

/* SoC별 베이스 주소 */
#define CALIPTRA_BASE_ADDR  0xA0000000UL

static uint32_t my_reg_read(uint32_t offset)
{
    return *((volatile uint32_t *)(CALIPTRA_BASE_ADDR + offset));
}

static void my_reg_write(uint32_t offset, uint32_t value)
{
    *((volatile uint32_t *)(CALIPTRA_BASE_ADDR + offset)) = value;
}

static bool my_ready_for_fuse(void)
{
    /* 플랫폼 GPIO/인터럽트 또는 직접 레지스터 확인 */
    uint32_t status = my_reg_read(CALIPTRA_REG_FLOW_STATUS);
    return (status & FLOW_STATUS_READY_FOR_FUSE_BIT) != 0;
}

static bool my_ready_for_fw(void)
{
    uint32_t status = my_reg_read(CALIPTRA_REG_FLOW_STATUS);
    return (status & FLOW_STATUS_READY_FOR_FW_BIT) != 0;
}

static bool my_ready_for_rt(void)
{
    uint32_t status = my_reg_read(CALIPTRA_REG_FLOW_STATUS);
    return (status & FLOW_STATUS_READY_FOR_RTFLOWS_BIT) != 0;
}

static bool my_is_fatal(void)
{
    return my_reg_read(CALIPTRA_REG_HW_ERROR_FATAL) != 0;
}

static void my_delay_us(uint32_t us)
{
    /* 플랫폼 타이머 기반 딜레이 */
    platform_udelay(us);
}

static void my_log(const char *fmt, ...)
{
    /* UART 또는 시스템 로그로 출력 */
    va_list ap;
    va_start(ap, fmt);
    platform_vprintf(fmt, ap);
    va_end(ap);
}

static caliptra_hw_ops_t my_ops = {
    .reg_read             = my_reg_read,
    .reg_write            = my_reg_write,
    .is_ready_for_fuse    = my_ready_for_fuse,
    .is_ready_for_fw      = my_ready_for_fw,
    .is_ready_for_rtflows = my_ready_for_rt,
    .is_error_fatal       = my_is_fatal,
    .is_error_non_fatal   = NULL,   /* 선택적 */
    .delay_us             = my_delay_us,
    .log                  = my_log,
};
```

---

## 2. Cold Boot 시퀀스 전체 예시

다음 코드는 Caliptra Cold Boot의 **완전한 시퀀스**를 보여줍니다.
각 단계는 반드시 순서대로 실행되어야 합니다.

```c
#include "caliptra_driver.h"
#include <string.h>

extern const uint8_t  g_fw_image[];
extern const uint32_t g_fw_size;

caliptra_status_t caliptra_cold_boot(void)
{
    caliptra_status_t st;
    caliptra_ctx_t    ctx;

    /* ──────────────────────────────────────────────
     * 1단계: 드라이버 초기화
     *   - HAL ops 포인터 연결
     *   - 메일박스 타임아웃 설정 (5초)
     * ────────────────────────────────────────────── */
    st = caliptra_driver_init(&ctx, &my_ops, 5000000 /* 5s timeout */);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 2단계: Fuse ready 대기
     *   - Caliptra가 리셋 후 FLOW_STATUS.ready_for_fuse를
     *     어설트할 때까지 폴링
     * ────────────────────────────────────────────── */
    st = caliptra_wait_for_fuse_ready(&ctx);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 3단계: Fuse 프로그래밍
     *   - 모든 Fuse 레지스터 기록 후 FUSE_WR_DONE 설정
     *   - 실제 배포에서는 UDS_SEED를 HSM에서 공급받아야 함
     * ────────────────────────────────────────────── */
    caliptra_fuse_t fuse;
    memset(&fuse, 0, sizeof(fuse));

    fuse.life_cycle      = CALIPTRA_LC_PRODUCTION;
    fuse.pqc_key_type    = 0x01;  /* ML-DSA 활성화 */
    fuse.soc_stepping_id = 0x0100; /* Major=1, Minor=0 */

    /* UDS Seed: 제조 단계에서 HSM으로부터 공급받은 값 */
    memcpy(fuse.uds_seed, g_uds_seed_from_hsm, CALIPTRA_UDS_SEED_SIZE);
    /* Field Entropy: 각 소자마다 고유한 256-bit 시드 */
    memcpy(fuse.field_entropy, g_field_entropy, CALIPTRA_FIELD_ENTROPY_SIZE);
    /* OCP L.O.C.K. 사용 시: HEK_RATCHET_SEED 기록 (2.1+) */
    memcpy(fuse.hek_ratchet_seed, g_hek_ratchet_seed, 32);

    st = caliptra_program_fuses(&ctx, &fuse);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 4단계: FW ready 대기
     *   - Caliptra ROM이 Fuse 로딩 완료 후
     *     FLOW_STATUS.ready_for_fw를 어설트할 때까지 폴링
     * ────────────────────────────────────────────── */
    st = caliptra_wait_for_fw_ready(&ctx);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 5단계: FW 이미지 로드
     *   - 메일박스 프로토콜로 FW_LOAD 커맨드 실행
     *   - FW 이미지는 ECC/ML-DSA 이중 서명 검증됨
     * ────────────────────────────────────────────── */
    st = caliptra_load_firmware(&ctx, g_fw_image, g_fw_size);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 6단계: Runtime ready 대기
     *   - FMC 및 Runtime FW 실행 완료 후
     *     FLOW_STATUS.ready_for_rtflows 어설트 대기
     * ────────────────────────────────────────────── */
    st = caliptra_wait_for_rt_ready(&ctx);
    if (st != CALIPTRA_OK) return st;

    /* 이제 모든 Runtime 커맨드 사용 가능 */
    return CALIPTRA_OK;
}
```

---

## 3. 보안 상태 / 라이프사이클

### 보안 상태 (`security_state[2:0]`)

`CPTRA_SECURITY_STATE` 레지스터에서 읽는 3비트 값입니다.

| 상태 | 값 | 설명 |
|---|---|---|
| `DBG_UNLOCKED_UNPROVISIONED` | `0b000` | Fuse 미기록, 디버그 열림. 개발 초기 상태. |
| `DBG_LOCKED_MANUFACTURING` | `0b101` | 제조 단계. Fuse 일부 기록, 디버그 잠금. |
| `DBG_UNLOCKED_PRODUCTION` | `0b011` | 프로덕션 Fuse 기록 완료, 디버그 열림. 부트 후 임시 상태. |
| `DBG_LOCKED_PRODUCTION` | `0b111` | 완전한 프로덕션 상태. 디버그 잠금. 정상 배포. |

### 라이프사이클 (`LIFE_CYCLE` Fuse)

| 상태 | 값 | 설명 |
|---|---|---|
| `CALIPTRA_LC_UNPROVISIONED` | `0b00` | Fuse 미기록 상태 |
| `CALIPTRA_LC_MANUFACTURING` | `0b01` | 제조 중 (Caliptra 키 생성 완료, SoC Fuse 기록 전) |
| `CALIPTRA_LC_UNDEFINED` | `0b10` | 미정의 (예약) |
| `CALIPTRA_LC_PRODUCTION` | `0b11` | 양산 상태. 정상 동작. |

> 라이프사이클은 **단방향**입니다. PRODUCTION으로 기록하면 되돌릴 수 없습니다.

---

## 4. `caliptra_fuse_t` 주요 필드

| 필드 | 크기 | 설명 |
|---|---|---|
| `uds_seed[16]` | 512 bit | UDS (Unique Device Secret). IDevID 키 파생 루트. HSM에서 공급. |
| `field_entropy[8]` | 256 bit | Field Entropy. 디바이스별 고유 시드 (2 슬롯 × 128-bit). |
| `vendor_pk_hash[12]` | 384 bit | Vendor FW 서명 공개키 해시 (SHA-384). |
| `owner_pk_hash[12]` | 384 bit | Owner FW 서명 공개키 해시 (SHA-384). |
| `ecc_revocation` | 4 bit | ECC 키 폐기 비트맵 (one-hot). |
| `lms_revocation` | 32 bit | LMS 키 폐기 비트맵. |
| `mldsa_revocation` | 4 bit | ML-DSA 키 폐기 비트맵 (2.0+). |
| `runtime_svn[4]` | 128 bit | Runtime FW 보안 버전 (one-hot anti-rollback). |
| `life_cycle` | 2 bit | 라이프사이클 (`caliptra_lifecycle_t`). |
| `pqc_key_type` | 2 bit | PQC 알고리즘 선택: bit0=ML-DSA, bit1=LMS. |
| `idevid_cert_attr[24]` | 768 bit | IDevID 인증서 속성 (Subject 정보 등). |
| `soc_stepping_id` | 16 bit | SoC 스테핑 ID. 인증서 Subject에 포함. |
| `anti_rollback_disable` | 1 bit | Anti-rollback 검사 비활성화 (개발용). |
| `hek_ratchet_seed[8]` | 256 bit | OCP L.O.C.K. HEK 생성 시드 (2.1+, in-field). |
| `manuf_debug_unlock_token[16]` | 512 bit | 제조 디버그 잠금 해제 토큰. |

---

## 5. 메일박스 8단계 프로토콜

`caliptra_mbox_send()`는 다음 8단계를 자동으로 처리합니다.
저수준 커맨드가 필요할 때만 `caliptra_mbox_cmd_t`를 직접 구성합니다.

| 단계 | 동작 | 레지스터 |
|---|---|---|
| 1 | Lock 획득 | `MBOX_LOCK` 쓰기 |
| 2 | CMD 기록 | `MBOX_CMD` 쓰기 |
| 3 | 데이터 길이 기록 | `MBOX_DLEN` 쓰기 |
| 4 | 데이터 기록 | `MBOX_DATAIN` 쓰기 (4B 단위) |
| 5 | Execute 신호 | `MBOX_EXECUTE` 쓰기 |
| 6 | STATUS 폴링 | `MBOX_STATUS` 읽기 (DATA_READY or FAILURE 대기) |
| 7 | 응답 데이터 읽기 | `MBOX_DATAOUT` 읽기 |
| 8 | Lock 해제 | `MBOX_STATUS` EXECUTE 클리어 |

---

## 6. 오류 처리

```c
/* Fatal 오류: 로깅 후 플랫폼에서 리셋 수행 */
if (caliptra_wait_for_rt_ready(&ctx) == CALIPTRA_ERR_FATAL) {
    caliptra_handle_fatal_error(&ctx);   /* 로그 덤프 */
    platform_reset();                    /* SoC 레벨 리셋 */
}

/* Non-fatal 오류: 클리어 후 재시도 가능 */
if (st == CALIPTRA_ERR_MBOX_STATUS) {
    caliptra_handle_non_fatal_error(&ctx);
    /* 재시도 로직... */
}
```

### 유틸리티 함수

```c
/* Runtime FW 버전 확인 */
uint32_t version;
caliptra_get_version(&ctx, &version);
uint16_t major = (version >> 16) & 0xFFFF;
uint16_t minor = version & 0xFFFF;

/* FIPS 자체 테스트 (양산 전 실행 권장) */
caliptra_status_t fips_st = caliptra_fips_self_test(&ctx);
if (fips_st != CALIPTRA_OK) {
    /* FIPS 테스트 실패 — 보안 정책에 따라 처리 */
}
```
