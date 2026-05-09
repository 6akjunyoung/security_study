# 측정값 & PCR API

> 레퍼런스: `caliptra-sw/libcaliptra/inc/caliptra_api.h`
> Runtime 준비 후 사용 가능 (stash는 Boot 단계에서도 가능)

## PCR 구조

Caliptra는 32개의 PCR을 유지합니다:

| PCR | 사용처 |
|-----|--------|
| PCR0 | 부팅 정보 (FMC 측정값 등) |
| PCR1~3 | Caliptra FW 내부 사용 |
| PCR4~30 | SoC 사용 가능 (EXTEND_PCR) |
| PCR31 | 예약 |

## Stash Measurement

```c
// SoC 측정값 stash (최대 8개)
// ROM 단계 및 Runtime 단계 모두 사용 가능
int caliptra_stash_measurement(
    struct caliptra_stash_measurement_req  *req,
    struct caliptra_stash_measurement_resp *resp,
    bool async);
```

**요청 구조체** (`caliptra_types.h`):
```c
struct caliptra_stash_measurement_req {
    struct caliptra_req_header hdr;
    uint8_t  metadata[4];     // SoC 정의 컨텍스트 (4바이트)
    uint8_t  measurement[48]; // SHA384 해시 (48바이트)
    uint8_t  context[48];     // 측정 컨텍스트 (48바이트)
    uint32_t svn;             // 보안 버전 번호
};
```

## PCR 확장

```c
// PCR 확장 (SoC 사용 PCR: 4~30)
int caliptra_extend_pcr(
    struct caliptra_extend_pcr_req *req, bool async);
```

## PCR Reset Counter

```c
// PCR Reset Counter 증가 (재부팅 추적)
int caliptra_increment_pcr_reset_counter(
    struct caliptra_increment_pcr_reset_counter_req *req, bool async);
```

## PCR Quote

PCR 값에 대한 서명된 증명을 획득합니다.

```c
// ECC384 PCR Quote
int caliptra_quote_pcrs_ecc384(
    struct caliptra_quote_pcrs_req        *req,
    struct caliptra_quote_pcrs_ecc384_resp *resp,
    bool async);

// MLDSA87 PCR Quote (양자 내성)
int caliptra_quote_pcrs_mldsa87(
    struct caliptra_quote_pcrs_req         *req,
    struct caliptra_quote_pcrs_mldsa87_resp *resp,
    bool async);
```

**요청 구조체**:
```c
struct caliptra_quote_pcrs_req {
    struct caliptra_req_header hdr;
    uint8_t nonce[32]; // 신선도 논스 (재전송 공격 방지)
};
```

## DPE Reallocate Context Limits

```c
// DPE 컨텍스트 제한 재할당
int caliptra_reallocate_dpe_context_limits(
    struct caliptra_reallocate_dpe_context_limits_req  *req,
    struct caliptra_reallocate_dpe_context_limits_resp *resp,
    bool async);
```

## 사용 예제

```c
#include "caliptra_api.h"
#include <string.h>

// 부팅 중 컴포넌트 측정값 stash
int stash_component(const uint8_t *sha384_hash)
{
    struct caliptra_stash_measurement_req req = {0};
    memcpy(req.measurement, sha384_hash, 48);
    req.svn = 1;

    struct caliptra_stash_measurement_resp resp = {0};
    return caliptra_stash_measurement(&req, &resp, false);
}

// PCR4에 측정값 확장
int extend_soc_pcr(const uint8_t *data_48bytes)
{
    struct caliptra_extend_pcr_req req = {0};
    req.pcr_idx = 4;
    memcpy(req.data, data_48bytes, 48);
    return caliptra_extend_pcr(&req, false);
}

// PCR Quote 획득 (ECC384)
int get_pcr_quote(const uint8_t nonce[32])
{
    struct caliptra_quote_pcrs_req req = {0};
    memcpy(req.nonce, nonce, 32);

    struct caliptra_quote_pcrs_ecc384_resp resp = {0};
    return caliptra_quote_pcrs_ecc384(&req, &resp, false);
}
```
