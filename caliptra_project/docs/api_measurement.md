# 측정값 & PCR API

> **관련 파일**
> - `include/caliptra_driver.h` — `caliptra_stash_measurement`, `caliptra_extend_pcr`, `caliptra_get_pcr_quote`
> - `include/caliptra_types.h` — `caliptra_pcr_index_t`, `CALIPTRA_PCR_SIZE`

---

## PCR 인덱스 표

Caliptra는 총 32개의 PCR(Platform Configuration Register)을 관리합니다.

| PCR | 용도 | 소유자 | 지원 단계 |
|---|---|---|---|
| PCR0 | Caliptra ROM 측정값 | Caliptra 내부 | ROM |
| PCR1 | Caliptra FMC 측정값 | Caliptra 내부 | FMC |
| PCR2 | Caliptra Runtime 측정값 | Caliptra 내부 | Runtime |
| PCR3 | Caliptra 구성 측정값 | Caliptra 내부 | ROM/FMC |
| PCR4~30 | SoC FW 측정값 | **SoC FW** | ROM + Runtime |
| PCR31 | 누적 측정값 (모든 PCR 합산) | Caliptra 내부 | — |

> PCR0~3 및 PCR31은 Caliptra 내부에서만 갱신됩니다. SoC FW는 PCR4~30만 사용합니다.

---

## 1. Stash Measurement

`caliptra_stash_measurement()`는 SoC FW에서 측정한 컴포넌트 해시를 Caliptra에 전달합니다.
Caliptra는 이 값을 내부적으로 보관하고, DICE 인증서 체인 및 PCR Quote에 반영합니다.

### 특징
- **최대 8개** 측정값 stash 가능 (ROM 단계 + Runtime 단계 합산)
- ROM 단계와 Runtime 단계 모두 호출 가능
- 각 측정값은 SHA-384 해시(48바이트)

### 요청 구조체 (`caliptra_stash_measurement_req_t`)

| 필드 | 타입 | 크기 | 설명 |
|---|---|---|---|
| `metadata` | `uint8_t[4]` | 4 B | 측정 대상 식별자 (FW ID, 컴포넌트 등) |
| `measurement` | `uint8_t[48]` | 48 B | SHA-384 해시 값 |
| `context` | `uint8_t[48]` | 48 B | 측정 컨텍스트 (선택적, 0-fill 가능) |
| `svn` | `uint32_t` | 4 B | Security Version Number |

### 코드 예시

```c
#include "caliptra_driver.h"
#include <string.h>

/* SoC FW 이미지의 SHA-384를 측정하여 stash */
caliptra_status_t measure_soc_fw(caliptra_ctx_t *ctx,
                                  const uint8_t *fw_buf,
                                  uint32_t       fw_size)
{
    caliptra_stash_measurement_req_t req;
    memset(&req, 0, sizeof(req));

    /* 컴포넌트 식별자 — 프로젝트 정의 4바이트 ID */
    req.metadata[0] = 'S';
    req.metadata[1] = 'O';
    req.metadata[2] = 'C';
    req.metadata[3] = '0';

    /* SHA-384 계산 (플랫폼 SHA 엔진 또는 Caliptra crypto 사용) */
    platform_sha384(fw_buf, fw_size, req.measurement);

    /* SVN: 현재 FW 버전 */
    req.svn = SOC_FW_SVN;

    caliptra_status_t st = caliptra_stash_measurement(ctx, &req);
    if (st != CALIPTRA_OK) {
        /* stash 실패 — 최대 8개 초과 또는 타임아웃 */
        return st;
    }
    return CALIPTRA_OK;
}

/* 여러 컴포넌트 측정 (최대 8개까지 반복 호출 가능) */
void measure_all_components(caliptra_ctx_t *ctx)
{
    /* 컴포넌트 0: 부트로더 */
    measure_soc_fw(ctx, g_bootloader_buf, g_bootloader_size);

    /* 컴포넌트 1: 설정 블랍 */
    caliptra_stash_measurement_req_t cfg_req = {
        .metadata    = {'C', 'F', 'G', '0'},
        .svn         = 1,
    };
    platform_sha384(g_config_buf, g_config_size, cfg_req.measurement);
    caliptra_stash_measurement(ctx, &cfg_req);

    /* ... 최대 8번 반복 */
}
```

---

## 2. Extend PCR

`caliptra_extend_pcr()`는 **Runtime 단계 전용**으로, PCR4~30에 새 측정값을 확장합니다.
확장(extend) 연산은 `PCR[n] = SHA-384(PCR[n] || measurement)` 방식으로 누적됩니다.

> **주의**: PCR 확장은 Runtime FW가 실행 중일 때만(`caliptra_wait_for_rt_ready()` 이후) 호출 가능합니다.

### 코드 예시

```c
#include "caliptra_driver.h"

/* PCR5에 동적 설정값 측정 확장 */
caliptra_status_t extend_runtime_config(caliptra_ctx_t *ctx,
                                         const void *config_data,
                                         uint32_t    config_size)
{
    uint8_t digest[CALIPTRA_SHA384_HASH_SIZE];

    /* SHA-384 계산 */
    platform_sha384(config_data, config_size, digest);

    /* PCR5에 확장 (CALIPTRA_PCR_SOC_BASE = 4) */
    caliptra_status_t st = caliptra_extend_pcr(ctx,
                                                CALIPTRA_PCR_SOC_BASE + 1, /* PCR5 */
                                                digest);
    if (st != CALIPTRA_OK) {
        /* CALIPTRA_ERR_INVALID_PARAM: 허용 범위(4~30) 초과 */
        return st;
    }
    return CALIPTRA_OK;
}
```

### PCR 인덱스 유효 범위

```c
/* 유효한 SoC PCR 인덱스 */
#define VALID_SOC_PCR(idx)  ((idx) >= CALIPTRA_PCR_SOC_BASE && \
                              (idx) <= CALIPTRA_PCR_SOC_MAX)
/* CALIPTRA_PCR_SOC_BASE = 4, CALIPTRA_PCR_SOC_MAX = 30 */
```

---

## 3. Get PCR Quote

`caliptra_get_pcr_quote()`는 **서명된 PCR 스냅샷**을 반환합니다.
원격 검증자(Relying Party)가 SoC의 부트 측정값을 검증할 때 사용합니다.

### 특징
- **Nonce 기반** 신선도 보장 (재생 공격 방지)
- PCR Quote는 Caliptra의 **RT Alias 키**로 ECDSA/ML-DSA 이중 서명
- Quote 형식은 CBOR 직렬화된 CoRIM/EAT 토큰

### 코드 예시

```c
#include "caliptra_driver.h"
#include <string.h>

/* Attestation 서버로부터 받은 nonce로 PCR Quote 생성 */
caliptra_status_t get_pcr_quote_for_attestation(
    caliptra_ctx_t *ctx,
    const uint8_t  *server_nonce,   /* 서버가 제공한 32바이트 난수 */
    uint8_t        *quote_out,
    uint32_t       *quote_size_out)
{
    /* quote_buf는 충분히 크게 할당 (일반적으로 4KB 이상) */
    uint8_t  quote_buf[4096];
    uint32_t quote_size = sizeof(quote_buf);

    caliptra_status_t st = caliptra_get_pcr_quote(ctx,
                                                    server_nonce,
                                                    quote_buf,
                                                    &quote_size);
    if (st == CALIPTRA_ERR_BUFFER_TOO_SMALL) {
        /* quote_size에 필요한 크기가 반환됨 — 버퍼 재할당 필요 */
        return st;
    }
    if (st != CALIPTRA_OK) return st;

    /* 결과 복사 */
    memcpy(quote_out, quote_buf, quote_size);
    *quote_size_out = quote_size;
    return CALIPTRA_OK;
}

/* 원격 Attestation 전체 흐름 예시 */
void remote_attestation_flow(caliptra_ctx_t *ctx)
{
    /* 1. Attestation 서버에서 nonce 수신 */
    uint8_t nonce[32];
    attestation_server_get_nonce(nonce);

    /* 2. PCR Quote 생성 */
    uint8_t  quote[4096];
    uint32_t quote_size;
    caliptra_get_pcr_quote(ctx, nonce, quote, &quote_size);

    /* 3. Quote를 서버로 전송 */
    attestation_server_send_quote(quote, quote_size);

    /* 4. 서버에서 검증: IDevID 인증서 체인 + Quote 서명 확인 */
}
```

---

## 4. 측정값 흐름 전체 그림

```
[ROM 단계]
  Caliptra ROM 자체 측정 → PCR0 (내부 자동)
  SoC caliptra_stash_measurement() → 최대 4개 stash

[FMC 단계]
  Caliptra FMC 측정값 → PCR1 (내부 자동)

[Runtime 단계]
  Caliptra RT FW 측정 → PCR2 (내부 자동)
  SoC caliptra_stash_measurement() → 남은 stash 슬롯
  SoC caliptra_extend_pcr(PCR4~30) → 동적 측정 누적

[Attestation]
  caliptra_get_pcr_quote(nonce) → 서명된 Quote
      └ PCR 스냅샷 + RT Alias 서명 → 원격 검증자 전달
```

> **Stash vs Extend**: Stash는 **DICE 인증서 체인 생성 시** 참조되는 정적 측정값,
> Extend는 **Runtime 동안 동적으로 누적**되는 PCR 값입니다. 두 API는 보완적으로 사용합니다.
