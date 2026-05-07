# 인증서 & DPE API

> **관련 파일**
> - `include/caliptra_driver.h` — 인증서 획득 API, `caliptra_invoke_dpe`
> - `include/caliptra_types.h` — 공통 타입

---

## 1. DICE 인증서 체인

Caliptra는 **DICE(Device Identifier Composition Engine)** 표준에 따라 계층적 인증서 체인을 생성합니다.
각 계층은 이전 계층의 키로 서명되어, UDS(Unique Device Secret)까지 신뢰 사슬이 연결됩니다.

```
[Caliptra 내부 — Fuse/UDS에서 파생]

  UDS_SEED (Fuse, 512-bit)
      │ DICE KDF (Caliptra ROM 내부)
      ▼
  IDevID 키쌍 (P-384 + ML-DSA-87)
      │ 자체 서명 인증서 (IDevID Cert)
      ▼
  LDevID 키쌍 (ROM 단계, Field Entropy 반영)
      │ IDevID로 서명 (LDevID Cert)
      ▼
  FMC Alias 키쌍 (FMC 단계, FMC 측정값 반영)
      │ LDevID로 서명 (FMC Alias Cert)
      ▼
  RT Alias 키쌍 (Runtime 단계, RT 측정값 반영)
      │ FMC Alias로 서명 (RT Alias Cert)
      ▼
  DPE Leaf 키쌍 (동적, invoke_dpe로 파생)
      │ RT Alias로 서명 (DPE Leaf Cert)
```

### 각 인증서의 용도

| 인증서 | 파생 단계 | 주요 용도 |
|---|---|---|
| **IDevID** | ROM | 디바이스 고유 식별. 제조사가 PKI에 등록. |
| **LDevID** | ROM | Field-replaceable 식별. Field Entropy 포함. |
| **FMC Alias** | FMC | FMC 코드 무결성 증명. |
| **RT Alias** | Runtime | Runtime 서비스 서명 (PCR Quote, DPE 등). |
| **DPE Leaf** | Runtime (동적) | 소프트웨어 컴포넌트별 동적 인증서. |

---

## 2. 인증서 획득 API

모든 인증서 API는 동일한 패턴을 따릅니다:
- `cert_buf`: 인증서를 받을 버퍼 포인터
- `cert_size`: 입력 시 버퍼 크기, 출력 시 실제 인증서 크기

```c
#include "caliptra_driver.h"
#include <string.h>

/*
 * 전체 DICE 인증서 체인 획득 예시
 * 원격 Attestation 또는 PKI 등록 시 사용
 */
caliptra_status_t collect_dice_chain(caliptra_ctx_t *ctx,
                                      uint8_t *chain_buf,
                                      uint32_t chain_buf_size,
                                      uint32_t *total_len)
{
    caliptra_status_t st;
    uint32_t offset = 0;

    /* IDevID 인증서 획득 */
    uint32_t cert_size = chain_buf_size - offset;
    st = caliptra_get_idevid_cert(ctx, chain_buf + offset, &cert_size);
    if (st != CALIPTRA_OK) return st;
    offset += cert_size;

    /* LDevID 인증서 획득 */
    cert_size = chain_buf_size - offset;
    st = caliptra_get_ldevid_cert(ctx, chain_buf + offset, &cert_size);
    if (st != CALIPTRA_OK) return st;
    offset += cert_size;

    /* FMC Alias 인증서 획득 */
    cert_size = chain_buf_size - offset;
    st = caliptra_get_fmc_alias_cert(ctx, chain_buf + offset, &cert_size);
    if (st != CALIPTRA_OK) return st;
    offset += cert_size;

    /* RT Alias 인증서 획득 */
    cert_size = chain_buf_size - offset;
    st = caliptra_get_rt_alias_cert(ctx, chain_buf + offset, &cert_size);
    if (st != CALIPTRA_OK) return st;
    offset += cert_size;

    *total_len = offset;
    return CALIPTRA_OK;
}
```

### IDevID 인증서

```c
/* IDevID 인증서: 제조 단계에서 한 번만 획득 후 PKI에 등록 */
uint8_t  idevid_cert[2048];
uint32_t idevid_size = sizeof(idevid_cert);

caliptra_status_t st = caliptra_get_idevid_cert(&ctx, idevid_cert, &idevid_size);
/* idevid_cert는 DER 인코딩된 X.509 인증서 */
/* Subject에 soc_stepping_id, idevid_cert_attr Fuse 값이 포함됨 */
```

### LDevID 인증서

```c
/* LDevID 인증서: Field Entropy 반영 — 디바이스 교체 시 갱신 */
uint8_t  ldevid_cert[2048];
uint32_t ldevid_size = sizeof(ldevid_cert);

caliptra_get_ldevid_cert(&ctx, ldevid_cert, &ldevid_size);
```

### RT Alias 인증서

```c
/* RT Alias 인증서: PCR Quote 서명 키의 공개키 포함 */
/* 이 인증서로 PCR Quote 서명을 검증 가능 */
uint8_t  rt_cert[4096];  /* ML-DSA 공개키 포함 시 큰 버퍼 필요 */
uint32_t rt_size = sizeof(rt_cert);

caliptra_get_rt_alias_cert(&ctx, rt_cert, &rt_size);
```

---

## 3. DPE (DICE Protection Environment)

DPE는 **런타임에 동적으로** DICE 인증서를 파생할 수 있는 Caliptra의 핵심 기능입니다.
소프트웨어 컴포넌트별로 컨텍스트를 분리하고, 각 컨텍스트에서 고유 키/인증서를 생성합니다.

### DPE 커맨드 목록

| 커맨드 | 설명 |
|---|---|
| `InitializeContext` | 새 DPE 컨텍스트 초기화 (초기 측정값 주입) |
| `DeriveContext` | 기존 컨텍스트에서 자식 컨텍스트 파생 (측정값 확장) |
| `CertifyKey` | 컨텍스트 내 키를 인증서로 발급 (X.509 또는 CBOR) |
| `GetCertificateChain` | 루트부터 해당 컨텍스트까지 전체 인증서 체인 반환 |
| `Sign` | 컨텍스트 키로 메시지 서명 |
| `RotateContextHandle` | 컨텍스트 핸들 교체 (포워드 시크리시) |
| `DestroyContext` | 컨텍스트 폐기 |
| `GetProfile` | DPE 구현 프로파일 정보 반환 |
| `ExtendTci` | 현재 컨텍스트에 측정값 추가 확장 |

### `caliptra_invoke_dpe` 사용법

DPE 커맨드는 TLV(Type-Length-Value) 형식으로 직렬화하여 전달합니다.

```c
#include "caliptra_driver.h"
#include <string.h>

/*
 * DPE GetCertificateChain 커맨드 예시
 * 현재 DPE 컨텍스트의 전체 인증서 체인을 획득
 */

/* DPE 커맨드/응답 헤더 */
typedef struct __attribute__((packed)) {
    uint32_t magic;       /* 0x44504500 ('DPE\0') */
    uint32_t cmd;         /* 커맨드 코드 */
    uint32_t profile;     /* DPE 프로파일 ID */
} dpe_req_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;      /* 0=성공 */
    uint32_t profile;
} dpe_resp_hdr_t;

/* GetCertificateChain 요청 */
typedef struct __attribute__((packed)) {
    dpe_req_hdr_t hdr;
    uint32_t      context_handle[4];  /* 128-bit 컨텍스트 핸들 */
    uint16_t      retain_context;     /* 1=컨텍스트 유지 */
    uint16_t      clear_from_context; /* 1=요청 후 컨텍스트 삭제 */
    uint32_t      cert_format;        /* 0=X509, 1=CBOR */
} dpe_get_cert_chain_req_t;

caliptra_status_t dpe_get_certificate_chain(
    caliptra_ctx_t *ctx,
    const uint32_t  context_handle[4],
    uint8_t        *cert_chain_out,
    uint32_t       *cert_chain_size)
{
    dpe_get_cert_chain_req_t req;
    memset(&req, 0, sizeof(req));

    req.hdr.magic   = 0x44504500;
    req.hdr.cmd     = 0x07;     /* GET_CERTIFICATE_CHAIN 커맨드 코드 */
    req.hdr.profile = 0x00000001; /* DPE 프로파일 v1 */

    memcpy(req.context_handle, context_handle, 16);
    req.retain_context = 1;     /* 컨텍스트 유지 */
    req.cert_format    = 0;     /* X.509 DER 형식 */

    uint8_t  resp_buf[8192];    /* DPE 응답은 클 수 있음 */
    uint32_t resp_size = sizeof(resp_buf);

    caliptra_status_t st = caliptra_invoke_dpe(
        ctx,
        (const uint8_t *)&req, sizeof(req),
        resp_buf, &resp_size);

    if (st != CALIPTRA_OK) return st;

    /* 응답 헤더 확인 */
    dpe_resp_hdr_t *resp_hdr = (dpe_resp_hdr_t *)resp_buf;
    if (resp_hdr->status != 0) {
        return CALIPTRA_ERR_CMD_FAILURE;
    }

    /* 인증서 체인은 헤더 이후 */
    uint32_t chain_len = resp_size - sizeof(dpe_resp_hdr_t);
    memcpy(cert_chain_out, resp_buf + sizeof(dpe_resp_hdr_t), chain_len);
    *cert_chain_size = chain_len;

    return CALIPTRA_OK;
}

/*
 * DPE DeriveContext 예시
 * 부모 컨텍스트에서 측정값을 추가한 자식 컨텍스트 생성
 */
typedef struct __attribute__((packed)) {
    dpe_req_hdr_t hdr;
    uint32_t context_handle[4];
    uint8_t  measurement[CALIPTRA_SHA384_HASH_SIZE]; /* SHA-384, 48B */
    uint8_t  label[CALIPTRA_SHA384_HASH_SIZE];       /* 라벨, 48B */
    uint16_t allow_ca;          /* 1=CA 인증서 발급 허용 */
    uint16_t create_certificate; /* 1=즉시 인증서 생성 */
    uint32_t target_locality;   /* 0=기본 */
} dpe_derive_context_req_t;

caliptra_status_t dpe_derive_context(
    caliptra_ctx_t *ctx,
    const uint32_t  parent_handle[4],
    const uint8_t  *fw_measurement,    /* 새 컴포넌트 SHA-384 */
    uint32_t        child_handle_out[4])
{
    dpe_derive_context_req_t req;
    memset(&req, 0, sizeof(req));

    req.hdr.magic   = 0x44504500;
    req.hdr.cmd     = 0x02;     /* DERIVE_CONTEXT 커맨드 코드 */
    req.hdr.profile = 0x00000001;

    memcpy(req.context_handle, parent_handle, 16);
    memcpy(req.measurement, fw_measurement, CALIPTRA_SHA384_HASH_SIZE);

    /* 라벨: 컴포넌트 이름 (패딩 필요) */
    const char *label = "SOC_COMPONENT_v1";
    memcpy(req.label, label, strlen(label));

    req.create_certificate = 0; /* 나중에 CertifyKey로 생성 */

    uint8_t  resp_buf[256];
    uint32_t resp_size = sizeof(resp_buf);

    caliptra_status_t st = caliptra_invoke_dpe(
        ctx,
        (const uint8_t *)&req, sizeof(req),
        resp_buf, &resp_size);

    if (st != CALIPTRA_OK) return st;

    /* 응답에서 새 컨텍스트 핸들 추출 */
    dpe_resp_hdr_t *resp_hdr = (dpe_resp_hdr_t *)resp_buf;
    if (resp_hdr->status != 0) return CALIPTRA_ERR_CMD_FAILURE;

    memcpy(child_handle_out, resp_buf + sizeof(dpe_resp_hdr_t), 16);
    return CALIPTRA_OK;
}
```

---

## 4. 인증서 체인 검증 흐름

원격 Attestation 서버에서 DICE 체인을 검증하는 절차:

```
1. IDevID Cert 획득 → 제조사 CA로 서명 검증
2. LDevID Cert 획득 → IDevID로 서명 검증
3. FMC Alias Cert 획득 → LDevID로 서명 검증 + FMC 측정값 확인
4. RT Alias Cert 획득 → FMC Alias로 서명 검증 + RT 측정값 확인
5. PCR Quote 획득 → RT Alias 공개키로 서명 검증 + Nonce 확인
6. Stash Measurements → Quote 내 측정값과 기대값 비교
```

> **DPE Leaf 인증서**는 `DeriveContext` + `CertifyKey` 조합으로 생성됩니다.
> 각 소프트웨어 컴포넌트가 독립적인 DICE 신원을 가질 수 있습니다.
