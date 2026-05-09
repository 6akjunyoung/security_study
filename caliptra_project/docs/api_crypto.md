# 암호 서비스 API

> 레퍼런스: `caliptra-sw/libcaliptra/inc/caliptra_api.h`
> Runtime 준비 후 사용 가능

## 개요

Caliptra는 서명 검증 서비스를 제공합니다.
키 생성/암호화 같은 범용 암호 서비스는 Caliptra의 역할이 아닙니다.
(OCP L.O.C.K.의 MEK 키 관리는 별도 — [api_lock.md](api_lock.md) 참조)

## 서명 검증 API

### ECDSA-384 검증

```c
// ECDSA-384 서명 검증
int caliptra_ecdsa384_verify(
    struct caliptra_ecdsa_verify_v2_req *req,
    bool async);
```

**요청 구조체** (`caliptra_types.h`):
```c
struct caliptra_ecdsa_verify_v2_req {
    struct caliptra_req_header hdr;
    uint8_t pub_key_x[48];  // P-384 공개키 X좌표
    uint8_t pub_key_y[48];  // P-384 공개키 Y좌표
    uint8_t signature_r[48]; // 서명 R값
    uint8_t signature_s[48]; // 서명 S값
    uint8_t sha384_digest[48]; // 검증할 해시 (SHA384)
};
```

### ML-DSA-87 검증

```c
// ML-DSA-87 서명 검증 (양자 내성, FIPS 204)
int caliptra_mldsa87_verify(
    struct caliptra_mldsa_verify_req *req,
    bool async);
```

### LMS 검증

```c
// LMS (Leighton-Micali Signature) 검증
int caliptra_lms_verify(
    struct caliptra_lms_verify_v2_req *req,
    bool async);
```

## FIPS API

### FIPS 버전 조회

```c
// FIPS 모드 및 버전 정보 조회
int caliptra_fips_version(
    struct caliptra_fips_version_resp *resp,
    bool async);
```

### FIPS 자체 테스트

```c
// FIPS 자체 테스트 시작
int caliptra_self_test_start(bool async);

// FIPS 자체 테스트 결과 확인
// 반환: 0=PASS, MBX_STATUS_FAILED=FAIL
int caliptra_self_test_get_results(bool async);
```

### Shutdown

```c
// Caliptra 안전 종료
int caliptra_shutdown(bool async);
```

## Capabilities 조회

```c
// Caliptra 지원 기능 비트맵 조회
// OCP LOCK 지원 여부: RT_OCP_LOCK (bit 65)
int caliptra_capabilities(
    struct caliptra_capabilities_resp *resp,
    bool async);
```

## 서명 검증 사용 예제

```c
#include "caliptra_api.h"
#include <string.h>

// ECDSA-384 서명 검증
int verify_ecdsa_signature(
    const uint8_t pub_x[48], const uint8_t pub_y[48],
    const uint8_t sig_r[48], const uint8_t sig_s[48],
    const uint8_t digest[48])
{
    struct caliptra_ecdsa_verify_v2_req req = {0};
    memcpy(req.pub_key_x,     pub_x,  48);
    memcpy(req.pub_key_y,     pub_y,  48);
    memcpy(req.signature_r,   sig_r,  48);
    memcpy(req.signature_s,   sig_s,  48);
    memcpy(req.sha384_digest, digest, 48);

    return caliptra_ecdsa384_verify(&req, false);
}

// FIPS 자체 테스트
int run_fips_self_test(void)
{
    int ret = caliptra_self_test_start(false);
    if (ret != NO_ERROR) return ret;

    return caliptra_self_test_get_results(false);
}
```

## 메모

Caliptra 2.x의 범용 암호화 서비스 (ECDH, AES, HKDF, ML-KEM 등)는
SoC FW 코드가 직접 호출하는 메일박스 커맨드로 노출되지 않습니다.
이러한 암호화 프리미티브는 Caliptra FW 내부에서만 사용되며,
OCP L.O.C.K. 프로토콜의 일부로 간접적으로 활용됩니다.
