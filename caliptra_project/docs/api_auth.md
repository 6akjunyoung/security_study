# 이미지 인증 API (Authorization Manifest)

> 레퍼런스: `caliptra-sw/libcaliptra/inc/caliptra_api.h`
> Runtime 준비 후 사용 가능

## 개요

Authorization Manifest는 SoC가 로드할 이미지(FW/앱)의 허용 해시 목록을 Caliptra에 등록합니다.
이후 `AUTHORIZE_AND_STASH`로 각 이미지의 인증 + 측정값 stash를 원자적으로 수행합니다.

## API 함수

### Authorization Manifest 설정

```c
// Caliptra에 Authorization Manifest 전달
// 반환: 0=성공, MBX_STATUS_FAILED=Caliptra가 거부
int caliptra_set_auth_manifest(
    struct caliptra_set_auth_manifest_req *req,
    bool async);
```

**매니페스트 플래그** (`caliptra_enums.h`):
```c
enum set_auth_manifest_manifest_flags {
    VENDOR_SIGNATURE_REQUIRED = (1UL << 0),  // Vendor 서명 검증 필수
};
```

### 이미지 인증 및 Stash

```c
// 이미지 해시가 Authorization Manifest와 일치하는지 검증
// 일치하면 measurement를 자동으로 stash
int caliptra_authorize_and_stash(
    struct caliptra_authorize_and_stash_req  *req,
    struct caliptra_authorize_and_stash_resp *resp,
    bool async);
```

**요청 구조체** (`caliptra_types.h`):
```c
struct caliptra_authorize_and_stash_req {
    struct caliptra_req_header hdr;
    uint8_t  fw_id[4];         // 이미지 식별자 (4바이트)
    uint8_t  measurement[48];  // SHA384 해시 (48바이트)
    uint8_t  context[48];      // 측정 컨텍스트 (48바이트)
    uint32_t svn;              // 보안 버전 번호
    uint32_t flags;            // SKIP_STASH = 0x1
    uint32_t source;           // IN_REQUEST = 0x1
    uint32_t image_size;       // 이미지 크기 (바이트)
};
```

**응답 구조체**:
```c
struct caliptra_authorize_and_stash_resp {
    struct caliptra_resp_header hdr;
    uint32_t auth_req_result;  // 인증 결과 (아래 열거형)
};
```

**인증 결과** (`caliptra_enums.h`):
```c
enum authorize_and_stash_auth_req_result {
    AUTHORIZE_IMAGE      = 0xDEADC0DE,  // 인증 성공
    IMAGE_NOT_AUTHORIZED = 0x21523F21,  // 해시 목록에 없음
    IMAGE_HASH_MISMATCH  = 0x8BFB95CB,  // 해시 불일치
};
```

**stash 플래그** (`caliptra_enums.h`):
```c
enum authorize_and_stash_flags {
    SKIP_STASH = (1UL << 0),  // stash 없이 인증만 수행
};

enum authorize_and_stash_source {
    IN_REQUEST = 0x1,  // measurement가 요청에 포함됨
};
```

## 사용 예제

```c
#include "caliptra_api.h"
#include "caliptra_enums.h"
#include <string.h>

// 1단계: Authorization Manifest 등록
int setup_auth_manifest(const uint8_t *manifest_data, uint32_t size)
{
    struct caliptra_set_auth_manifest_req req = {0};
    if (size > sizeof(req.manifest)) return -1;

    req.manifest_size = size;
    memcpy(req.manifest, manifest_data, size);
    // req.flags = VENDOR_SIGNATURE_REQUIRED; // 필요 시

    return caliptra_set_auth_manifest(&req, false);
}

// 2단계: 이미지 인증 + stash
int authorize_image(
    uint32_t fw_id,
    const uint8_t *image_hash_48,
    uint32_t image_size)
{
    struct caliptra_authorize_and_stash_req req = {0};
    memcpy(req.fw_id,       &fw_id,        4);
    memcpy(req.measurement, image_hash_48, 48);
    req.svn        = 0;
    req.flags      = 0;        // 0 = stash 포함
    req.source     = IN_REQUEST;
    req.image_size = image_size;

    struct caliptra_authorize_and_stash_resp resp = {0};
    int ret = caliptra_authorize_and_stash(&req, &resp, false);
    if (ret != NO_ERROR) return ret;

    switch (resp.auth_req_result) {
    case AUTHORIZE_IMAGE:
        return 0;  // 성공
    case IMAGE_NOT_AUTHORIZED:
        return -1; // 미등록 이미지
    case IMAGE_HASH_MISMATCH:
        return -2; // 해시 불일치 (변조 의심)
    default:
        return -3;
    }
}
```
