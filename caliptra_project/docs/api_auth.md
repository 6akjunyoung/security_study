# Authorization Manifest API (1.2+)

> **관련 파일**
> - `include/caliptra_driver.h` — `caliptra_set_auth_manifest`, `caliptra_authorize_and_stash`
> - `include/caliptra_types.h` — `caliptra_mbox_resp_hdr_t`, `caliptra_status_t`

---

## 1. Authorization Manifest 목적

Authorization Manifest는 **SoC가 직접 허가할 이미지 목록**을 Caliptra에 등록하는 메커니즘입니다.
Caliptra Vendor/Owner FW 서명과는 별도로, SoC별 커스텀 이미지 인증 정책을 구현할 수 있습니다.

### 사용 시나리오

- SoC 부트 시, 여러 컴포넌트(부트로더, TEE, 펌웨어 등)를 순서대로 인증하고 측정값을 stash
- 동일한 API 호출로 **이미지 인증 + PCR 측정** 두 작업을 원자적으로 수행
- `SKIP_STASH` 플래그로 인증만 수행하고 측정은 건너뛸 수 있음

### Authorization Manifest vs. FW_LOAD 비교

| 항목 | FW_LOAD | Authorization Manifest |
|---|---|---|
| 대상 | Caliptra FW 자체 | SoC 커스텀 이미지 |
| 서명 키 | Vendor/Owner 키 (Fuse에 해시) | SoC Manifest Signing Key |
| 호출 시점 | Cold Boot 중 1회 | Runtime, 여러 번 호출 가능 |
| 측정 stash | 자동 | `authorize_and_stash`로 명시적 |

---

## 2. `caliptra_set_auth_manifest` — Manifest 등록

Authorization Manifest를 Caliptra Runtime에 등록합니다.
이후 `caliptra_authorize_and_stash()`로 매니페스트 내 이미지를 인증합니다.

### Manifest 구조

Authorization Manifest는 다음 섹션으로 구성됩니다:

```
[Authorization Manifest]
  ├── 헤더 (magic, version, flags)
  ├── 매니페스트 서명 공개키 (P-384 + ML-DSA)
  ├── 매니페스트 서명 (ECDSA + ML-DSA 이중 서명)
  └── 이미지 허가 목록 (ImageManifestList)
        ├── Entry[0]: { fw_id, digest, svn_min, flags }
        ├── Entry[1]: { fw_id, digest, svn_min, flags }
        └── ...
```

각 Entry의 `digest`는 해당 이미지의 SHA-384 해시입니다.
`fw_id`는 32-bit 이미지 식별자로, `authorize_and_stash` 호출 시 일치 여부를 확인합니다.

### 코드 예시

```c
#include "caliptra_driver.h"

/*
 * SoC Authorization Manifest 등록
 * manifest_buf: 서명된 매니페스트 바이너리 (HSM 또는 빌드 시 생성)
 */
caliptra_status_t register_auth_manifest(caliptra_ctx_t *ctx,
                                          const void    *manifest_buf,
                                          uint32_t       manifest_size)
{
    /* 매니페스트 크기 제한 확인 (128 KiB 메일박스 크기 이내) */
    if (manifest_size > CALIPTRA_MBOX_SIZE_BYTES) {
        return CALIPTRA_ERR_INVALID_PARAM;
    }

    caliptra_status_t st = caliptra_set_auth_manifest(ctx,
                                                        manifest_buf,
                                                        manifest_size);
    if (st != CALIPTRA_OK) {
        /* 실패 원인:
         *   CALIPTRA_ERR_CMD_FAILURE: 서명 검증 실패
         *   CALIPTRA_ERR_INVALID_PARAM: 매니페스트 형식 오류
         *   CALIPTRA_ERR_NOT_READY: Runtime 미준비
         */
        return st;
    }

    return CALIPTRA_OK;
}
```

---

## 3. `caliptra_authorize_and_stash` — 이미지 인증 + 측정값 Stash

등록된 Authorization Manifest를 참조하여 이미지를 인증하고, 성공 시 측정값을 stash합니다.
하나의 API 호출로 **인증과 측정이 원자적으로** 수행됩니다.

### 요청 구조체 (`caliptra_authorize_and_stash_req_t`)

| 필드 | 타입 | 크기 | 설명 |
|---|---|---|---|
| `fw_id` | `uint32_t` | 4 B | 이미지 식별자 (매니페스트의 Entry fw_id와 일치해야 함) |
| `measurement` | `uint8_t[48]` | 48 B | 이미지의 실제 SHA-384 해시 (런타임에 측정한 값) |
| `svn` | `uint32_t` | 4 B | 이미지의 Security Version Number |
| `flags` | `uint32_t` | 4 B | 제어 플래그 (아래 표 참조) |

### `flags` 비트필드

| 비트 | 상수 | 설명 |
|---|---|---|
| `bit[0]` | `CALIPTRA_AUTH_FLAG_SKIP_STASH` | stash를 건너뜀. 인증만 수행. |
| `bit[1]` | `CALIPTRA_AUTH_FLAG_REQUIRE_IMAGE_HASH` | 매니페스트의 digest와 measurement를 강제 비교. |
| 나머지 | — | 예약 (0으로 설정) |

### 응답 구조체 (`caliptra_authorize_and_stash_resp_t`)

| 필드 | 타입 | 크기 | 설명 |
|---|---|---|---|
| `hdr` | `caliptra_mbox_resp_hdr_t` | 8 B | 메일박스 응답 공통 헤더 (chksum, fips_status) |
| `auth_result` | `uint32_t` | 4 B | 인증 결과 (0=성공, 비영=실패 코드) |
| `dpe_result` | `uint32_t` | 4 B | DPE stash 결과 (0=성공, 비영=DPE 오류) |

### 코드 예시

```c
#include "caliptra_driver.h"
#include <string.h>

/*
 * SoC 부트로더 인증 + Stash 예시
 * 이미 caliptra_set_auth_manifest()로 매니페스트가 등록된 상태여야 함
 */
caliptra_status_t authorize_and_measure_bootloader(
    caliptra_ctx_t *ctx,
    const void     *bootloader_buf,
    uint32_t        bootloader_size)
{
    caliptra_authorize_and_stash_req_t  req;
    caliptra_authorize_and_stash_resp_t resp;

    memset(&req, 0, sizeof(req));

    /* 이미지 식별자: 프로젝트에서 사전 정의한 4바이트 ID */
    req.fw_id = 0x424C4400; /* 'BLD\0' — 부트로더 */

    /* 실제 이미지 SHA-384 계산 */
    platform_sha384(bootloader_buf, bootloader_size, req.measurement);

    /* SVN: 현재 부트로더 버전 */
    req.svn = BOOTLOADER_SVN;

    /* 인증 + Stash 동시 수행 (SKIP_STASH 플래그 없음) */
    req.flags = 0;

    caliptra_status_t st = caliptra_authorize_and_stash(ctx, &req, &resp);
    if (st != CALIPTRA_OK) return st;

    /* 응답 확인 */
    if (resp.auth_result != 0) {
        /* 인증 실패:
         *   - fw_id 미등록 (매니페스트에 없음)
         *   - measurement != 매니페스트 digest
         *   - SVN < svn_min (anti-rollback 위반)
         */
        return CALIPTRA_ERR_CMD_FAILURE;
    }

    if (resp.dpe_result != 0) {
        /* DPE stash 실패: 최대 8개 초과 또는 DPE 내부 오류 */
        /* 정책에 따라 계속 진행 또는 중단 */
    }

    return CALIPTRA_OK;
}

/*
 * 인증만 수행 (측정값 stash 없이)
 * 예: 이미 stash된 컴포넌트의 재인증
 */
caliptra_status_t authorize_only(caliptra_ctx_t *ctx,
                                  uint32_t        fw_id,
                                  const uint8_t  *image_digest)
{
    caliptra_authorize_and_stash_req_t  req;
    caliptra_authorize_and_stash_resp_t resp;

    memset(&req, 0, sizeof(req));
    req.fw_id   = fw_id;
    memcpy(req.measurement, image_digest, CALIPTRA_SHA384_HASH_SIZE);
    req.flags   = 0x01; /* SKIP_STASH: stash 건너뜀 */

    caliptra_status_t st = caliptra_authorize_and_stash(ctx, &req, &resp);
    if (st != CALIPTRA_OK) return st;

    return (resp.auth_result == 0) ? CALIPTRA_OK : CALIPTRA_ERR_CMD_FAILURE;
}
```

---

## 4. 전체 부트 인증 플로우

아래는 여러 SoC 컴포넌트를 순서대로 인증하는 일반적인 패턴입니다.

```c
#include "caliptra_driver.h"

caliptra_status_t soc_secure_boot_flow(caliptra_ctx_t *ctx)
{
    caliptra_status_t st;

    /* ── 준비 단계: Runtime 대기 후 Manifest 등록 ── */
    st = caliptra_wait_for_rt_ready(ctx);
    if (st != CALIPTRA_OK) return st;

    /* Authorization Manifest: 빌드 시스템에서 서명한 바이너리 */
    st = caliptra_set_auth_manifest(ctx,
                                     g_auth_manifest_bin,
                                     g_auth_manifest_size);
    if (st != CALIPTRA_OK) return st;

    /* ── 컴포넌트 0: 부트로더 인증 + 측정 ────────── */
    {
        caliptra_authorize_and_stash_req_t  req = { .fw_id = 0x424C4400,
                                                     .svn   = BL_SVN };
        caliptra_authorize_and_stash_resp_t resp;
        platform_sha384(g_bootloader, g_bootloader_size, req.measurement);

        st = caliptra_authorize_and_stash(ctx, &req, &resp);
        if (st != CALIPTRA_OK || resp.auth_result != 0) {
            caliptra_handle_fatal_error(ctx);
            return CALIPTRA_ERR_CMD_FAILURE;
        }
    }

    /* ── 컴포넌트 1: TEE 커널 인증 + 측정 ──────── */
    {
        caliptra_authorize_and_stash_req_t  req = { .fw_id = 0x54454500,
                                                     .svn   = TEE_SVN };
        caliptra_authorize_and_stash_resp_t resp;
        platform_sha384(g_tee_kernel, g_tee_kernel_size, req.measurement);

        st = caliptra_authorize_and_stash(ctx, &req, &resp);
        if (st != CALIPTRA_OK || resp.auth_result != 0) {
            caliptra_handle_fatal_error(ctx);
            return CALIPTRA_ERR_CMD_FAILURE;
        }
    }

    /* ── 컴포넌트 2: SoC FW 인증 (stash 생략) ───── */
    {
        caliptra_authorize_and_stash_req_t  req = { .fw_id = 0x53464D00,
                                                     .flags = 0x01 /* SKIP_STASH */ };
        caliptra_authorize_and_stash_resp_t resp;
        platform_sha384(g_soc_fw, g_soc_fw_size, req.measurement);

        st = caliptra_authorize_and_stash(ctx, &req, &resp);
        if (st != CALIPTRA_OK || resp.auth_result != 0) {
            caliptra_handle_fatal_error(ctx);
            return CALIPTRA_ERR_CMD_FAILURE;
        }
    }

    /* 모든 컴포넌트 인증 완료 → 부트 진행 */
    return CALIPTRA_OK;
}
```

---

## 5. 응답 해석 세부

### `auth_result` 코드

| 값 | 의미 |
|---|---|
| `0x00000000` | 인증 성공 |
| `0x00000001` | `fw_id`가 매니페스트에 없음 |
| `0x00000002` | `measurement`가 매니페스트 digest와 불일치 |
| `0x00000003` | Anti-rollback 위반 (SVN < `svn_min`) |
| `0x00000004` | 매니페스트 미등록 (`set_auth_manifest` 미호출) |
| `0x00000005` | 매니페스트 서명 검증 실패 |

### `dpe_result` 코드

| 값 | 의미 |
|---|---|
| `0x00000000` | stash 성공 (또는 SKIP_STASH 플래그 설정됨) |
| `0x00000001` | Stash 슬롯 초과 (최대 8개) |
| `0x00000002` | DPE 내부 오류 |

> `auth_result == 0` 이더라도 `dpe_result != 0`이면 측정값이 기록되지 않았습니다.
> 보안 정책에 따라 부트를 계속 진행할지 중단할지 결정하세요.

---

## 6. `caliptra_soc_manifest_svn` Fuse 연동

Authorization Manifest의 anti-rollback은 `soc_manifest_svn[4]` Fuse와 연동됩니다.
매니페스트의 `svn_min` 값이 Fuse의 `soc_manifest_svn`보다 작으면 인증이 거부됩니다.

```c
/* caliptra_fuse_t에서 SOC Manifest SVN 설정 */
caliptra_fuse_t fuse;
/* 128-bit one-hot: SVN 3까지 번인 (bit0~2 = 1) */
fuse.soc_manifest_svn[0] = 0x00000007; /* SVN 3 최소 */
```
