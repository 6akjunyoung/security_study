# OCP L.O.C.K. API (2.1+)

> **관련 파일**
> - `include/caliptra_lock.h` — MEK 전달 API (고수준/저수준), MEK 블랍 구조체
> - `include/caliptra_crypto_ext.h` — 하위 암호화 서비스 (ECDH, ML-KEM, HKDF, AES-GCM)
> - `include/caliptra_types.h` — `CALIPTRA_ECC384_PUBKEY_SIZE`, `CALIPTRA_ML_KEM_1024_*`

---

## 1. 개요

**OCP L.O.C.K. (Layered Open Composable Key management)** 는 SoC Host가 SSD(NVMe 드라이브)에
MEK(Media Encryption Key)를 **안전하게 전달**하기 위한 OCP 표준 프로토콜입니다.

### 핵심 보안 속성

- SoC FW는 MEK의 **plaintext 값을 절대 보지 못합니다**.
- MEK는 Caliptra 내부 KV에서 파생되어, HPKE(Hybrid Public Key Encryption)로 암호화된 블랍 형태로만 SSD에 전달됩니다.
- 공격자가 SoC 메모리를 덤프해도 MEK를 복원할 수 없습니다.
- Caliptra 2.1+ 필요 (`pqc_key_type`, `hek_ratchet_seed` Fuse 기록 포함).

---

## 2. 키 계층 구조

```
[Fuse] HEK_RATCHET_SEED (256-bit)
    │  HKDF (Caliptra boot-time, FW 내부 자동 실행)
    ▼
[KV]  HEK  (Host Encryption Key, SoC FW 불가시)
    │  HKDF + (drive_serial[32], namespace_id)
    ▼
[KV]  MDK  (MEK Derivation Key, per-drive)
    │  HKDF + (namespace_id, lba_start, lba_count)
    ▼
[KV]  MEK  (Media Encryption Key, AES-256-XTS)
              ↓ HPKE 암호화 후
         [blob] → SSD (NVMe Key Programming)
```

각 키 파생 단계는 **Caliptra FW 내부**에서 자동으로 수행됩니다.
SoC FW는 `caliptra_lock_deliver_mek_*()` 호출 시 **MEK 핸들**을 전달하고,
암호화된 **MEK 블랍**을 돌려받습니다.

---

## 3. HPKE 모드 비교

| 모드 | KEM 알고리즘 | 전체 구성 | 보안 수준 | 권장 여부 |
|---|---|---|---|---|
| **ECDH** | DHKEM P-384 (RFC 9180) | ECDH + HKDF + AES-256-GCM | 128-bit (고전) | 고전 환경 |
| **ML-KEM** | ML-KEM-1024 (FIPS 203) | ML-KEM + HKDF + AES-256-GCM | 256-bit (양자 내성) | **양자 위협 대비** |
| **Hybrid** | ECDH + ML-KEM | 두 KEM 결합 + HKDF + AES-256-GCM | 고전 + 양자 동시 보장 | **최고 보안** |

> **권장**: 새로운 SoC 설계에서는 **Hybrid 모드**를 기본값으로 사용하세요.
> 고전 컴퓨터와 양자 컴퓨터 모두에 대한 보안을 동시에 보장합니다.

---

## 4. SoC 통합 체크리스트

### 제조 단계 (공장에서만)
- [ ] **`hek_ratchet_seed[8]`** Fuse 기록 (256-bit, HSM에서 생성). 이후 변경 불가.
- [ ] `pqc_key_type` Fuse: ML-KEM 지원 설정 (`bit0 = 1`).
- [ ] `life_cycle` Fuse: `CALIPTRA_LC_PRODUCTION` 설정.

### 하드웨어 설계 단계
- [ ] **`OCP_LOCK_ENABLE`** strap 설정 (PCB 레벨).
- [ ] NVMe 인터페이스: Identify 커맨드로 DPK(Drive Public Key) 수집 지원.
- [ ] NVMe Key Programming 커맨드 구현.

### SoC FW 구현
- [ ] Cold boot 완료 후 `caliptra_wait_for_rt_ready()` 확인.
- [ ] NVMe Identify로 드라이브 공개키(DPK) 수집.
- [ ] MEK 컨텍스트 설정: `drive_serial`, `namespace_id`, `lba_start/count`.
- [ ] `caliptra_lock_deliver_mek_*()` 호출 → MEK 블랍 획득.
- [ ] NVMe Key Programming 커맨드로 MEK 블랍 전달.
- [ ] MEK 블랍을 SoC 메모리에 장기 보존하지 않도록 설계.

---

## 5. 코드 예시 — ML-KEM HPKE (양자 내성 권장)

```c
#include "caliptra_lock.h"
#include <string.h>

caliptra_status_t setup_drive_encryption_mlkem(
    caliptra_ctx_t *ctx,
    nvme_drive_t   *drive,
    uint32_t        nsid)
{
    caliptra_status_t st;

    /* ──────────────────────────────────────────────
     * 1단계: NVMe Identify로 드라이브 ML-KEM 공개키 수집
     *   - SSD는 NVMe Identify 응답에 DPK(Drive Public Key) 포함
     *   - ML-KEM-1024 공개키: 1568바이트
     * ────────────────────────────────────────────── */
    uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE]; /* 1568B */
    st = nvme_get_drive_mlkem_pub_key(drive, drive_mlkem_pub);
    if (st != 0) return CALIPTRA_ERR_INVALID_PARAM;

    /* ──────────────────────────────────────────────
     * 2단계: MEK 컨텍스트 설정
     *   - drive_serial: HPKE 바인딩 (재생 공격 방지)
     *   - namespace_id, lba_range: 암호화 범위 바인딩
     * ────────────────────────────────────────────── */
    caliptra_lock_mek_context_t mek_ctx;
    memset(&mek_ctx, 0, sizeof(mek_ctx));

    nvme_get_drive_serial(drive, mek_ctx.drive_serial); /* 최대 32바이트 */
    mek_ctx.namespace_id = nsid;
    mek_ctx.lba_start    = 0;
    mek_ctx.lba_count    = 0;  /* 0 = 전체 네임스페이스 */

    /* ──────────────────────────────────────────────
     * 3단계: MEK 핸들 획득
     *   - Caliptra FW가 HEK → MDK → MEK 파생 후 핸들 반환
     *   - SoC FW는 MEK 원시 값 접근 불가
     * ────────────────────────────────────────────── */
    caliptra_key_handle_t mek_handle;
    st = caliptra_get_mek_handle(ctx, &mek_ctx, &mek_handle);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 4단계: ML-KEM HPKE MEK 전달 (원스텝)
     *   내부적으로:
     *     1. ML-KEM-ENCAP(drive_mlkem_pub) → (mlkem_ct, ss)
     *     2. HKDF(ss, mek_ctx) → wrap_key
     *     3. AES-256-GCM(mek_handle, wrap_key) → encrypted_mek
     * ────────────────────────────────────────────── */
    caliptra_lock_mlkem_mek_blob_t blob;
    st = caliptra_lock_deliver_mek_mlkem(
        ctx,
        drive_mlkem_pub,
        &mek_handle,
        &mek_ctx,
        &blob);
    if (st != CALIPTRA_OK) return st;

    /* ──────────────────────────────────────────────
     * 5단계: SSD에 MEK 블랍 전달
     *   - NVMe Key Programming 커맨드 사용
     *   - SSD가 자신의 ML-KEM 개인키로 복호화하여 MEK 획득
     * ────────────────────────────────────────────── */
    st = nvme_key_program(drive, nsid, &blob, sizeof(blob));
    if (st != 0) return CALIPTRA_ERR_CMD_FAILURE;

    return CALIPTRA_OK;
}
```

---

## 6. 코드 예시 — Hybrid HPKE (최고 보안)

ECDH와 ML-KEM 두 KEM을 동시에 사용하여, 고전 컴퓨터와 양자 컴퓨터 모두에 대한 보안을 보장합니다.

```c
#include "caliptra_lock.h"

caliptra_status_t setup_drive_encryption_hybrid(
    caliptra_ctx_t *ctx,
    nvme_drive_t   *drive,
    uint32_t        nsid)
{
    /* ECDH + ML-KEM 공개키 모두 수집 (NVMe Identify) */
    uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE];    /* 96B, X+Y */
    uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE]; /* 1568B */

    nvme_get_drive_ecdh_pub_key(drive, drive_ecdh_pub);
    nvme_get_drive_mlkem_pub_key(drive, drive_mlkem_pub);

    /* MEK 컨텍스트 및 핸들 설정 */
    caliptra_lock_mek_context_t mek_ctx;
    memset(&mek_ctx, 0, sizeof(mek_ctx));
    nvme_get_drive_serial(drive, mek_ctx.drive_serial);
    mek_ctx.namespace_id = nsid;

    caliptra_key_handle_t mek_handle;
    caliptra_get_mek_handle(ctx, &mek_ctx, &mek_handle);

    /* Hybrid HPKE 원스텝:
     *   1. ECDH(임시키, drive_ecdh_pub) → (ss_ecdh, eph_pub)
     *   2. ML-KEM-ENCAP(drive_mlkem_pub) → (mlkem_ct, ss_mlkem)
     *   3. HKDF(ss_ecdh || ss_mlkem, mek_ctx) → wrap_key
     *   4. AES-256-GCM(mek_handle, wrap_key) → encrypted_mek
     */
    caliptra_lock_hybrid_mek_blob_t blob;
    caliptra_status_t st = caliptra_lock_deliver_mek_hybrid(
        ctx,
        drive_ecdh_pub,
        drive_mlkem_pub,
        &mek_handle,
        &mek_ctx,
        &blob);
    if (st != CALIPTRA_OK) return st;

    /* SSD에 Hybrid MEK 블랍 전달 */
    return nvme_key_program(drive, nsid, &blob, sizeof(blob));
}
```

---

## 7. MEK 블랍 구조체 상세

SSD로 전달되는 MEK 블랍은 모드에 따라 구조가 다릅니다.

### `caliptra_lock_ecdh_mek_blob_t` (ECDH HPKE)

| 필드 | 크기 | 설명 |
|---|---|---|
| `eph_pub_key[96]` | 96 B | Caliptra 생성 임시 P-384 공개키. SSD가 ECDH 복원에 사용. |
| `iv[12]` | 12 B | AES-256-GCM IV. TRNG로 생성. |
| `tag[16]` | 16 B | AES-256-GCM 인증 태그. |
| `mek_ct_size` | 4 B | 암호화된 MEK 크기. |
| `mek_ct[]` | 가변 | 암호화된 MEK (AES-256-XTS 키, 64B). |

### `caliptra_lock_mlkem_mek_blob_t` (ML-KEM HPKE)

| 필드 | 크기 | 설명 |
|---|---|---|
| `mlkem_ct[1568]` | 1568 B | ML-KEM-1024 암호문. SSD의 ML-KEM 개인키로 복호화. |
| `iv[12]` | 12 B | AES-256-GCM IV. |
| `tag[16]` | 16 B | AES-256-GCM 인증 태그. |
| `mek_ct_size` | 4 B | 암호화된 MEK 크기. |
| `mek_ct[]` | 가변 | 암호화된 MEK. |

### `caliptra_lock_hybrid_mek_blob_t` (Hybrid HPKE)

| 필드 | 크기 | 설명 |
|---|---|---|
| `eph_pub_key[96]` | 96 B | ECDH 임시 공개키. |
| `mlkem_ct[1568]` | 1568 B | ML-KEM-1024 암호문. |
| `iv[12]` | 12 B | AES-256-GCM IV. |
| `tag[16]` | 16 B | AES-256-GCM 인증 태그. |
| `mek_ct_size` | 4 B | 암호화된 MEK 크기. |
| `mek_ct[]` | 가변 | 암호화된 MEK. |

---

## 8. 저수준 API 단계별 설명 (고급 사용자)

고수준 `caliptra_lock_deliver_mek_*()` 대신 단계별로 제어해야 할 경우 사용합니다.
예: 부분 실패 복구, 커스텀 AAD, 여러 네임스페이스 일괄 처리 등.

### ML-KEM 저수준 4단계

```c
#include "caliptra_lock.h"

caliptra_status_t deliver_mek_mlkem_lowlevel(
    caliptra_ctx_t               *ctx,
    const uint8_t                 drive_mlkem_pub[1568],
    const caliptra_key_handle_t  *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_mlkem_mek_blob_t    *blob)
{
    caliptra_status_t     st;
    caliptra_key_handle_t ss_handle;
    caliptra_key_handle_t wrap_key_handle;

    /* ── 단계 1: ML-KEM 캡슐화 ─────────────────────
     *   drive_mlkem_pub로 공유 비밀 생성
     *   mlkem_ct: SSD에 전달할 암호문
     * ─────────────────────────────────────────────── */
    st = caliptra_lock_mlkem_encap(ctx,
                                    drive_mlkem_pub,
                                    blob->mlkem_ct,    /* 출력: 1568B */
                                    &ss_handle);       /* 출력: 공유 비밀 핸들 */
    if (st != CALIPTRA_OK) return st;

    /* ── 단계 2: 래핑 키 파생 ─────────────────────
     *   HKDF(ss_handle, mek_context) → AES-256 래핑 키
     * ─────────────────────────────────────────────── */
    st = caliptra_lock_hpke_derive_wrap_key(ctx,
                                             &ss_handle,
                                             mek_ctx,
                                             &wrap_key_handle);
    if (st != CALIPTRA_OK) return st;

    /* ── 단계 3: IV 생성 (TRNG) ─────────────────── */
    st = caliptra_crypto_rng(ctx, CALIPTRA_AES_GCM_IV_SIZE, blob->iv);
    if (st != CALIPTRA_OK) return st;

    /* ── 단계 4: MEK 래핑 (AES-256-GCM) ─────────
     *   mek_handle: MEK KV 핸들 (plaintext 불가시)
     *   wrap_key_handle: 래핑 키 KV 핸들
     *   출력: encrypted_mek + tag
     * ─────────────────────────────────────────────── */
    const uint8_t *aad     = (const uint8_t *)mek_ctx;
    uint32_t       aad_len = sizeof(caliptra_lock_mek_context_t);

    st = caliptra_lock_wrap_mek(ctx,
                                 mek_handle,
                                 &wrap_key_handle,
                                 blob->iv,
                                 aad, aad_len,
                                 blob->mek_ct, &blob->mek_ct_size,
                                 blob->tag);
    return st;
}
```

### ECDH 저수준 4단계

```c
caliptra_status_t deliver_mek_ecdh_lowlevel(
    caliptra_ctx_t                *ctx,
    const uint8_t                  drive_ecdh_pub[96],
    const caliptra_key_handle_t   *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_ecdh_mek_blob_t *blob)
{
    caliptra_key_handle_t ss_handle;
    caliptra_key_handle_t wrap_key_handle;
    caliptra_status_t     st;

    /* 단계 1: ECDH 캡슐화 (임시키 내부 생성 포함) */
    st = caliptra_lock_ecdh_encap(ctx,
                                   drive_ecdh_pub,
                                   &ss_handle,       /* 공유 비밀 핸들 */
                                   blob->eph_pub_key); /* 임시 공개키 출력 */
    if (st != CALIPTRA_OK) return st;

    /* 단계 2: 래핑 키 파생 */
    st = caliptra_lock_hpke_derive_wrap_key(ctx, &ss_handle, mek_ctx, &wrap_key_handle);
    if (st != CALIPTRA_OK) return st;

    /* 단계 3: IV 생성 */
    caliptra_crypto_rng(ctx, CALIPTRA_AES_GCM_IV_SIZE, blob->iv);

    /* 단계 4: MEK 래핑 */
    const uint8_t *aad = (const uint8_t *)mek_ctx;
    return caliptra_lock_wrap_mek(ctx, mek_handle, &wrap_key_handle,
                                   blob->iv, aad, sizeof(*mek_ctx),
                                   blob->mek_ct, &blob->mek_ct_size, blob->tag);
}
```

---

## 9. 전체 플로우 요약

```
SoC FW                    Caliptra (내부)                  SSD
  │                            │                            │
  │ ── nvme_identify ──────────────────────────────────▶   │
  │ ◀──────────────────── DPK(drive_pub_key) ────────────  │
  │                            │                            │
  │ ── deliver_mek_*() ──────▶ │                           │
  │                       MEK 파생 (KV 내부)               │
  │                       HPKE 암호화 (KV 내부)            │
  │ ◀────────────── MEK 블랍 반환 ─                        │
  │                            │                            │
  │ ── nvme_key_program ───────────────────────────────▶   │
  │                            │         MEK 블랍 수신      │
  │                            │         HPKE 복호화        │
  │                            │         MEK 적용 (AES-XTS)│
```
