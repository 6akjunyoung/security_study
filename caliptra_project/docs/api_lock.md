# OCP L.O.C.K. API (Caliptra 2.1+)

> 레퍼런스:
> - `caliptra_project/include/caliptra_lock.h` — SoC API
> - `caliptra_project/include/caliptra_lock_types.h` — C 구조체
> - `caliptra-sw/api/src/mailbox.rs` — Rust 커맨드 코드 및 구조체 (정식 소스)
> - `caliptra-sw/runtime/src/ocp_lock/` — Runtime FW 구현
> - OCP_LOCK_Specification_v1.0_RC2.pdf — 프로토콜 스펙

## 개요

OCP L.O.C.K.은 SSD MEK(Media Encryption Key) 보안 전달 프로토콜입니다.

**핵심 원칙:**
- Caliptra가 MEK를 생성/파생/봉인합니다
- MEK plaintext는 SoC FW에 절대 노출되지 않습니다
- HPKE를 통해 암호화된 MEK만 SSD에 전달됩니다
- Customer가 MPK(Managed Platform Key)로 MEK 접근을 제어합니다

## 키 계층

```
[Fuse] UDS/HEK_RATCHET_SEED
    │  (부팅 시 Caliptra ROM 내부에서 파생)
    ▼
HEK (Host Encryption Key) — Caliptra 내부, FW 비가시
    │  + drive_serial
    ▼
MDK (MEK Derivation Key) — 드라이브별
    │  + namespace_id + lba_range
    ▼
MEK (Media Encryption Key) — SSD 암호화 엔진에 로드
```

## HPKE 지원 알고리즘

| 알고리즘 | 플래그 | 설명 |
|----------|--------|------|
| ECDH-P384 + HKDF-SHA384 + AES-256-GCM | bit 0 | 표준 |
| ML-KEM-1024 + HKDF-SHA384 + AES-256-GCM | bit 1 | 양자 내성 |
| 하이브리드 (ECDH + ML-KEM) | bit 2 | 고전+양자 동시 보호 |

## 커맨드 코드 (caliptra-sw/api/src/mailbox.rs)

| 커맨드 | 코드 | ASCII | 설명 |
|--------|------|-------|------|
| `REPORT_HEK_METADATA` | 0x5248_4D54 | "RHMT" | HEK 메타데이터 조회 |
| `GET_ALGORITHMS` | 0x4741_4C47 | "GALG" | 지원 알고리즘 조회 |
| `INITIALIZE_MEK_SECRET` | 0x494D_4B53 | "IMKS" | MEK 파생 세션 초기화 |
| `MIX_MPK` | 0x4D4D_504B | "MMPK" | Customer MPK 혼합 |
| `DERIVE_MEK` | 0x444D_454B | "DMEK" | MEK 파생 |
| `ENUMERATE_HPKE_HANDLES` | 0x4548_444C | "EHDL" | HPKE 핸들 목록 조회 |
| `ROTATE_HPKE_KEY` | 0x5248_504B | "RHPK" | HPKE 키 교체 |
| `GENERATE_MEK` | 0x474D_454B | "GMEK" | 새 MEK 생성 |
| `GET_HPKE_PUB_KEY` | 0x4748_504B | "GHPK" | HPKE 공개키 획득 |
| `GENERATE_MPK` | 0x474D_504B | "GMPK" | MPK 생성 |
| `REWRAP_MPK` | 0x5245_5750 | "REWP" | MPK 재봉인 |
| `ENABLE_MPK` | 0x524D_504B | "RMPK" | MPK 활성화 |
| `TEST_ACCESS_KEY` | 0x5441_434B | "TACK" | Access Key 검증 |
| `GET_STATUS` | 0x4753_5441 | "GSTA" | 상태 조회 |
| `CLEAR_KEY_CACHE` | 0x434C_4B43 | "CLKC" | 키 캐시 무효화 |
| `UNLOAD_MEK` | 0x554D_454B | "UMEK" | MEK 언로드 |
| `LOAD_MEK` | 0x4C4D_454B | "LMEK" | MEK 로드 |

## API 함수

```c
// 1. HEK 메타데이터 조회
int caliptra_lock_report_hek_metadata(
    const ocp_lock_report_hek_metadata_req_t *req,
    ocp_lock_report_hek_metadata_resp_t      *resp, bool async);

// 2. 지원 알고리즘 조회
int caliptra_lock_get_algorithms(
    ocp_lock_get_algorithms_resp_t *resp, bool async);

// 3. MEK 파생 세션 초기화
int caliptra_lock_initialize_mek_secret(
    const uint8_t sek[32], const uint8_t dpk[32],
    ocp_lock_initialize_mek_secret_resp_t *resp, bool async);

// 4. Customer MPK 혼합
int caliptra_lock_mix_mpk(
    const ocp_lock_wrapped_key_t *enabled_mpk,
    ocp_lock_mix_mpk_resp_t *resp, bool async);

// 5. MEK 파생
int caliptra_lock_derive_mek(
    const uint8_t mek_checksum[16],
    const uint8_t metadata[20], const uint8_t aux_metadata[32],
    uint32_t cmd_timeout,
    ocp_lock_derive_mek_resp_t *resp, bool async);

// 6. HPKE 핸들 목록 조회
int caliptra_lock_enumerate_hpke_handles(
    ocp_lock_enumerate_hpke_handles_resp_t *resp, bool async);

// 7. HPKE 키 교체
int caliptra_lock_rotate_hpke_key(
    uint32_t hpke_handle,
    ocp_lock_rotate_hpke_key_resp_t *resp, bool async);

// 8. 새 MEK 생성
int caliptra_lock_generate_mek(
    ocp_lock_generate_mek_resp_t *resp, bool async);

// 9. HPKE 공개키 획득
int caliptra_lock_get_hpke_pub_key(
    uint32_t hpke_handle,
    ocp_lock_get_hpke_pub_key_resp_t *resp, bool async);

// 10. MPK 생성
int caliptra_lock_generate_mpk(
    const uint8_t sek[32],
    const uint8_t *metadata, uint32_t metadata_len,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_generate_mpk_resp_t *resp, bool async);

// 11. MPK 재봉인 (Access Key 교체)
int caliptra_lock_rewrap_mpk(
    const uint8_t sek[32],
    const ocp_lock_wrapped_key_t *current_locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const uint8_t new_ak_ciphertext[48],
    ocp_lock_rewrap_mpk_resp_t *resp, bool async);

// 12. MPK 활성화 (Locked → Enabled)
int caliptra_lock_enable_mpk(
    const uint8_t sek[32],
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const ocp_lock_wrapped_key_t *locked_mpk,
    ocp_lock_enable_mpk_resp_t *resp, bool async);

// 13. Access Key 검증
int caliptra_lock_test_access_key(
    const uint8_t sek[32], const uint8_t nonce[32],
    const ocp_lock_wrapped_key_t *locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_test_access_key_resp_t *resp, bool async);

// 14. 상태 조회
int caliptra_lock_get_status(
    ocp_lock_get_status_resp_t *resp, bool async);

// 15. 키 캐시 무효화
int caliptra_lock_clear_key_cache(
    uint32_t cmd_timeout,
    ocp_lock_clear_key_cache_resp_t *resp, bool async);

// 16. MEK 언로드
int caliptra_lock_unload_mek(
    const uint8_t metadata[20], uint32_t cmd_timeout,
    ocp_lock_unload_mek_resp_t *resp, bool async);

// 17. MEK 로드
int caliptra_lock_load_mek(
    const uint8_t metadata[20], const uint8_t aux_metadata[32],
    const ocp_lock_wrapped_key_t *wrapped_mek, uint32_t cmd_timeout,
    ocp_lock_load_mek_resp_t *resp, bool async);
```

## MEK 전달 시퀀스

### 방법 A: GENERATE_MEK (새 MEK 생성)

```
1. GET_ALGORITHMS    → 지원 알고리즘 확인
2. ENUMERATE_HPKE_HANDLES → 핸들 번호 확인
3. GET_HPKE_PUB_KEY  → Caliptra HPKE 공개키 획득 → SSD에 전달
4. GENERATE_MEK      → 새 MEK 생성 (WrappedKey 반환)
5. GENERATE_MPK      → Customer Access Key 포함 MPK 생성 [선택]
6. ENABLE_MPK        → MPK 활성화 [선택]
7. LOAD_MEK          → 암호화 엔진에 MEK 로드
```

### 방법 B: DERIVE_MEK (HEK에서 파생)

```
1. INITIALIZE_MEK_SECRET(SEK, DPK) → 파생 세션 초기화
2. MIX_MPK(enabled_mpk)            → Customer MPK 혼합 [선택]
3. DERIVE_MEK(metadata)            → MEK 파생
4. LOAD_MEK(wrapped_mek)           → 암호화 엔진에 MEK 로드
```

### 드라이브 잠금/슬립

```
UNLOAD_MEK → 암호화 엔진에서 MEK 제거
CLEAR_KEY_CACHE → 내부 키 캐시 초기화 [선택]
```

## 주요 상수

| 상수 | 값 | 설명 |
|------|----|------|
| `OCP_LOCK_MAX_HPKE_HANDLES` | 3 | 최대 HPKE 핸들 수 |
| `OCP_LOCK_MAX_HPKE_PUBKEY_LEN` | 1665 | HPKE 공개키 최대 크기 (ML-KEM-1024 기준) |
| `OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN` | 32 | WrappedKey 메타데이터 최대 크기 |
| `OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN` | 256 | SealedAccessKey info 최대 크기 |
| `OCP_LOCK_MAX_ENC_LEN` | 1665 | KEM ciphertext 최대 크기 |
| `OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE` | 20 | 암호화 엔진 메타데이터 크기 |
| `OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE` | 32 | 보조 메타데이터 크기 |

## 주요 구조체

### WrappedKey (암호화된 키 컨테이너)

```c
typedef struct {
    uint16_t key_type;   // 0x01=LockedMpk, 0x02=EnabledMpk, 0x03=WrappedMek
    uint16_t reserved;
    uint8_t  salt[12];
    uint32_t metadata_len;
    uint32_t key_len;
    uint8_t  iv[12];
    uint8_t  metadata[32];
    uint8_t  ciphertext_and_auth_tag[80]; // AES-256-GCM 암호문 + 16B 태그
} ocp_lock_wrapped_key_t;
```

### SealedAccessKey (HPKE 봉인 Access Key)

```c
typedef struct {
    ocp_lock_hpke_handle_t hpke_handle;
    uint32_t               access_key_len;
    uint32_t               info_len;
    uint8_t                info[256];
    uint8_t                kem_ciphertext[1665]; // HPKE KEM 암호문
    uint8_t                _padding[3];
    uint8_t                ak_ciphertext[48];    // AES-GCM 암호화 Access Key
} ocp_lock_sealed_access_key_t;
```

## SoC 책임

1. **Fuse 설정**: HEK 관련 Fuse 프로그래밍 (제조 단계, HW 상태 머신)
2. **SSD 공개키 수집**: NVMe Identify 커맨드로 SSD HPKE 공개키 획득
3. **HPKE 세션 조정**: Caliptra HPKE 공개키를 SSD에 전달
4. **MEK 로드 트리거**: `LOAD_MEK` 호출로 SSD 암호화 엔진 활성화
5. **보안 이벤트 처리**: `UNLOAD_MEK`, `CLEAR_KEY_CACHE`로 드라이브 잠금

SoC FW는 MEK plaintext를 절대 처리하지 않습니다.
