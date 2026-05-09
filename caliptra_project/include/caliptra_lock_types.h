// Licensed under the Apache-2.0 license
#pragma once

/*
 * OCP L.O.C.K. v1.0 C 타입 정의
 *
 * caliptra-sw/api/src/mailbox.rs 의 Rust 타입을 C 구조체로 변환한 것입니다.
 * Caliptra Runtime FW가 처리하는 OCP LOCK 메일박스 커맨드의
 * 요청/응답 레이아웃과 정확히 일치해야 합니다.
 *
 * 레퍼런스:
 *   caliptra-sw/api/src/mailbox.rs          — 커맨드 코드 및 구조체 정의
 *   caliptra-sw/runtime/src/ocp_lock/       — 런타임 FW 구현
 *   OCP_LOCK_Specification_v1.0_RC2.pdf     — 프로토콜 스펙
 *
 * 빌드 요구사항:
 *   이 헤더는 caliptra_types.h (libcaliptra)를 필요로 합니다.
 *   include 경로: -I caliptra-sw/libcaliptra/inc
 */

#include <stdint.h>
#include <stdbool.h>
#include "caliptra_types.h"  /* struct caliptra_req_header, caliptra_resp_header */

/* ─────────────────────────────────────────────────────────────────────
 * OCP LOCK 메일박스 커맨드 코드
 * Source: caliptra-sw/api/src/mailbox.rs (CommandId)
 * ───────────────────────────────────────────────────────────────────── */

#define OCP_LOCK_REPORT_HEK_METADATA     0x5248_4D54u  /* "RHMT" */
#define OCP_LOCK_GET_ALGORITHMS           0x4741_4C47u  /* "GALG" */
#define OCP_LOCK_INITIALIZE_MEK_SECRET    0x494D_4B53u  /* "IMKS" */
#define OCP_LOCK_MIX_MPK                  0x4D4D_504Bu  /* "MMPK" */
#define OCP_LOCK_DERIVE_MEK               0x444D_454Bu  /* "DMEK" */
#define OCP_LOCK_ENUMERATE_HPKE_HANDLES   0x4548_444Cu  /* "EHDL" */
#define OCP_LOCK_ROTATE_HPKE_KEY          0x5248_504Bu  /* "RHPK" */
#define OCP_LOCK_GENERATE_MEK             0x474D_454Bu  /* "GMEK" */
#define OCP_LOCK_GET_HPKE_PUB_KEY         0x4748_504Bu  /* "GHPK" */
#define OCP_LOCK_GENERATE_MPK             0x474D_504Bu  /* "GMPK" */
#define OCP_LOCK_REWRAP_MPK               0x5245_5750u  /* "REWP" */
#define OCP_LOCK_ENABLE_MPK               0x524D_504Bu  /* "RMPK" */
#define OCP_LOCK_TEST_ACCESS_KEY          0x5441_434Bu  /* "TACK" */
#define OCP_LOCK_GET_STATUS               0x4753_5441u  /* "GSTA" */
#define OCP_LOCK_CLEAR_KEY_CACHE          0x434C_4B43u  /* "CLKC" */
#define OCP_LOCK_UNLOAD_MEK               0x554D_454Bu  /* "UMEK" */
#define OCP_LOCK_LOAD_MEK                 0x4C4D_454Bu  /* "LMEK" */

/* ─────────────────────────────────────────────────────────────────────
 * OCP LOCK 상수
 * Source: caliptra-sw/api/src/mailbox.rs
 * ───────────────────────────────────────────────────────────────────── */

#define OCP_LOCK_MAX_HPKE_HANDLES                   3u
#define OCP_LOCK_MAX_HPKE_PUBKEY_LEN                1665u
#define OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN        32u
#define OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN            256u
#define OCP_LOCK_MAX_ENC_LEN                         1665u
#define OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE     20u
#define OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE          32u
#define OCP_LOCK_ENCRYPTION_ENGINE_MAX_MEK_SIZE      64u

/* ─────────────────────────────────────────────────────────────────────
 * HPKE 알고리즘 플래그 (비트마스크)
 * ───────────────────────────────────────────────────────────────────── */

typedef uint32_t ocp_lock_hpke_algorithms_t;
#define OCP_LOCK_HPKE_ECDH_P384_HKDF_SHA384_AES_256_GCM          (1u << 0)
#define OCP_LOCK_HPKE_ML_KEM_1024_HKDF_SHA384_AES_256_GCM        (1u << 1)
#define OCP_LOCK_HPKE_ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM (1u << 2)

typedef uint32_t ocp_lock_access_key_sizes_t;
#define OCP_LOCK_ACCESS_KEY_SIZE_128 (1u << 0)
#define OCP_LOCK_ACCESS_KEY_SIZE_256 (1u << 1)

/* ─────────────────────────────────────────────────────────────────────
 * 공통 구조체
 * ───────────────────────────────────────────────────────────────────── */

/* HPKE 핸들 — HPKE 키 식별자 */
typedef struct {
    uint32_t                  handle;
    ocp_lock_hpke_algorithms_t hpke_algorithm;
} ocp_lock_hpke_handle_t;

/* WrappedKey — 암호화된 키 컨테이너 (MEK/MPK 등) */
typedef struct {
    uint16_t key_type;   /* 0x01=LockedMpk, 0x02=EnabledMpk, 0x03=WrappedMek */
    uint16_t reserved;
    uint8_t  salt[12];
    uint32_t metadata_len;
    uint32_t key_len;
    uint8_t  iv[12];
    uint8_t  metadata[OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    uint8_t  ciphertext_and_auth_tag[80]; /* AES-256-GCM 암호문 + 16B 태그 */
} ocp_lock_wrapped_key_t;

/* SealedAccessKey — HPKE로 봉인된 Access Key */
typedef struct {
    ocp_lock_hpke_handle_t hpke_handle;
    uint32_t               access_key_len;
    uint32_t               info_len;
    uint8_t                info[OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN];
    uint8_t                kem_ciphertext[OCP_LOCK_MAX_ENC_LEN];
    uint8_t                _padding[3];
    uint8_t                ak_ciphertext[48]; /* AES-256-GCM 암호화된 Access Key */
} ocp_lock_sealed_access_key_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 1: REPORT_HEK_METADATA (0x5248_4D54 "RHMT")
 *
 * HEK(Host Encryption Key) 메타데이터 조회
 * HEK 슬롯 수, 활성 슬롯, 시드 상태 등을 반환합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved0;
    uint16_t total_slots;
    uint16_t active_slots;
    uint16_t seed_state;
    uint16_t padding0;
} ocp_lock_report_hek_metadata_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t flags;      /* bit31: HEK_AVAILABLE */
    uint32_t reserved[3];
} ocp_lock_report_hek_metadata_resp_t;

#define OCP_LOCK_HEK_AVAILABLE_FLAG (1u << 31)

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 2: GET_ALGORITHMS (0x4741_4C47 "GALG")
 *
 * Caliptra가 지원하는 HPKE 알고리즘과 Access Key 크기 쿼리
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
} ocp_lock_get_algorithms_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t                    reserved[4];
    ocp_lock_hpke_algorithms_t  hpke_algorithms;
    ocp_lock_access_key_sizes_t access_key_sizes;
} ocp_lock_get_algorithms_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 3: INITIALIZE_MEK_SECRET (0x494D_4B53 "IMKS")
 *
 * MEK 비밀 초기화 — SEK(세션 설정 키)와 DPK(드라이브 개인키)를
 * 사용해 EPK(임시 공개키)와 중간 MEK 비밀을 파생합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint8_t  sek[32]; /* Session Establishment Key */
    uint8_t  dpk[32]; /* Drive Private Key */
} ocp_lock_initialize_mek_secret_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
} ocp_lock_initialize_mek_secret_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 4: MIX_MPK (0x4D4D_504B "MMPK")
 *
 * Enabled MPK를 MEK 파생에 혼합합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t              reserved;
    ocp_lock_wrapped_key_t enabled_mpk;
} ocp_lock_mix_mpk_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
} ocp_lock_mix_mpk_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 5: DERIVE_MEK (0x444D_454B "DMEK")
 *
 * MEK 파생 — 메타데이터 및 보조 메타데이터를 사용해 MEK를 파생합니다.
 * INITIALIZE_MEK_SECRET 또는 MIX_MPK 이후 호출합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint8_t  mek_checksum[16];    /* MEK 무결성 검증 값 */
    uint8_t  metadata[20];        /* 암호화 엔진 메타데이터 */
    uint8_t  aux_metadata[32];    /* 보조 메타데이터 */
    uint32_t cmd_timeout;         /* 타임아웃 (밀리초) */
} ocp_lock_derive_mek_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
    uint8_t  mek_checksum[16];
} ocp_lock_derive_mek_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 6: ENUMERATE_HPKE_HANDLES (0x4548_444C "EHDL")
 *
 * 사용 가능한 HPKE 키 핸들 목록 조회
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
} ocp_lock_enumerate_hpke_handles_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t                reserved;
    uint32_t                hpke_handle_count;
    ocp_lock_hpke_handle_t  hpke_handles[OCP_LOCK_MAX_HPKE_HANDLES];
} ocp_lock_enumerate_hpke_handles_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 7: ROTATE_HPKE_KEY (0x5248_504B "RHPK")
 *
 * 지정한 HPKE 핸들의 키를 교체합니다. 새 핸들 번호를 반환합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint32_t hpke_handle;
} ocp_lock_rotate_hpke_key_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
    uint32_t hpke_handle; /* 새로 할당된 핸들 번호 */
} ocp_lock_rotate_hpke_key_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 8: GENERATE_MEK (0x474D_454B "GMEK")
 *
 * 새 MEK를 생성하고 WrappedKey 형태로 반환합니다.
 * 생성된 MEK는 Caliptra 내부에만 남고 plaintext는 외부로 노출되지 않습니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
} ocp_lock_generate_mek_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t               reserved;
    ocp_lock_wrapped_key_t wrapped_mek;
} ocp_lock_generate_mek_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 9: GET_HPKE_PUB_KEY (0x4748_504B "GHPK")
 *
 * 지정한 핸들의 HPKE 공개키를 반환합니다.
 * SoC는 이 공개키를 SSD에 전달하여 MEK 전달 세션을 설정합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint32_t hpke_handle;
} ocp_lock_get_hpke_pub_key_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
    uint32_t pub_key_len;
    uint8_t  pub_key[OCP_LOCK_MAX_HPKE_PUBKEY_LEN]; /* P-384(96B) 또는 ML-KEM-1024(1568B) */
    uint8_t  padding[3];
} ocp_lock_get_hpke_pub_key_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 10: GENERATE_MPK (0x474D_504B "GMPK")
 *
 * MPK(Managed Platform Key) 생성 — Customer가 제공한 Access Key로
 * MEK를 봉인합니다. SealedAccessKey를 통해 HPKE로 전달됩니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header    hdr;
    uint32_t                      reserved;
    uint8_t                       sek[32];  /* Session Establishment Key */
    uint32_t                      metadata_len;
    uint8_t                       metadata[OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    ocp_lock_sealed_access_key_t  sealed_access_key;
} ocp_lock_generate_mpk_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t               reserved;
    ocp_lock_wrapped_key_t wrapped_mek; /* MPK로 봉인된 MEK */
} ocp_lock_generate_mpk_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 11: REWRAP_MPK (0x5245_5750 "REWP")
 *
 * MPK 재봉인 — 기존 MPK를 새 Access Key로 교체합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header    hdr;
    uint32_t                      reserved;
    uint8_t                       sek[32];
    ocp_lock_wrapped_key_t        current_locked_mpk;
    ocp_lock_sealed_access_key_t  sealed_access_key;
    uint8_t                       new_ak_ciphertext[48];
} ocp_lock_rewrap_mpk_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t               reserved;
    ocp_lock_wrapped_key_t wrapped_mek;
} ocp_lock_rewrap_mpk_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 12: ENABLE_MPK (0x524D_504B "RMPK")
 *
 * Locked MPK → Enabled MPK 전환
 * Access Key 검증 후 MEK 접근을 활성화합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header    hdr;
    uint32_t                      reserved;
    uint8_t                       sek[32];
    ocp_lock_sealed_access_key_t  sealed_access_key;
    ocp_lock_wrapped_key_t        locked_mpk;
} ocp_lock_enable_mpk_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t               reserved;
    ocp_lock_wrapped_key_t enabled_mpk; /* 활성화된 MPK */
} ocp_lock_enable_mpk_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 13: TEST_ACCESS_KEY (0x5441_434B "TACK")
 *
 * Access Key 검증 — SHA2-384 다이제스트로 Access Key 유효성 확인
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header    hdr;
    uint32_t                      reserved;
    uint8_t                       sek[32];
    uint8_t                       nonce[32];
    ocp_lock_wrapped_key_t        locked_mpk;
    ocp_lock_sealed_access_key_t  sealed_access_key;
} ocp_lock_test_access_key_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
    uint8_t  digest[48]; /* SHA2-384 다이제스트 */
} ocp_lock_test_access_key_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 14: GET_STATUS (0x4753_5441 "GSTA")
 *
 * OCP LOCK 상태 레지스터 조회
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
} ocp_lock_get_status_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved[4];
    uint32_t ctrl_register; /* OCP LOCK 제어 레지스터 값 */
} ocp_lock_get_status_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 15: CLEAR_KEY_CACHE (0x434C_4B43 "CLKC")
 *
 * 키 캐시 무효화 — 내부 MEK 캐시를 초기화합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint32_t cmd_timeout; /* 타임아웃 (밀리초) */
} ocp_lock_clear_key_cache_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
} ocp_lock_clear_key_cache_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 16: UNLOAD_MEK (0x554D_454B "UMEK")
 *
 * MEK 언로드 — 암호화 엔진에서 MEK를 제거합니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t reserved;
    uint8_t  metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];
    uint32_t cmd_timeout;
} ocp_lock_unload_mek_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
} ocp_lock_unload_mek_resp_t;

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 17: LOAD_MEK (0x4C4D_454B "LMEK")
 *
 * MEK 로드 — WrappedKey를 언래핑하여 암호화 엔진에 MEK를 로드합니다.
 * MEK plaintext는 SoC FW에 노출되지 않습니다.
 * ───────────────────────────────────────────────────────────────────── */

typedef struct {
    struct caliptra_req_header hdr;
    uint32_t               reserved;
    uint8_t                metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE];
    uint8_t                aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE];
    ocp_lock_wrapped_key_t wrapped_mek; /* GENERATE_MEK 또는 DERIVE_MEK 결과 */
    uint32_t               cmd_timeout;
} ocp_lock_load_mek_req_t;

typedef struct {
    struct caliptra_resp_header hdr;
    uint32_t reserved;
} ocp_lock_load_mek_resp_t;
