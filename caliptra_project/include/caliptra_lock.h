#ifndef CALIPTRA_LOCK_H
#define CALIPTRA_LOCK_H

/*
 * OCP L.O.C.K. (Layered Open Composable Key management) API
 * Caliptra 2.1+ 지원
 *
 * 스펙: https://chipsalliance.github.io/Caliptra/ocp-lock/specification/HEAD/
 * 로컬 스펙: caliptra_project/Caliptra/doc/ocp_lock/
 *
 * ─────────────────────────────────────────────────────────
 * 키 계층 (Key Hierarchy)
 * ─────────────────────────────────────────────────────────
 *
 *   [Fuse] HEK_RATCHET_SEED (256-bit)
 *       │ HKDF (boot-time, Caliptra FW 내부)
 *       ▼
 *   [KV]  HEK  (Host Encryption Key, FW-invisible)
 *       │ HKDF + (drive_serial, NSID)
 *       ▼
 *   [KV]  MDK  (MEK Derivation Key, per-drive)
 *       │ HKDF + (namespace_id, lba_range)
 *       ▼
 *   [KV]  MEK  (Media Encryption Key, AES-256-XTS, to SSD)
 *
 * ─────────────────────────────────────────────────────────
 * MEK 전달 (HPKE — Hybrid Public Key Encryption)
 * ─────────────────────────────────────────────────────────
 *
 *   ECDH 모드 (RFC 9180 DHKEM P-384):
 *     1. Caliptra ECDH(임시키, drive_ecdh_pub) → shared_secret (KV)
 *     2. HKDF(shared_secret, mek_context) → wrap_key (KV)
 *     3. AES-256-GCM(mek_handle, wrap_key) → encrypted_mek
 *     → SSD로: {eph_pub_key, encrypted_mek, iv, tag}
 *
 *   ML-KEM 모드 (FIPS 203, ML-KEM-1024):
 *     1. Caliptra ML-KEM-ENCAP(drive_mlkem_pub) → (ct, shared_secret KV)
 *     2. HKDF(shared_secret, mek_context) → wrap_key (KV)
 *     3. AES-256-GCM(mek_handle, wrap_key) → encrypted_mek
 *     → SSD로: {mlkem_ct, encrypted_mek, iv, tag}
 *
 *   Hybrid 모드 (ECDH + ML-KEM, 양자 내성):
 *     1. ECDH + ML-KEM 각각 수행 → (ss_ecdh, ss_mlkem)
 *     2. HKDF(concat(ss_ecdh, ss_mlkem), mek_context) → wrap_key
 *     3. AES-256-GCM(mek_handle, wrap_key) → encrypted_mek
 *     → SSD로: {eph_pub_key, mlkem_ct, encrypted_mek, iv, tag}
 *
 * ─────────────────────────────────────────────────────────
 * SoC 책임
 * ─────────────────────────────────────────────────────────
 *   - HEK_RATCHET_SEED Fuse 프로그래밍 (제조 단계)
 *   - OCP_LOCK_ENABLE strap 설정
 *   - NVMe Identify로 SSD 공개키(DPK) 수집
 *   - caliptra_lock_deliver_mek_*() 호출 → MEK 블랍 획득
 *   - NVMe Key Programming 커맨드로 SSD에 MEK 블랍 전달
 *   - SoC FW는 MEK plaintext를 절대 보지 않음
 */

#include "caliptra_driver.h"
#include "caliptra_crypto_ext.h"

/* ---------------------------------------------------------------------------
 * MEK 바인딩 컨텍스트 (HPKE info 파라미터)
 * --------------------------------------------------------------------------- */

typedef struct {
    uint8_t  drive_serial[32];  /* SSD 시리얼 번호 (NVMe IDENTIFY에서) */
    uint32_t namespace_id;      /* NVMe Namespace ID */
    uint64_t lba_start;         /* 시작 LBA (0=전체 네임스페이스) */
    uint64_t lba_count;         /* LBA 범위 (0=전체) */
} caliptra_lock_mek_context_t;

/* ---------------------------------------------------------------------------
 * MEK 전달 블랍 (SSD로 전달하는 구조체)
 * --------------------------------------------------------------------------- */

/* ECDH HPKE MEK 블랍 */
typedef struct {
    uint8_t  eph_pub_key[CALIPTRA_ECC384_PUBKEY_SIZE]; /* 임시 P-384 공개키 (96B) */
    uint8_t  iv[CALIPTRA_AES_GCM_IV_SIZE];              /* GCM IV (12B) */
    uint8_t  tag[CALIPTRA_AES_GCM_TAG_SIZE];            /* GCM 인증 태그 (16B) */
    uint32_t mek_ct_size;
    uint8_t  mek_ct[CALIPTRA_AES_MAX_PT_SIZE];          /* 암호화된 MEK */
} caliptra_lock_ecdh_mek_blob_t;

/* ML-KEM HPKE MEK 블랍 */
typedef struct {
    uint8_t  mlkem_ct[CALIPTRA_ML_KEM_1024_CT_SIZE];   /* ML-KEM ciphertext (1568B) */
    uint8_t  iv[CALIPTRA_AES_GCM_IV_SIZE];
    uint8_t  tag[CALIPTRA_AES_GCM_TAG_SIZE];
    uint32_t mek_ct_size;
    uint8_t  mek_ct[CALIPTRA_AES_MAX_PT_SIZE];
} caliptra_lock_mlkem_mek_blob_t;

/* Hybrid HPKE MEK 블랍 (ECDH + ML-KEM) */
typedef struct {
    uint8_t  eph_pub_key[CALIPTRA_ECC384_PUBKEY_SIZE]; /* ECDH 임시 공개키 */
    uint8_t  mlkem_ct[CALIPTRA_ML_KEM_1024_CT_SIZE];   /* ML-KEM ciphertext */
    uint8_t  iv[CALIPTRA_AES_GCM_IV_SIZE];
    uint8_t  tag[CALIPTRA_AES_GCM_TAG_SIZE];
    uint32_t mek_ct_size;
    uint8_t  mek_ct[CALIPTRA_AES_MAX_PT_SIZE];
} caliptra_lock_hybrid_mek_blob_t;

/* ---------------------------------------------------------------------------
 * 저수준 HPKE API (단계별 사용 — 고급 사용자용)
 * --------------------------------------------------------------------------- */

/*
 * caliptra_lock_ecdh_encap - P-384 ECDH HPKE KEM
 * Caliptra가 내부에서 임시 키쌍을 생성하고 ECDH를 수행합니다.
 *
 * @drive_ecdh_pub:  SSD의 P-384 ECDH 공개키 (96바이트)
 * @out_ss_handle:   공유 비밀 KV 핸들 (HKDF 입력으로 사용)
 * @out_eph_pub:     Caliptra 생성 임시 공개키 (SSD로 전달, 96바이트)
 */
caliptra_status_t caliptra_lock_ecdh_encap(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    caliptra_key_handle_t *out_ss_handle,
    uint8_t out_eph_pub[CALIPTRA_ECC384_PUBKEY_SIZE]);

/*
 * caliptra_lock_mlkem_encap - ML-KEM-1024 HPKE KEM
 *
 * @drive_mlkem_pub: SSD의 ML-KEM-1024 공개키 (1568바이트)
 * @out_ct:          ML-KEM ciphertext (SSD로 전달, 1568바이트)
 * @out_ss_handle:   공유 비밀 KV 핸들
 */
caliptra_status_t caliptra_lock_mlkem_encap(
    caliptra_ctx_t *ctx,
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    uint8_t out_ct[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle);

/*
 * caliptra_lock_hpke_derive_wrap_key - HKDF로 MEK 래핑 키 파생
 * 공유 비밀 + MEK 컨텍스트 → AES-256 래핑 키 (KV)
 *
 * @ss_handle:           ECDH 또는 ML-KEM 공유 비밀 KV 핸들
 * @mek_ctx:             MEK 바인딩 컨텍스트 (drive serial, NSID, LBA)
 * @out_wrap_key_handle: AES-256 래핑 키 KV 핸들
 */
caliptra_status_t caliptra_lock_hpke_derive_wrap_key(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *ss_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_key_handle_t *out_wrap_key_handle);

/*
 * caliptra_lock_wrap_mek - AES-256-GCM으로 MEK 암호화
 * MEK KV 핸들을 외부로 꺼내지 않고 Caliptra 내부에서 암호화합니다.
 *
 * @mek_handle:          MEK KV 핸들
 * @wrap_key_handle:     AES-256 래핑 키 KV 핸들
 * @iv:                  GCM IV (12바이트)
 * @aad:                 추가 인증 데이터 (NULL=없음)
 * @aad_len:             AAD 크기
 * @out_ct:              암호화된 MEK 출력 버퍼
 * @out_ct_len:          암호화된 크기 반환
 * @out_tag:             GCM 인증 태그 (16바이트)
 */
caliptra_status_t caliptra_lock_wrap_mek(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *mek_handle,
    const caliptra_key_handle_t *wrap_key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    uint8_t *out_ct, uint32_t *out_ct_len,
    uint8_t out_tag[CALIPTRA_AES_GCM_TAG_SIZE]);

/* ---------------------------------------------------------------------------
 * 고수준 MEK 전달 API (전체 HPKE 시퀀스 원스텝)
 * --------------------------------------------------------------------------- */

/*
 * caliptra_lock_deliver_mek_ecdh - ECDH HPKE로 MEK 전달
 *
 * 순서:
 *   1. ECDH_KEY_AGREE(임시키 생성, drive_ecdh_pub) → shared_secret + eph_pub
 *   2. HKDF(shared_secret, mek_ctx) → wrap_key
 *   3. AES-256-GCM(mek_handle, wrap_key, rng_iv) → encrypted_mek + tag
 *
 * @drive_ecdh_pub: SSD P-384 공개키 (96바이트)
 * @mek_handle:     MEK KV 핸들 (Caliptra FW가 파생한 값)
 * @mek_ctx:        MEK 바인딩 컨텍스트
 * @out_blob:       SSD로 전달할 ECDH MEK 블랍
 */
caliptra_status_t caliptra_lock_deliver_mek_ecdh(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_ecdh_mek_blob_t *out_blob);

/*
 * caliptra_lock_deliver_mek_mlkem - ML-KEM HPKE로 MEK 전달
 *
 * 순서:
 *   1. ML_KEM_ENCAP(drive_mlkem_pub) → (mlkem_ct, shared_secret)
 *   2. HKDF(shared_secret, mek_ctx) → wrap_key
 *   3. AES-256-GCM(mek_handle, wrap_key, rng_iv) → encrypted_mek + tag
 *
 * @drive_mlkem_pub: SSD ML-KEM-1024 공개키 (1568바이트)
 * @mek_handle:      MEK KV 핸들
 * @mek_ctx:         MEK 바인딩 컨텍스트
 * @out_blob:        SSD로 전달할 ML-KEM MEK 블랍
 */
caliptra_status_t caliptra_lock_deliver_mek_mlkem(
    caliptra_ctx_t *ctx,
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_mlkem_mek_blob_t *out_blob);

/*
 * caliptra_lock_deliver_mek_hybrid - 하이브리드 HPKE (ECDH + ML-KEM)
 *
 * 고전 보안(ECDH)과 양자 내성(ML-KEM)을 동시에 보장합니다.
 * 순서:
 *   1. ECDH_KEY_AGREE(임시키, drive_ecdh_pub) → (ss_ecdh, eph_pub)
 *   2. ML_KEM_ENCAP(drive_mlkem_pub)          → (mlkem_ct, ss_mlkem)
 *   3. HKDF(ss_ecdh || ss_mlkem, mek_ctx)     → wrap_key
 *   4. AES-256-GCM(mek_handle, wrap_key, rng_iv) → encrypted_mek + tag
 *
 * @drive_ecdh_pub:  SSD P-384 공개키 (96바이트)
 * @drive_mlkem_pub: SSD ML-KEM-1024 공개키 (1568바이트)
 * @mek_handle:      MEK KV 핸들
 * @mek_ctx:         MEK 바인딩 컨텍스트
 * @out_blob:        SSD로 전달할 Hybrid MEK 블랍
 */
caliptra_status_t caliptra_lock_deliver_mek_hybrid(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_hybrid_mek_blob_t *out_blob);

#endif /* CALIPTRA_LOCK_H */
