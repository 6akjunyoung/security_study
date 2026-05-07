#ifndef CALIPTRA_CRYPTO_EXT_H
#define CALIPTRA_CRYPTO_EXT_H

/*
 * Caliptra 2.0+ 확장 암호화 서비스 API
 *
 * caliptra_driver.h에 없는 암호화 커맨드 래퍼입니다:
 *   SHA-384/512 해시, HMAC-SHA384, HKDF-SHA384
 *   AES-256-GCM 암호화/복호화
 *   ECDH P-384 키 합의
 *   ML-KEM-1024 캡슐화/역캡슐화
 *   서명 검증 (ECDSA P-384, ML-DSA-87)
 *   키 임포트 (원시 키 → KV 핸들)
 *
 * 모든 키는 Caliptra Key Vault(KV) 핸들로 참조합니다.
 * SoC FW는 원시 키 값에 접근할 수 없습니다 (AES/HMAC/HEK 등).
 */

#include "caliptra_driver.h"
#include "caliptra_mbox.h"

/* ---------------------------------------------------------------------------
 * 해시
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_hash - SHA-384 또는 SHA-512 해시 계산
 * @algorithm:    0=SHA384, 1=SHA512
 * @data:         입력 데이터
 * @data_len:     입력 크기 (바이트)
 * @out_hash:     출력 해시 버퍼 (SHA384: 48B, SHA512: 64B)
 * @out_hash_len: 실제 출력 크기 반환
 */
caliptra_status_t caliptra_crypto_hash(caliptra_ctx_t *ctx,
                                        uint32_t algorithm,
                                        const uint8_t *data, uint32_t data_len,
                                        uint8_t *out_hash, uint32_t *out_hash_len);

/* ---------------------------------------------------------------------------
 * HMAC / HKDF
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_hmac - HMAC-SHA384 계산
 * @key_handle: HMAC 키 KV 핸들 (CALIPTRA_KEY_TYPE_HMAC_SHA384)
 * @data:       입력 데이터 (최대 CALIPTRA_HMAC_DATA_MAX 바이트)
 * @data_len:   입력 크기
 * @out_hmac:   출력 HMAC 버퍼 (48바이트)
 */
caliptra_status_t caliptra_crypto_hmac(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *key_handle,
                                        const uint8_t *data, uint32_t data_len,
                                        uint8_t out_hmac[CALIPTRA_SHA384_HASH_SIZE]);

/*
 * caliptra_crypto_hkdf - HKDF-SHA384 키 파생
 * IKM 핸들에서 KV 내 새 키 핸들을 파생합니다.
 *
 * @ikm_handle:  Input Keying Material KV 핸들
 * @salt:        솔트 (NULL이면 zero-filled, 최대 CALIPTRA_HKDF_SALT_MAX)
 * @salt_len:    솔트 크기
 * @info:        컨텍스트/레이블 (최대 CALIPTRA_HKDF_INFO_MAX)
 * @info_len:    info 크기
 * @okm_length:  출력 키 길이 (바이트, 최대 CALIPTRA_HKDF_OKM_MAX)
 * @out_handle:  파생된 키 KV 핸들 반환
 */
caliptra_status_t caliptra_crypto_hkdf(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *ikm_handle,
                                        const uint8_t *salt, uint32_t salt_len,
                                        const uint8_t *info, uint32_t info_len,
                                        uint32_t okm_length,
                                        caliptra_key_handle_t *out_handle);

/* ---------------------------------------------------------------------------
 * AES-256-GCM
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_aes_gcm_encrypt - AES-256-GCM 암호화
 * @key_handle: AES-256 키 KV 핸들 (또는 MEK 핸들)
 * @iv:         96-bit GCM IV (12바이트)
 * @aad:        추가 인증 데이터 (NULL=없음, 최대 CALIPTRA_AES_AAD_MAX_SIZE)
 * @aad_len:    AAD 크기
 * @plaintext:  평문 (최대 CALIPTRA_AES_MAX_PT_SIZE)
 * @pt_len:     평문 크기
 * @out_ct:     암호문 출력 버퍼 (pt_len 이상 크기)
 * @out_ct_len: 암호문 크기 반환
 * @out_tag:    GCM 인증 태그 (16바이트)
 */
caliptra_status_t caliptra_crypto_aes_gcm_encrypt(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *plaintext, uint32_t pt_len,
    uint8_t *out_ct, uint32_t *out_ct_len,
    uint8_t out_tag[CALIPTRA_AES_GCM_TAG_SIZE]);

/*
 * caliptra_crypto_aes_gcm_decrypt - AES-256-GCM 복호화
 * @key_handle:  AES-256 키 KV 핸들
 * @iv:          암호화 시 사용한 IV (12바이트)
 * @aad:         AAD (암호화와 동일해야 함)
 * @aad_len:     AAD 크기
 * @ciphertext:  암호문
 * @ct_len:      암호문 크기
 * @tag:         GCM 인증 태그 (16바이트, 검증 포함)
 * @out_pt:      복호화된 평문 출력
 * @out_pt_len:  평문 크기 반환
 */
caliptra_status_t caliptra_crypto_aes_gcm_decrypt(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *ciphertext, uint32_t ct_len,
    const uint8_t tag[CALIPTRA_AES_GCM_TAG_SIZE],
    uint8_t *out_pt, uint32_t *out_pt_len);

/* ---------------------------------------------------------------------------
 * ECDH / ML-KEM (키 합의 / 캡슐화)
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_ecdh_key_agree - ECDH P-384 키 합의
 * 지정한 개인키와 상대방 공개키를 사용해 공유 비밀을 KV에 생성합니다.
 *
 * @priv_key_handle: 자신의 P-384 개인키 KV 핸들
 * @peer_pub_key:    상대방 P-384 공개키 (96바이트)
 * @out_ss_handle:   공유 비밀 KV 핸들 (HKDF 입력으로 사용)
 */
caliptra_status_t caliptra_crypto_ecdh_key_agree(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *priv_key_handle,
    const uint8_t peer_pub_key[CALIPTRA_ECC384_PUBKEY_SIZE],
    caliptra_key_handle_t *out_ss_handle);

/*
 * caliptra_crypto_ml_kem_encap - ML-KEM-1024 캡슐화
 * 수신자 공개키로 공유 비밀을 캡슐화합니다.
 *
 * @recipient_pub:  수신자 ML-KEM-1024 공개키 (1568바이트)
 * @out_ct:         암호문 (1568바이트, 수신자에게 전달)
 * @out_ss_handle:  공유 비밀 KV 핸들
 */
caliptra_status_t caliptra_crypto_ml_kem_encap(
    caliptra_ctx_t *ctx,
    const uint8_t recipient_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    uint8_t out_ct[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle);

/*
 * caliptra_crypto_ml_kem_decap - ML-KEM-1024 역캡슐화
 * 자신의 개인키로 암호문에서 공유 비밀을 복원합니다.
 *
 * @priv_key_handle: 자신의 ML-KEM-1024 개인키 KV 핸들
 * @ciphertext:      수신한 암호문 (1568바이트)
 * @out_ss_handle:   공유 비밀 KV 핸들
 */
caliptra_status_t caliptra_crypto_ml_kem_decap(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *priv_key_handle,
    const uint8_t ciphertext[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle);

/* ---------------------------------------------------------------------------
 * 키 임포트 / 서명 검증
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_import_key - 외부 키를 Caliptra KV로 임포트
 * 임포트 후 원시 키 값은 더 이상 SoC FW에서 사용하지 않습니다.
 *
 * @key_type:   caliptra_key_type_t (ECDSA_P384, AES_256, HMAC_SHA384, ML_KEM_1024)
 * @key_data:   원시 키 바이트
 * @key_size:   키 크기 (최대 CALIPTRA_IMPORT_KEY_MAX_SIZE)
 * @out_handle: KV 핸들 반환
 */
caliptra_status_t caliptra_crypto_import_key(
    caliptra_ctx_t *ctx,
    caliptra_key_type_t key_type,
    const uint8_t *key_data, uint32_t key_size,
    caliptra_key_handle_t *out_handle);

/*
 * caliptra_crypto_verify_signature - ECDSA P-384 또는 ML-DSA-87 서명 검증
 * @pub_key_handle: 공개키 KV 핸들
 * @flags:          0x01=ECDSA P-384, 0x02=ML-DSA-87
 * @digest:         SHA-384 해시 (48바이트)
 * @sig:            서명 데이터
 * @sig_len:        서명 크기
 * @out_valid:      검증 결과 반환 (true=유효)
 */
caliptra_status_t caliptra_crypto_verify_signature(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *pub_key_handle,
    uint32_t flags,
    const uint8_t digest[CALIPTRA_SHA384_HASH_SIZE],
    const uint8_t *sig, uint32_t sig_len,
    bool *out_valid);

#endif /* CALIPTRA_CRYPTO_EXT_H */
