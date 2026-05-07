/*
 * Caliptra 2.0+ 확장 암호화 서비스 구현
 *
 * caliptra_crypto_ext.h의 모든 함수를 구현합니다.
 * 각 함수는 메일박스 커맨드 하나에 대응하는 얇은 래퍼입니다.
 */

#include <string.h>
#include "../include/caliptra_crypto_ext.h"
#include "../include/caliptra_regs.h"

/* ---------------------------------------------------------------------------
 * 내부 헬퍼
 * --------------------------------------------------------------------------- */
#define CRYPTO_CHECK(ctx) \
    do { if (!(ctx) || !(ctx)->initialized) return CALIPTRA_ERR_NOT_READY; } while(0)

/* ---------------------------------------------------------------------------
 * SHA-384 / SHA-512
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_hash(caliptra_ctx_t *ctx,
                                        uint32_t algorithm,
                                        const uint8_t *data, uint32_t data_len,
                                        uint8_t *out_hash, uint32_t *out_hash_len)
{
    CRYPTO_CHECK(ctx);
    if (!data || !out_hash || !out_hash_len) return CALIPTRA_ERR_INVALID_PARAM;
    if (data_len > (CALIPTRA_MBOX_SIZE_BYTES - 16)) return CALIPTRA_ERR_INVALID_PARAM;

    /* 요청 버퍼: chksum(4) + algorithm(4) + data_size(4) + data */
    static uint8_t req_buf[12 + 512];
    uint32_t *p = (uint32_t *)req_buf;
    p[0] = 0;           /* chksum placeholder */
    p[1] = algorithm;
    p[2] = data_len;
    uint32_t truncated = (data_len > 512) ? 512 : data_len;
    memcpy(req_buf + 12, data, truncated);
    uint32_t total = 12 + truncated;
    p[0] = caliptra_mbox_calc_checksum(req_buf, total);

    caliptra_crypto_hash_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_HASH,
        .req             = req_buf,
        .req_len         = total,
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    uint32_t hash_len = (algorithm == 0) ? CALIPTRA_SHA384_HASH_SIZE : CALIPTRA_SHA512_HASH_SIZE;
    memcpy(out_hash, resp.hash, hash_len);
    *out_hash_len = hash_len;
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * HMAC-SHA384
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_hmac(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *key_handle,
                                        const uint8_t *data, uint32_t data_len,
                                        uint8_t out_hmac[CALIPTRA_SHA384_HASH_SIZE])
{
    CRYPTO_CHECK(ctx);
    if (!key_handle || !data || !out_hmac) return CALIPTRA_ERR_INVALID_PARAM;
    if (data_len > CALIPTRA_HMAC_DATA_MAX) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_hmac_req_t req = { 0 };
    memcpy(&req.key_handle, key_handle, sizeof(*key_handle));
    req.algorithm = 0;  /* HMAC-SHA384 */
    req.data_size = data_len;
    memcpy(req.data, data, data_len);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_hmac_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_HMAC,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_hmac, resp.hmac, CALIPTRA_SHA384_HASH_SIZE);
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * HKDF-SHA384
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_hkdf(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *ikm_handle,
                                        const uint8_t *salt, uint32_t salt_len,
                                        const uint8_t *info, uint32_t info_len,
                                        uint32_t okm_length,
                                        caliptra_key_handle_t *out_handle)
{
    CRYPTO_CHECK(ctx);
    if (!ikm_handle || !out_handle) return CALIPTRA_ERR_INVALID_PARAM;
    if (salt_len > CALIPTRA_HKDF_SALT_MAX) return CALIPTRA_ERR_INVALID_PARAM;
    if (info_len > CALIPTRA_HKDF_INFO_MAX) return CALIPTRA_ERR_INVALID_PARAM;
    if (okm_length == 0 || okm_length > CALIPTRA_HKDF_OKM_MAX) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_hkdf_req_t req = { 0 };
    memcpy(&req.ikm_handle, ikm_handle, sizeof(*ikm_handle));
    req.salt_size = salt_len;
    if (salt && salt_len > 0)
        memcpy(req.salt, salt, salt_len);
    req.info_size = info_len;
    if (info && info_len > 0)
        memcpy(req.info, info, info_len);
    req.okm_length = okm_length;
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_hkdf_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_HKDF,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_handle, &resp.okm_handle, sizeof(*out_handle));
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * AES-256-GCM 암호화
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_aes_gcm_encrypt(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *plaintext, uint32_t pt_len,
    uint8_t *out_ct, uint32_t *out_ct_len,
    uint8_t out_tag[CALIPTRA_AES_GCM_TAG_SIZE])
{
    CRYPTO_CHECK(ctx);
    if (!key_handle || !iv || !plaintext || !out_ct || !out_ct_len || !out_tag)
        return CALIPTRA_ERR_INVALID_PARAM;
    if (pt_len > CALIPTRA_AES_MAX_PT_SIZE) return CALIPTRA_ERR_INVALID_PARAM;
    if (aad_len > CALIPTRA_AES_AAD_MAX_SIZE) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_aes_req_t req = { 0 };
    memcpy(&req.key_handle, key_handle, sizeof(*key_handle));
    memcpy(req.iv, iv, CALIPTRA_AES_GCM_IV_SIZE);
    req.aad_size = aad_len;
    if (aad && aad_len > 0)
        memcpy(req.aad, aad, aad_len);
    req.data_size = pt_len;
    memcpy(req.data, plaintext, pt_len);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_aes_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_ENCRYPT_AES,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_ct, resp.data, resp.data_size);
    *out_ct_len = resp.data_size;
    memcpy(out_tag, resp.tag, CALIPTRA_AES_GCM_TAG_SIZE);
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * AES-256-GCM 복호화
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_aes_gcm_decrypt(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *ciphertext, uint32_t ct_len,
    const uint8_t tag[CALIPTRA_AES_GCM_TAG_SIZE],
    uint8_t *out_pt, uint32_t *out_pt_len)
{
    CRYPTO_CHECK(ctx);
    if (!key_handle || !iv || !ciphertext || !tag || !out_pt || !out_pt_len)
        return CALIPTRA_ERR_INVALID_PARAM;
    if (ct_len > CALIPTRA_AES_MAX_PT_SIZE) return CALIPTRA_ERR_INVALID_PARAM;
    if (aad_len > CALIPTRA_AES_AAD_MAX_SIZE) return CALIPTRA_ERR_INVALID_PARAM;

    /* 복호화 요청: data에 ciphertext + tag를 함께 전달 */
    caliptra_crypto_aes_req_t req = { 0 };
    memcpy(&req.key_handle, key_handle, sizeof(*key_handle));
    memcpy(req.iv, iv, CALIPTRA_AES_GCM_IV_SIZE);
    req.aad_size = aad_len;
    if (aad && aad_len > 0)
        memcpy(req.aad, aad, aad_len);
    req.data_size = ct_len;
    memcpy(req.data, ciphertext, ct_len);
    /* GCM 복호화 시 tag는 aad 마지막 부분으로 전달 (구현체에 따라 다름) */
    memcpy(req.aad + aad_len, tag, CALIPTRA_AES_GCM_TAG_SIZE);
    req.aad_size += CALIPTRA_AES_GCM_TAG_SIZE;
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_aes_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_DECRYPT_AES,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_pt, resp.data, resp.data_size);
    *out_pt_len = resp.data_size;
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * ECDH P-384 키 합의
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_ecdh_key_agree(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *priv_key_handle,
    const uint8_t peer_pub_key[CALIPTRA_ECC384_PUBKEY_SIZE],
    caliptra_key_handle_t *out_ss_handle)
{
    CRYPTO_CHECK(ctx);
    if (!priv_key_handle || !peer_pub_key || !out_ss_handle)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_ecdh_req_t req = { 0 };
    req.generate_ephemeral = 0;
    memcpy(&req.private_key_handle, priv_key_handle, sizeof(*priv_key_handle));
    memcpy(req.peer_pub_key, peer_pub_key, CALIPTRA_ECC384_PUBKEY_SIZE);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_ecdh_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_ECDH_KEY_AGREE,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_ss_handle, &resp.shared_secret_handle, sizeof(*out_ss_handle));
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * ML-KEM-1024 캡슐화
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_ml_kem_encap(
    caliptra_ctx_t *ctx,
    const uint8_t recipient_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    uint8_t out_ct[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle)
{
    CRYPTO_CHECK(ctx);
    if (!recipient_pub || !out_ct || !out_ss_handle)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_ml_kem_encap_req_t req = { 0 };
    memcpy(req.recipient_pub_key, recipient_pub, CALIPTRA_ML_KEM_1024_PUB_SIZE);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_ml_kem_encap_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_ML_KEM_ENCAP,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_ct, resp.ciphertext, CALIPTRA_ML_KEM_1024_CT_SIZE);
    memcpy(out_ss_handle, &resp.shared_secret_handle, sizeof(*out_ss_handle));
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * ML-KEM-1024 역캡슐화
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_ml_kem_decap(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *priv_key_handle,
    const uint8_t ciphertext[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle)
{
    CRYPTO_CHECK(ctx);
    if (!priv_key_handle || !ciphertext || !out_ss_handle)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_ml_kem_decap_req_t req = { 0 };
    memcpy(&req.private_key_handle, priv_key_handle, sizeof(*priv_key_handle));
    memcpy(req.ciphertext, ciphertext, CALIPTRA_ML_KEM_1024_CT_SIZE);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_ml_kem_decap_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_ML_KEM_DECAP,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_ss_handle, &resp.shared_secret_handle, sizeof(*out_ss_handle));
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 키 임포트
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_import_key(
    caliptra_ctx_t *ctx,
    caliptra_key_type_t key_type,
    const uint8_t *key_data, uint32_t key_size,
    caliptra_key_handle_t *out_handle)
{
    CRYPTO_CHECK(ctx);
    if (!key_data || !out_handle) return CALIPTRA_ERR_INVALID_PARAM;
    if (key_size > CALIPTRA_IMPORT_KEY_MAX_SIZE) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_import_key_req_t req = { 0 };
    req.key_type = key_type;
    req.key_size = key_size;
    memcpy(req.key_data, key_data, key_size);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_import_key_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_IMPORT_KEY,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_handle, &resp.handle, sizeof(*out_handle));
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 서명 검증 (ECDSA P-384 / ML-DSA-87)
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_verify_signature(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *pub_key_handle,
    uint32_t flags,
    const uint8_t digest[CALIPTRA_SHA384_HASH_SIZE],
    const uint8_t *sig, uint32_t sig_len,
    bool *out_valid)
{
    CRYPTO_CHECK(ctx);
    if (!pub_key_handle || !digest || !sig || !out_valid)
        return CALIPTRA_ERR_INVALID_PARAM;
    if (sig_len > CALIPTRA_VERIFY_SIG_MAX_SIZE) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_verify_req_t req = { 0 };
    memcpy(&req.pub_key_handle, pub_key_handle, sizeof(*pub_key_handle));
    req.flags = flags;
    memcpy(req.digest, digest, CALIPTRA_SHA384_HASH_SIZE);
    req.sig_size = sig_len;
    memcpy(req.sig, sig, sig_len);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_verify_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_VERIFY,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    *out_valid = (resp.verify_result == 0);
    return CALIPTRA_OK;
}
