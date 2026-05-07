/*
 * OCP L.O.C.K. (Layered Open Composable Key management) 구현
 *
 * caliptra_lock.h의 모든 함수를 구현합니다.
 *
 * 이 파일은 HPKE (Hybrid Public Key Encryption) 시퀀스를 오케스트레이션합니다.
 * 각 단계는 Caliptra 메일박스 커맨드를 통해 수행되며,
 * MEK plaintext는 항상 Caliptra Key Vault(KV) 내부에만 존재합니다.
 *
 * 스펙: caliptra_project/Caliptra/doc/ocp_lock/
 * 다이어그램: hpke_kem_ecdh.drawio.svg, hpke_kem_mlkem.drawio.svg, hpke_kem_hybrid.drawio.svg
 */

#include <string.h>
#include "../include/caliptra_lock.h"

/* ---------------------------------------------------------------------------
 * 내부 헬퍼: MEK 컨텍스트 → HKDF info 직렬화
 * HKDF info = drive_serial(32) || namespace_id(4) || lba_start(8) || lba_count(8)
 * --------------------------------------------------------------------------- */
static uint32_t lock_serialize_mek_context(const caliptra_lock_mek_context_t *mek_ctx,
                                            uint8_t *buf, uint32_t buf_size)
{
    if (buf_size < 52) return 0;

    uint32_t off = 0;
    memcpy(buf + off, mek_ctx->drive_serial, 32);        off += 32;
    memcpy(buf + off, &mek_ctx->namespace_id, 4);        off += 4;
    memcpy(buf + off, &mek_ctx->lba_start, 8);           off += 8;
    memcpy(buf + off, &mek_ctx->lba_count, 8);           off += 8;
    return off;  /* 52 */
}

/* ---------------------------------------------------------------------------
 * 내부 헬퍼: ECDH HPKE KEM (임시 키 생성 포함)
 * generate_ephemeral=1로 설정하여 Caliptra가 임시 키쌍을 내부 생성합니다.
 * --------------------------------------------------------------------------- */
static caliptra_status_t lock_ecdh_ephemeral(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    caliptra_key_handle_t *out_ss_handle,
    uint8_t out_eph_pub[CALIPTRA_ECC384_PUBKEY_SIZE])
{
    caliptra_crypto_ecdh_req_t req = { 0 };
    req.generate_ephemeral = 1;
    /* private_key_handle는 generate_ephemeral=1일 때 무시됨 */
    memcpy(req.peer_pub_key, drive_ecdh_pub, CALIPTRA_ECC384_PUBKEY_SIZE);
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
    if (out_eph_pub)
        memcpy(out_eph_pub, resp.eph_pub_key, CALIPTRA_ECC384_PUBKEY_SIZE);
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 저수준 HPKE API
 * --------------------------------------------------------------------------- */

caliptra_status_t caliptra_lock_ecdh_encap(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    caliptra_key_handle_t *out_ss_handle,
    uint8_t out_eph_pub[CALIPTRA_ECC384_PUBKEY_SIZE])
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!drive_ecdh_pub || !out_ss_handle || !out_eph_pub)
        return CALIPTRA_ERR_INVALID_PARAM;

    return lock_ecdh_ephemeral(ctx, drive_ecdh_pub, out_ss_handle, out_eph_pub);
}

caliptra_status_t caliptra_lock_mlkem_encap(
    caliptra_ctx_t *ctx,
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    uint8_t out_ct[CALIPTRA_ML_KEM_1024_CT_SIZE],
    caliptra_key_handle_t *out_ss_handle)
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!drive_mlkem_pub || !out_ct || !out_ss_handle)
        return CALIPTRA_ERR_INVALID_PARAM;

    return caliptra_crypto_ml_kem_encap(ctx, drive_mlkem_pub, out_ct, out_ss_handle);
}

caliptra_status_t caliptra_lock_hpke_derive_wrap_key(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *ss_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_key_handle_t *out_wrap_key_handle)
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!ss_handle || !mek_ctx || !out_wrap_key_handle)
        return CALIPTRA_ERR_INVALID_PARAM;

    uint8_t info[52];
    uint32_t info_len = lock_serialize_mek_context(mek_ctx, info, sizeof(info));
    if (info_len == 0) return CALIPTRA_ERR_INVALID_PARAM;

    /* HKDF-SHA384: IKM=shared_secret, salt=없음, info=mek_context, okm=32바이트(AES-256 키) */
    return caliptra_crypto_hkdf(ctx, ss_handle,
                                 NULL, 0,
                                 info, info_len,
                                 32,  /* AES-256 = 32바이트 */
                                 out_wrap_key_handle);
}

caliptra_status_t caliptra_lock_wrap_mek(
    caliptra_ctx_t *ctx,
    const caliptra_key_handle_t *mek_handle,
    const caliptra_key_handle_t *wrap_key_handle,
    const uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE],
    const uint8_t *aad, uint32_t aad_len,
    uint8_t *out_ct, uint32_t *out_ct_len,
    uint8_t out_tag[CALIPTRA_AES_GCM_TAG_SIZE])
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!mek_handle || !wrap_key_handle || !iv || !out_ct || !out_ct_len || !out_tag)
        return CALIPTRA_ERR_INVALID_PARAM;

    /*
     * AES-GCM encrypt(wrap_key, iv, aad, mek_handle)
     * MEK는 KV 핸들로 참조되므로 data 필드를 mek_handle의 핸들 값으로 채웁니다.
     * Caliptra FW는 핸들을 인식하여 실제 MEK를 참조합니다.
     */
    caliptra_crypto_aes_req_t req = { 0 };
    memcpy(&req.key_handle, wrap_key_handle, sizeof(*wrap_key_handle));
    memcpy(req.iv, iv, CALIPTRA_AES_GCM_IV_SIZE);
    req.aad_size = aad_len;
    if (aad && aad_len > 0)
        memcpy(req.aad, aad, aad_len);
    /* data 필드에 MEK 핸들 값을 전달 (Caliptra FW가 해석) */
    memcpy(req.data, mek_handle->handle, CALIPTRA_KEY_HANDLE_SIZE);
    req.data_size = CALIPTRA_KEY_HANDLE_SIZE;
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
 * 고수준 MEK 전달 API
 * --------------------------------------------------------------------------- */

/*
 * IV 생성 헬퍼: RNG로 12바이트 GCM IV 생성
 */
static caliptra_status_t lock_gen_iv(caliptra_ctx_t *ctx,
                                      uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE])
{
    return caliptra_crypto_rng(ctx, CALIPTRA_AES_GCM_IV_SIZE, iv);
}

/* ---------------------------------------------------------------------------
 * ECDH HPKE MEK 전달
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_lock_deliver_mek_ecdh(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_ecdh_mek_blob_t *out_blob)
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!drive_ecdh_pub || !mek_handle || !mek_ctx || !out_blob)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_status_t st;

    /* Step 1: ECDH KEM — 임시 키쌍 생성 + 공유 비밀 */
    caliptra_key_handle_t ss_handle;
    st = lock_ecdh_ephemeral(ctx, drive_ecdh_pub, &ss_handle, out_blob->eph_pub_key);
    if (st != CALIPTRA_OK) return st;

    /* Step 2: HKDF — 공유 비밀 → AES 래핑 키 */
    caliptra_key_handle_t wrap_key;
    st = caliptra_lock_hpke_derive_wrap_key(ctx, &ss_handle, mek_ctx, &wrap_key);
    if (st != CALIPTRA_OK) return st;

    /* Step 3: 랜덤 IV 생성 */
    st = lock_gen_iv(ctx, out_blob->iv);
    if (st != CALIPTRA_OK) return st;

    /* Step 4: AES-256-GCM — MEK 암호화 */
    st = caliptra_lock_wrap_mek(ctx, mek_handle, &wrap_key,
                                  out_blob->iv, NULL, 0,
                                  out_blob->mek_ct, &out_blob->mek_ct_size,
                                  out_blob->tag);
    return st;
}

/* ---------------------------------------------------------------------------
 * ML-KEM HPKE MEK 전달
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_lock_deliver_mek_mlkem(
    caliptra_ctx_t *ctx,
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_mlkem_mek_blob_t *out_blob)
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!drive_mlkem_pub || !mek_handle || !mek_ctx || !out_blob)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_status_t st;

    /* Step 1: ML-KEM encap — ciphertext + 공유 비밀 */
    caliptra_key_handle_t ss_handle;
    st = caliptra_crypto_ml_kem_encap(ctx, drive_mlkem_pub,
                                       out_blob->mlkem_ct, &ss_handle);
    if (st != CALIPTRA_OK) return st;

    /* Step 2: HKDF — 공유 비밀 → AES 래핑 키 */
    caliptra_key_handle_t wrap_key;
    st = caliptra_lock_hpke_derive_wrap_key(ctx, &ss_handle, mek_ctx, &wrap_key);
    if (st != CALIPTRA_OK) return st;

    /* Step 3: 랜덤 IV 생성 */
    st = lock_gen_iv(ctx, out_blob->iv);
    if (st != CALIPTRA_OK) return st;

    /* Step 4: AES-256-GCM — MEK 암호화 */
    st = caliptra_lock_wrap_mek(ctx, mek_handle, &wrap_key,
                                  out_blob->iv, NULL, 0,
                                  out_blob->mek_ct, &out_blob->mek_ct_size,
                                  out_blob->tag);
    return st;
}

/* ---------------------------------------------------------------------------
 * Hybrid HPKE MEK 전달 (ECDH + ML-KEM)
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_lock_deliver_mek_hybrid(
    caliptra_ctx_t *ctx,
    const uint8_t drive_ecdh_pub[CALIPTRA_ECC384_PUBKEY_SIZE],
    const uint8_t drive_mlkem_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE],
    const caliptra_key_handle_t *mek_handle,
    const caliptra_lock_mek_context_t *mek_ctx,
    caliptra_lock_hybrid_mek_blob_t *out_blob)
{
    if (!ctx || !ctx->initialized) return CALIPTRA_ERR_NOT_READY;
    if (!drive_ecdh_pub || !drive_mlkem_pub || !mek_handle || !mek_ctx || !out_blob)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_status_t st;

    /* Step 1a: ECDH KEM */
    caliptra_key_handle_t ss_ecdh;
    st = lock_ecdh_ephemeral(ctx, drive_ecdh_pub, &ss_ecdh, out_blob->eph_pub_key);
    if (st != CALIPTRA_OK) return st;

    /* Step 1b: ML-KEM encap */
    caliptra_key_handle_t ss_mlkem;
    st = caliptra_crypto_ml_kem_encap(ctx, drive_mlkem_pub,
                                       out_blob->mlkem_ct, &ss_mlkem);
    if (st != CALIPTRA_OK) return st;

    /*
     * Step 2: Hybrid HKDF — concat(ss_ecdh, ss_mlkem) → wrap_key
     *
     * HKDF info = mek_context || "hybrid"
     * Caliptra FW에서 두 핸들을 결합하는 방식은 구현 의존적입니다.
     * 여기서는 ss_ecdh 핸들을 IKM으로, ss_mlkem 핸들 값을 salt로 사용합니다.
     */
    uint8_t info[52 + 8];
    uint32_t info_len = lock_serialize_mek_context(mek_ctx, info, 52);
    /* 하이브리드 레이블 추가 */
    const char label[] = "hybrid";
    memcpy(info + info_len, label, 6);
    info_len += 6;

    caliptra_key_handle_t wrap_key;
    st = caliptra_crypto_hkdf(ctx, &ss_ecdh,
                               ss_mlkem.handle, CALIPTRA_KEY_HANDLE_SIZE, /* salt = ml-kem ss handle */
                               info, info_len,
                               32,
                               &wrap_key);
    if (st != CALIPTRA_OK) return st;

    /* Step 3: 랜덤 IV 생성 */
    st = lock_gen_iv(ctx, out_blob->iv);
    if (st != CALIPTRA_OK) return st;

    /* Step 4: AES-256-GCM — MEK 암호화 */
    st = caliptra_lock_wrap_mek(ctx, mek_handle, &wrap_key,
                                  out_blob->iv, NULL, 0,
                                  out_blob->mek_ct, &out_blob->mek_ct_size,
                                  out_blob->tag);
    return st;
}
