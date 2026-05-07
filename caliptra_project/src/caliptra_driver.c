/*
 * Caliptra 2.x SoC 드라이버 구현
 *
 * 이 파일은 caliptra_driver.h의 구현체입니다.
 * 플랫폼별 HAL(caliptra_hw_ops_t)을 통해 하드웨어에 접근합니다.
 *
 * 레지스터 오프셋 출처: caliptra_regs.h
 * 프로토콜 출처: Caliptra 2.1 spec (doc/Caliptra.md)
 */

#include <string.h>
#include "../include/caliptra_driver.h"
#include "../include/caliptra_regs.h"

/* ---------------------------------------------------------------------------
 * 내부 헬퍼 매크로
 * --------------------------------------------------------------------------- */
#define DRV_LOG(ctx, fmt, ...) \
    do { if ((ctx)->ops->log) (ctx)->ops->log(fmt, ##__VA_ARGS__); } while(0)

#define DRV_CHECK(ctx) \
    do { if (!(ctx) || !(ctx)->initialized) return CALIPTRA_ERR_NOT_READY; } while(0)

#define ALIGN_UP4(x)  (((x) + 3U) & ~3U)

/* 레지스터 접근 래퍼 */
#define REG_R(ctx, off)    ((ctx)->ops->reg_read(off))
#define REG_W(ctx, off, v) ((ctx)->ops->reg_write((off), (v)))

/* 메일박스 폴링 기본 인터벌 (마이크로초) */
#define MBOX_POLL_INTERVAL_US  10U

/* ---------------------------------------------------------------------------
 * 초기화
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_driver_init(caliptra_ctx_t *ctx,
                                        const caliptra_hw_ops_t *ops,
                                        uint32_t mbox_timeout_us)
{
    if (!ctx || !ops) return CALIPTRA_ERR_INVALID_PARAM;
    if (!ops->reg_read || !ops->reg_write) return CALIPTRA_ERR_INVALID_PARAM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ops             = ops;
    ctx->mbox_timeout_us = mbox_timeout_us;
    ctx->initialized     = true;
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 부트 플로우 API
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_wait_for_fuse_ready(caliptra_ctx_t *ctx)
{
    DRV_CHECK(ctx);
    uint32_t elapsed = 0;

    while (true) {
        /* CPTRA_FLOW_STATUS의 ready_for_fuse 비트 또는 전용 신호 확인 */
        if (ctx->ops->is_ready_for_fuse && ctx->ops->is_ready_for_fuse())
            return CALIPTRA_OK;

        /* 신호 핸들러가 없으면 FLOW_STATUS 레지스터 폴링 */
        uint32_t status = REG_R(ctx, CPTRA_FLOW_STATUS_OFFSET);
        if (status & (1U << 0))  /* ready_for_fuse bit */
            return CALIPTRA_OK;

        if (ctx->ops->delay_us)
            ctx->ops->delay_us(MBOX_POLL_INTERVAL_US);

        if (ctx->mbox_timeout_us > 0) {
            elapsed += MBOX_POLL_INTERVAL_US;
            if (elapsed >= ctx->mbox_timeout_us)
                return CALIPTRA_ERR_TIMEOUT;
        }
    }
}

caliptra_status_t caliptra_program_fuses(caliptra_ctx_t *ctx,
                                          const caliptra_fuse_t *fuse)
{
    DRV_CHECK(ctx);
    if (!fuse) return CALIPTRA_ERR_INVALID_PARAM;

    /* UDS Seed (512 bit = 16 DWORDS) */
    for (int i = 0; i < 16; i++)
        REG_W(ctx, CPTRA_FUSE_UDS_SEED_BASE_OFFSET + i * 4, fuse->uds_seed[i]);

    /* Field Entropy (256 bit = 8 DWORDS) */
    for (int i = 0; i < 8; i++)
        REG_W(ctx, CPTRA_FUSE_FIELD_ENTROPY_BASE_OFFSET + i * 4, fuse->field_entropy[i]);

    /* Vendor PK Hash (384 bit = 12 DWORDS) */
    for (int i = 0; i < 12; i++)
        REG_W(ctx, CPTRA_FUSE_VENDOR_PK_HASH_BASE_OFFSET + i * 4, fuse->vendor_pk_hash[i]);

    REG_W(ctx, CPTRA_FUSE_ECC_REVOCATION_OFFSET, fuse->ecc_revocation);

    /* Owner PK Hash (384 bit = 12 DWORDS) */
    for (int i = 0; i < 12; i++)
        REG_W(ctx, CPTRA_FUSE_OWNER_PK_HASH_BASE_OFFSET + i * 4, fuse->owner_pk_hash[i]);

    /* Runtime SVN (128 bit = 4 DWORDS) */
    for (int i = 0; i < 4; i++)
        REG_W(ctx, CPTRA_FUSE_RUNTIME_SVN_BASE_OFFSET + i * 4, fuse->runtime_svn[i]);

    REG_W(ctx, CPTRA_FUSE_ANTI_ROLLBACK_DISABLE_OFFSET, fuse->anti_rollback_disable);

    /* IDevID Cert Attr (768 bit = 24 DWORDS) */
    for (int i = 0; i < 24; i++)
        REG_W(ctx, CPTRA_FUSE_IDEVID_CERT_ATTR_BASE_OFFSET + i * 4, fuse->idevid_cert_attr[i]);

    REG_W(ctx, CPTRA_FUSE_LIFE_CYCLE_OFFSET, fuse->life_cycle);
    REG_W(ctx, CPTRA_FUSE_LMS_REVOCATION_OFFSET, fuse->lms_revocation);
    REG_W(ctx, CPTRA_FUSE_MLDSA_REVOCATION_OFFSET, fuse->mldsa_revocation);  /* 2.0+ */
    REG_W(ctx, CPTRA_FUSE_SOC_STEPPING_ID_OFFSET, fuse->soc_stepping_id);
    REG_W(ctx, CPTRA_FUSE_PQC_KEY_TYPE_OFFSET, fuse->pqc_key_type);          /* 2.0+ */

    /* SOC Manifest SVN (128 bit = 4 DWORDS) */
    for (int i = 0; i < 4; i++)
        REG_W(ctx, CPTRA_FUSE_SOC_MANIFEST_SVN_BASE_OFFSET + i * 4, fuse->soc_manifest_svn[i]);

    /* OCP L.O.C.K. HEK Ratchet Seed (256 bit = 8 DWORDS, 2.1+, in-field programmable) */
    for (int i = 0; i < 8; i++)
        REG_W(ctx, CPTRA_FUSE_HEK_RATCHET_SEED_BASE_OFFSET + i * 4, fuse->hek_ratchet_seed[i]);

    /* Fuse 쓰기 완료 → LOCK */
    REG_W(ctx, CPTRA_FUSE_WR_DONE_OFFSET, 1U);

    DRV_LOG(ctx, "Caliptra: fuse programming done\n");
    return CALIPTRA_OK;
}

caliptra_status_t caliptra_wait_for_fw_ready(caliptra_ctx_t *ctx)
{
    DRV_CHECK(ctx);
    uint32_t elapsed = 0;

    while (true) {
        if (ctx->ops->is_ready_for_fw && ctx->ops->is_ready_for_fw())
            return CALIPTRA_OK;

        uint32_t status = REG_R(ctx, CPTRA_FLOW_STATUS_OFFSET);
        if (status & CPTRA_FLOW_STATUS_READY_FOR_FW)
            return CALIPTRA_OK;

        /* Fatal 오류 감시 */
        if (ctx->ops->is_error_fatal && ctx->ops->is_error_fatal())
            return CALIPTRA_ERR_FATAL;

        if (ctx->ops->delay_us)
            ctx->ops->delay_us(MBOX_POLL_INTERVAL_US);

        if (ctx->mbox_timeout_us > 0) {
            elapsed += MBOX_POLL_INTERVAL_US;
            if (elapsed >= ctx->mbox_timeout_us)
                return CALIPTRA_ERR_TIMEOUT;
        }
    }
}

caliptra_status_t caliptra_load_firmware(caliptra_ctx_t *ctx,
                                          const void *fw_image,
                                          uint32_t fw_size)
{
    DRV_CHECK(ctx);
    if (!fw_image || fw_size == 0) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_mbox_cmd_t cmd = {
        .cmd          = CALIPTRA_CMD_FIRMWARE_LOAD,
        .req          = fw_image,
        .req_len      = fw_size,
        .resp         = NULL,
        .resp_max_len = 0,
        .resp_actual_len = NULL,
        .timeout_us   = ctx->mbox_timeout_us,
    };
    return caliptra_mbox_send(ctx, &cmd);
}

caliptra_status_t caliptra_wait_for_rt_ready(caliptra_ctx_t *ctx)
{
    DRV_CHECK(ctx);
    uint32_t elapsed = 0;

    while (true) {
        if (ctx->ops->is_ready_for_rtflows && ctx->ops->is_ready_for_rtflows())
            return CALIPTRA_OK;

        uint32_t status = REG_R(ctx, CPTRA_FLOW_STATUS_OFFSET);
        if (status & CPTRA_FLOW_STATUS_READY_FOR_RT)
            return CALIPTRA_OK;

        if (ctx->ops->is_error_fatal && ctx->ops->is_error_fatal())
            return CALIPTRA_ERR_FATAL;

        if (ctx->ops->delay_us)
            ctx->ops->delay_us(MBOX_POLL_INTERVAL_US);

        if (ctx->mbox_timeout_us > 0) {
            elapsed += MBOX_POLL_INTERVAL_US;
            if (elapsed >= ctx->mbox_timeout_us)
                return CALIPTRA_ERR_TIMEOUT;
        }
    }
}

/* ---------------------------------------------------------------------------
 * 저수준 메일박스 API (8단계 프로토콜)
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_mbox_send(caliptra_ctx_t *ctx,
                                      caliptra_mbox_cmd_t *cmd)
{
    DRV_CHECK(ctx);
    if (!cmd) return CALIPTRA_ERR_INVALID_PARAM;

    uint32_t elapsed = 0;

    /* Step 1: LOCK 획득 */
    while (REG_R(ctx, MBOX_LOCK_OFFSET) != 0) {
        if (ctx->ops->delay_us)
            ctx->ops->delay_us(MBOX_POLL_INTERVAL_US);
        if (cmd->timeout_us > 0) {
            elapsed += MBOX_POLL_INTERVAL_US;
            if (elapsed >= cmd->timeout_us)
                return CALIPTRA_ERR_MBOX_LOCK;
        }
    }

    /* Step 2: 커맨드 코드 */
    REG_W(ctx, MBOX_CMD_OFFSET, cmd->cmd);

    /* Step 3: 데이터 길이 */
    REG_W(ctx, MBOX_DLEN_OFFSET, cmd->req_len);

    /* Step 4: 입력 데이터 (32비트 단위) */
    if (cmd->req && cmd->req_len > 0) {
        const uint32_t *src = (const uint32_t *)cmd->req;
        uint32_t dwords = ALIGN_UP4(cmd->req_len) / 4;
        for (uint32_t i = 0; i < dwords; i++)
            REG_W(ctx, MBOX_DATAIN_OFFSET, src[i]);
    }

    /* Step 5: 실행 시작 */
    REG_W(ctx, MBOX_EXECUTE_OFFSET, 1U);

    /* Step 6: 완료 대기 */
    elapsed = 0;
    uint32_t status;
    while (true) {
        status = REG_R(ctx, MBOX_STATUS_OFFSET) & 0x03U;  /* 하위 2비트 = 상태 */
        if (status != MBOX_STATUS_CMD_BUSY)
            break;

        if (ctx->ops->delay_us)
            ctx->ops->delay_us(MBOX_POLL_INTERVAL_US);

        if (cmd->timeout_us > 0) {
            elapsed += MBOX_POLL_INTERVAL_US;
            if (elapsed >= cmd->timeout_us) {
                REG_W(ctx, MBOX_EXECUTE_OFFSET, 0U);
                return CALIPTRA_ERR_TIMEOUT;
            }
        }
    }

    if (status == MBOX_STATUS_CMD_FAILURE) {
        REG_W(ctx, MBOX_EXECUTE_OFFSET, 0U);
        DRV_LOG(ctx, "Caliptra: mbox cmd 0x%08X failed\n", cmd->cmd);
        return CALIPTRA_ERR_CMD_FAILURE;
    }

    /* Step 7: 응답 데이터 읽기 */
    if (status == MBOX_STATUS_DATA_READY && cmd->resp && cmd->resp_max_len > 0) {
        uint32_t resp_len = REG_R(ctx, MBOX_DLEN_OFFSET);
        uint32_t read_len = (resp_len < cmd->resp_max_len) ? resp_len : cmd->resp_max_len;

        uint32_t *dst = (uint32_t *)cmd->resp;
        uint32_t dwords = ALIGN_UP4(read_len) / 4;
        for (uint32_t i = 0; i < dwords; i++)
            dst[i] = REG_R(ctx, MBOX_DATAOUT_OFFSET);

        if (cmd->resp_actual_len)
            *cmd->resp_actual_len = read_len;
    }

    /* Step 8: LOCK 해제 */
    REG_W(ctx, MBOX_EXECUTE_OFFSET, 0U);

    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 측정값 API
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_stash_measurement(
    caliptra_ctx_t *ctx,
    const caliptra_stash_measurement_req_t *req)
{
    DRV_CHECK(ctx);
    if (!req) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_stash_measurement_resp_t resp;
    uint32_t resp_len = 0;

    /* 체크섬은 호출자가 미리 설정하거나, 여기서 계산 */
    caliptra_stash_measurement_req_t mutable_req;
    memcpy(&mutable_req, req, sizeof(mutable_req));
    mutable_req.chksum = caliptra_mbox_calc_checksum(&mutable_req, sizeof(mutable_req));

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_STASH_MEASUREMENT,
        .req             = &mutable_req,
        .req_len         = sizeof(mutable_req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    if (caliptra_mbox_verify_checksum(&resp, resp_len) != 0)
        return CALIPTRA_ERR_MBOX_STATUS;

    return CALIPTRA_OK;
}

caliptra_status_t caliptra_extend_pcr(caliptra_ctx_t *ctx,
                                       uint32_t pcr_idx,
                                       const uint8_t *measurement)
{
    DRV_CHECK(ctx);
    if (!measurement) return CALIPTRA_ERR_INVALID_PARAM;
    if (pcr_idx < CALIPTRA_PCR_SOC_BASE || pcr_idx > CALIPTRA_PCR_SOC_MAX)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_extend_pcr_req_t req = { 0 };
    req.pcr_idx = pcr_idx;
    memcpy(req.value, measurement, CALIPTRA_SHA384_HASH_SIZE);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_extend_pcr_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_EXTEND_PCR,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    return caliptra_mbox_send(ctx, &cmd);
}

/* ---------------------------------------------------------------------------
 * 인증서 API (공통 구현)
 * --------------------------------------------------------------------------- */
static caliptra_status_t get_cert_common(caliptra_ctx_t *ctx,
                                          uint32_t cmd_code,
                                          uint8_t *cert_buf,
                                          uint32_t *cert_size)
{
    DRV_CHECK(ctx);
    if (!cert_buf || !cert_size || *cert_size == 0)
        return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_get_cert_req_t req = { 0 };
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    /* 응답은 헤더(8 bytes) + 크기(4 bytes) + 인증서 데이터 */
    static uint8_t resp_buf[sizeof(caliptra_get_cert_resp_t)];
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = cmd_code,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = resp_buf,
        .resp_max_len    = sizeof(resp_buf),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    caliptra_get_cert_resp_t *resp = (caliptra_get_cert_resp_t *)resp_buf;
    if (caliptra_mbox_verify_checksum(resp, resp_len) != 0)
        return CALIPTRA_ERR_MBOX_STATUS;

    if (resp->data_size > *cert_size)
        return CALIPTRA_ERR_BUFFER_TOO_SMALL;

    memcpy(cert_buf, resp->data, resp->data_size);
    *cert_size = resp->data_size;
    return CALIPTRA_OK;
}

caliptra_status_t caliptra_get_idevid_cert(caliptra_ctx_t *ctx,
                                             uint8_t *cert_buf,
                                             uint32_t *cert_size)
{
    return get_cert_common(ctx, CALIPTRA_CMD_GET_IDEVID_CERT, cert_buf, cert_size);
}

caliptra_status_t caliptra_get_ldevid_cert(caliptra_ctx_t *ctx,
                                             uint8_t *cert_buf,
                                             uint32_t *cert_size)
{
    return get_cert_common(ctx, CALIPTRA_CMD_GET_LDEVID_CERT, cert_buf, cert_size);
}

caliptra_status_t caliptra_get_fmc_alias_cert(caliptra_ctx_t *ctx,
                                               uint8_t *cert_buf,
                                               uint32_t *cert_size)
{
    return get_cert_common(ctx, CALIPTRA_CMD_GET_FMC_ALIAS_CERT, cert_buf, cert_size);
}

caliptra_status_t caliptra_get_rt_alias_cert(caliptra_ctx_t *ctx,
                                              uint8_t *cert_buf,
                                              uint32_t *cert_size)
{
    return get_cert_common(ctx, CALIPTRA_CMD_GET_RT_ALIAS_CERT, cert_buf, cert_size);
}

/* ---------------------------------------------------------------------------
 * DPE API
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_invoke_dpe(caliptra_ctx_t *ctx,
                                       const uint8_t *dpe_cmd,
                                       uint32_t dpe_cmd_size,
                                       uint8_t *dpe_resp,
                                       uint32_t *dpe_resp_size)
{
    DRV_CHECK(ctx);
    if (!dpe_cmd || !dpe_resp || !dpe_resp_size) return CALIPTRA_ERR_INVALID_PARAM;

    /* 요청 구조체 동적 구성 (스택 사용 주의: 4KB + 헤더) */
    static uint8_t req_buf[sizeof(caliptra_invoke_dpe_req_t)];
    caliptra_invoke_dpe_req_t *req = (caliptra_invoke_dpe_req_t *)req_buf;

    if (dpe_cmd_size > CALIPTRA_DPE_CMD_MAX_SIZE) return CALIPTRA_ERR_INVALID_PARAM;

    req->chksum    = 0;
    req->data_size = dpe_cmd_size;
    memcpy(req->data, dpe_cmd, dpe_cmd_size);

    uint32_t req_total = (uint32_t)offsetof(caliptra_invoke_dpe_req_t, data) + dpe_cmd_size;
    req->chksum = caliptra_mbox_calc_checksum(req, req_total);

    static uint8_t resp_buf[sizeof(caliptra_invoke_dpe_resp_t)];
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_INVOKE_DPE_COMMAND,
        .req             = req,
        .req_len         = req_total,
        .resp            = resp_buf,
        .resp_max_len    = sizeof(resp_buf),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    caliptra_invoke_dpe_resp_t *resp = (caliptra_invoke_dpe_resp_t *)resp_buf;
    if (resp->data_size > *dpe_resp_size) return CALIPTRA_ERR_BUFFER_TOO_SMALL;

    memcpy(dpe_resp, resp->data, resp->data_size);
    *dpe_resp_size = resp->data_size;
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 암호화 서비스 API
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_crypto_sign(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *key_handle,
                                        const uint8_t *digest,
                                        uint32_t flags,
                                        caliptra_crypto_sign_resp_t *resp)
{
    DRV_CHECK(ctx);
    if (!key_handle || !digest || !resp) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_sign_req_t req = { 0 };
    memcpy(&req.key_handle, key_handle, sizeof(caliptra_key_handle_t));
    req.flags = flags;
    memcpy(req.digest, digest, CALIPTRA_SHA384_HASH_SIZE);
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    uint32_t resp_len = 0;
    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_SIGN,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = resp,
        .resp_max_len    = sizeof(*resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    return caliptra_mbox_send(ctx, &cmd);
}

caliptra_status_t caliptra_crypto_rng(caliptra_ctx_t *ctx,
                                       uint32_t length,
                                       uint8_t *out_buf)
{
    DRV_CHECK(ctx);
    if (!out_buf || length == 0 || length > 256) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_crypto_rng_req_t req = { 0 };
    req.length = length;
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_crypto_rng_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_CRYPTO_RNG,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    memcpy(out_buf, resp.data, resp.length);
    return CALIPTRA_OK;
}

/* ---------------------------------------------------------------------------
 * 오류 처리
 * --------------------------------------------------------------------------- */
void caliptra_handle_fatal_error(caliptra_ctx_t *ctx)
{
    if (!ctx || !ctx->initialized) return;

    uint32_t hw_err = REG_R(ctx, CPTRA_HW_ERROR_FATAL_OFFSET);
    uint32_t fw_err = REG_R(ctx, CPTRA_FW_ERROR_FATAL_OFFSET);
    uint32_t hw_enc = REG_R(ctx, CPTRA_HW_ERROR_ENC_OFFSET);
    uint32_t fw_enc = REG_R(ctx, CPTRA_FW_ERROR_ENC_OFFSET);

    DRV_LOG(ctx, "Caliptra FATAL: hw_err=0x%08X fw_err=0x%08X "
                 "hw_enc=0x%08X fw_enc=0x%08X\n",
            hw_err, fw_err, hw_enc, fw_enc);
    /* 실제 리셋은 SoC 플랫폼 코드에서 cptra_rst_b 어설션으로 수행 */
}

void caliptra_handle_non_fatal_error(caliptra_ctx_t *ctx)
{
    if (!ctx || !ctx->initialized) return;

    uint32_t hw_err = REG_R(ctx, CPTRA_HW_ERROR_NON_FATAL_OFFSET);
    uint32_t fw_err = REG_R(ctx, CPTRA_FW_ERROR_NON_FATAL_OFFSET);

    DRV_LOG(ctx, "Caliptra NON-FATAL: hw=0x%08X fw=0x%08X\n", hw_err, fw_err);

    /* W1C: 오류 클리어 */
    REG_W(ctx, CPTRA_HW_ERROR_NON_FATAL_OFFSET, hw_err);
    REG_W(ctx, CPTRA_FW_ERROR_NON_FATAL_OFFSET, fw_err);
}

/* ---------------------------------------------------------------------------
 * 유틸리티
 * --------------------------------------------------------------------------- */
caliptra_status_t caliptra_get_version(caliptra_ctx_t *ctx, uint32_t *version_out)
{
    DRV_CHECK(ctx);
    if (!version_out) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_version_req_t req = { 0 };
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_version_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_VERSION,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    caliptra_status_t st = caliptra_mbox_send(ctx, &cmd);
    if (st != CALIPTRA_OK) return st;

    *version_out = resp.version;
    return CALIPTRA_OK;
}

caliptra_status_t caliptra_fips_self_test(caliptra_ctx_t *ctx)
{
    DRV_CHECK(ctx);

    caliptra_req_hdr_t req = { 0 };
    req.chksum = caliptra_mbox_calc_checksum(&req, sizeof(req));

    caliptra_resp_hdr_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_FIPS_SELF_TEST,
        .req             = &req,
        .req_len         = sizeof(req),
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    return caliptra_mbox_send(ctx, &cmd);
}

caliptra_status_t caliptra_set_auth_manifest(caliptra_ctx_t *ctx,
                                              const void *manifest,
                                              uint32_t manifest_size)
{
    DRV_CHECK(ctx);
    if (!manifest || manifest_size == 0) return CALIPTRA_ERR_INVALID_PARAM;

    /* 헤더(8바이트) + 크기(4바이트) + 매니페스트 데이터 */
    static uint8_t req_buf[12 + 128 * 1024];  /* 최대 128KiB */
    uint32_t *p = (uint32_t *)req_buf;
    p[0] = 0;             /* chksum placeholder */
    p[1] = manifest_size;
    memcpy(req_buf + 8, manifest, manifest_size);
    uint32_t total = 8 + manifest_size;
    p[0] = caliptra_mbox_calc_checksum(req_buf, total);

    caliptra_set_auth_manifest_resp_t resp;
    uint32_t resp_len = 0;

    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_SET_AUTH_MANIFEST,
        .req             = req_buf,
        .req_len         = total,
        .resp            = &resp,
        .resp_max_len    = sizeof(resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    return caliptra_mbox_send(ctx, &cmd);
}

caliptra_status_t caliptra_authorize_and_stash(
    caliptra_ctx_t *ctx,
    const caliptra_authorize_and_stash_req_t *req,
    caliptra_authorize_and_stash_resp_t *resp)
{
    DRV_CHECK(ctx);
    if (!req || !resp) return CALIPTRA_ERR_INVALID_PARAM;

    caliptra_authorize_and_stash_req_t mreq;
    memcpy(&mreq, req, sizeof(mreq));
    mreq.chksum = caliptra_mbox_calc_checksum(&mreq, sizeof(mreq));

    uint32_t resp_len = 0;
    caliptra_mbox_cmd_t cmd = {
        .cmd             = CALIPTRA_CMD_AUTHORIZE_AND_STASH,
        .req             = &mreq,
        .req_len         = sizeof(mreq),
        .resp            = resp,
        .resp_max_len    = sizeof(*resp),
        .resp_actual_len = &resp_len,
        .timeout_us      = ctx->mbox_timeout_us,
    };

    return caliptra_mbox_send(ctx, &cmd);
}
