// Licensed under the Apache-2.0 license

/*
 * OCP L.O.C.K. v1.0 구현
 *
 * caliptra_lock.h에 선언된 모든 OCP LOCK 커맨드 래퍼를 구현합니다.
 * 각 함수는 caliptra_mailbox_execute()를 통해 Caliptra Runtime FW에
 * 메일박스 요청을 전달합니다.
 *
 * libcaliptra는 다음을 자동으로 처리합니다:
 *   - 요청 체크섬 계산 (caliptra_req_header.chksum)
 *   - 응답 체크섬 검증 (caliptra_resp_header.chksum)
 *   - FIPS 상태 확인 (caliptra_resp_header.fips_status)
 *   - 메일박스 잠금 획득/해제 (FSM: IDLE → LOCK → CMD → DATA → EXECUTE → DONE)
 *
 * 레퍼런스:
 *   caliptra-sw/libcaliptra/inc/caliptra_api.h — caliptra_mailbox_execute
 *   caliptra-sw/api/src/mailbox.rs             — Rust 커맨드 코드 및 구조체
 */

#include <string.h>
#include "caliptra_lock.h"

/* ─────────────────────────────────────────────────────────────────────
 * 내부 헬퍼 매크로
 * ───────────────────────────────────────────────────────────────────── */

/* caliptra_buffer 초기화 헬퍼 */
#define MAKE_TX_BUF(req_ptr) \
    ((struct caliptra_buffer){ .data = (const uint8_t*)(req_ptr), .len = sizeof(*(req_ptr)) })

#define MAKE_RX_BUF(resp_ptr) \
    ((struct caliptra_buffer){ .data = (uint8_t*)(resp_ptr), .len = sizeof(*(resp_ptr)) })

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 1: REPORT_HEK_METADATA (0x5248_4D54 "RHMT")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_report_hek_metadata(
    const ocp_lock_report_hek_metadata_req_t *req,
    ocp_lock_report_hek_metadata_resp_t      *resp,
    bool async)
{
    struct caliptra_buffer tx = MAKE_TX_BUF(req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_REPORT_HEK_METADATA, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 2: GET_ALGORITHMS (0x4741_4C47 "GALG")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_get_algorithms(
    ocp_lock_get_algorithms_resp_t *resp,
    bool async)
{
    ocp_lock_get_algorithms_req_t req = { .hdr = { .chksum = 0 } };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_GET_ALGORITHMS, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 3: INITIALIZE_MEK_SECRET (0x494D_4B53 "IMKS")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_initialize_mek_secret(
    const uint8_t sek[32],
    const uint8_t dpk[32],
    ocp_lock_initialize_mek_secret_resp_t *resp,
    bool async)
{
    ocp_lock_initialize_mek_secret_req_t req = { .hdr = { .chksum = 0 }, .reserved = 0 };
    memcpy(req.sek, sek, 32);
    memcpy(req.dpk, dpk, 32);

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    int ret = caliptra_mailbox_execute(OCP_LOCK_INITIALIZE_MEK_SECRET, &tx, &rx, async);

    /* 보안: 스택의 키 데이터 제로화 */
    memset(&req, 0, sizeof(req));
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 4: MIX_MPK (0x4D4D_504B "MMPK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_mix_mpk(
    const ocp_lock_wrapped_key_t *enabled_mpk,
    ocp_lock_mix_mpk_resp_t      *resp,
    bool async)
{
    ocp_lock_mix_mpk_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.enabled_mpk, enabled_mpk, sizeof(ocp_lock_wrapped_key_t));

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_MIX_MPK, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 5: DERIVE_MEK (0x444D_454B "DMEK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_derive_mek(
    const uint8_t mek_checksum[16],
    const uint8_t metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    const uint8_t aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE],
    uint32_t cmd_timeout,
    ocp_lock_derive_mek_resp_t *resp,
    bool async)
{
    ocp_lock_derive_mek_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.mek_checksum, mek_checksum, 16);
    memcpy(req.metadata,     metadata,     OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE);
    memcpy(req.aux_metadata, aux_metadata, OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE);
    req.cmd_timeout = cmd_timeout;

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_DERIVE_MEK, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 6: ENUMERATE_HPKE_HANDLES (0x4548_444C "EHDL")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_enumerate_hpke_handles(
    ocp_lock_enumerate_hpke_handles_resp_t *resp,
    bool async)
{
    ocp_lock_enumerate_hpke_handles_req_t req = { .hdr = { .chksum = 0 }, .reserved = 0 };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_ENUMERATE_HPKE_HANDLES, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 7: ROTATE_HPKE_KEY (0x5248_504B "RHPK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_rotate_hpke_key(
    uint32_t hpke_handle,
    ocp_lock_rotate_hpke_key_resp_t *resp,
    bool async)
{
    ocp_lock_rotate_hpke_key_req_t req = {
        .hdr         = { .chksum = 0 },
        .reserved    = 0,
        .hpke_handle = hpke_handle,
    };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_ROTATE_HPKE_KEY, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 8: GENERATE_MEK (0x474D_454B "GMEK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_generate_mek(
    ocp_lock_generate_mek_resp_t *resp,
    bool async)
{
    ocp_lock_generate_mek_req_t req = { .hdr = { .chksum = 0 }, .reserved = 0 };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_GENERATE_MEK, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 9: GET_HPKE_PUB_KEY (0x4748_504B "GHPK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_get_hpke_pub_key(
    uint32_t hpke_handle,
    ocp_lock_get_hpke_pub_key_resp_t *resp,
    bool async)
{
    ocp_lock_get_hpke_pub_key_req_t req = {
        .hdr         = { .chksum = 0 },
        .reserved    = 0,
        .hpke_handle = hpke_handle,
    };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_GET_HPKE_PUB_KEY, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 10: GENERATE_MPK (0x474D_504B "GMPK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_generate_mpk(
    const uint8_t                       sek[32],
    const uint8_t                      *metadata,
    uint32_t                            metadata_len,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_generate_mpk_resp_t       *resp,
    bool async)
{
    ocp_lock_generate_mpk_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.sek, sek, 32);

    if (metadata && metadata_len > 0 && metadata_len <= OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN) {
        req.metadata_len = metadata_len;
        memcpy(req.metadata, metadata, metadata_len);
    }

    memcpy(&req.sealed_access_key, sealed_access_key, sizeof(ocp_lock_sealed_access_key_t));

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    int ret = caliptra_mailbox_execute(OCP_LOCK_GENERATE_MPK, &tx, &rx, async);

    memset(&req, 0, sizeof(req));
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 11: REWRAP_MPK (0x5245_5750 "REWP")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_rewrap_mpk(
    const uint8_t                       sek[32],
    const ocp_lock_wrapped_key_t       *current_locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const uint8_t                       new_ak_ciphertext[48],
    ocp_lock_rewrap_mpk_resp_t         *resp,
    bool async)
{
    ocp_lock_rewrap_mpk_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.sek, sek, 32);
    memcpy(&req.current_locked_mpk, current_locked_mpk, sizeof(ocp_lock_wrapped_key_t));
    memcpy(&req.sealed_access_key,  sealed_access_key,  sizeof(ocp_lock_sealed_access_key_t));
    memcpy(req.new_ak_ciphertext,   new_ak_ciphertext,  48);

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    int ret = caliptra_mailbox_execute(OCP_LOCK_REWRAP_MPK, &tx, &rx, async);

    memset(&req, 0, sizeof(req));
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 12: ENABLE_MPK (0x524D_504B "RMPK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_enable_mpk(
    const uint8_t                       sek[32],
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const ocp_lock_wrapped_key_t       *locked_mpk,
    ocp_lock_enable_mpk_resp_t         *resp,
    bool async)
{
    ocp_lock_enable_mpk_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.sek, sek, 32);
    memcpy(&req.sealed_access_key, sealed_access_key, sizeof(ocp_lock_sealed_access_key_t));
    memcpy(&req.locked_mpk,        locked_mpk,        sizeof(ocp_lock_wrapped_key_t));

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    int ret = caliptra_mailbox_execute(OCP_LOCK_ENABLE_MPK, &tx, &rx, async);

    memset(&req, 0, sizeof(req));
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 13: TEST_ACCESS_KEY (0x5441_434B "TACK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_test_access_key(
    const uint8_t                       sek[32],
    const uint8_t                       nonce[32],
    const ocp_lock_wrapped_key_t       *locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_test_access_key_resp_t    *resp,
    bool async)
{
    ocp_lock_test_access_key_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.sek,   sek,   32);
    memcpy(req.nonce, nonce, 32);
    memcpy(&req.locked_mpk,       locked_mpk,       sizeof(ocp_lock_wrapped_key_t));
    memcpy(&req.sealed_access_key, sealed_access_key, sizeof(ocp_lock_sealed_access_key_t));

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    int ret = caliptra_mailbox_execute(OCP_LOCK_TEST_ACCESS_KEY, &tx, &rx, async);

    memset(&req, 0, sizeof(req));
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 14: GET_STATUS (0x4753_5441 "GSTA")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_get_status(
    ocp_lock_get_status_resp_t *resp,
    bool async)
{
    ocp_lock_get_status_req_t req = { .hdr = { .chksum = 0 } };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_GET_STATUS, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 15: CLEAR_KEY_CACHE (0x434C_4B43 "CLKC")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_clear_key_cache(
    uint32_t cmd_timeout,
    ocp_lock_clear_key_cache_resp_t *resp,
    bool async)
{
    ocp_lock_clear_key_cache_req_t req = {
        .hdr         = { .chksum = 0 },
        .reserved    = 0,
        .cmd_timeout = cmd_timeout,
    };
    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_CLEAR_KEY_CACHE, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 16: UNLOAD_MEK (0x554D_454B "UMEK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_unload_mek(
    const uint8_t metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    uint32_t cmd_timeout,
    ocp_lock_unload_mek_resp_t *resp,
    bool async)
{
    ocp_lock_unload_mek_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.metadata, metadata, OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE);
    req.cmd_timeout = cmd_timeout;

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_UNLOAD_MEK, &tx, &rx, async);
}

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 17: LOAD_MEK (0x4C4D_454B "LMEK")
 * ───────────────────────────────────────────────────────────────────── */

int caliptra_lock_load_mek(
    const uint8_t                  metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    const uint8_t                  aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE],
    const ocp_lock_wrapped_key_t  *wrapped_mek,
    uint32_t cmd_timeout,
    ocp_lock_load_mek_resp_t      *resp,
    bool async)
{
    ocp_lock_load_mek_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.metadata,     metadata,     OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE);
    memcpy(req.aux_metadata, aux_metadata, OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE);
    memcpy(&req.wrapped_mek, wrapped_mek,  sizeof(ocp_lock_wrapped_key_t));
    req.cmd_timeout = cmd_timeout;

    struct caliptra_buffer tx = MAKE_TX_BUF(&req);
    struct caliptra_buffer rx = MAKE_RX_BUF(resp);
    return caliptra_mailbox_execute(OCP_LOCK_LOAD_MEK, &tx, &rx, async);
}
