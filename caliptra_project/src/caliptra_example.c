// Licensed under the Apache-2.0 license

/*
 * Caliptra 2.x SoC 통합 예제
 *
 * 실제 libcaliptra API (caliptra-sw/libcaliptra/inc/caliptra_api.h) 를 사용하는
 * 전형적인 SoC 부팅 및 Runtime 커맨드 흐름을 보여줍니다.
 *
 * 빌드 include 경로:
 *   -I caliptra-sw/libcaliptra/inc
 *   -I caliptra-sw/registers/generated-src
 *   -I caliptra_project/include
 *
 * 링크:
 *   caliptra-sw/libcaliptra/src/caliptra_api.c
 *   caliptra_project/src/caliptra_driver.c   (HAL — 플랫폼별 구현 필요)
 *   caliptra_project/src/caliptra_lock.c     (OCP LOCK 래퍼)
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* libcaliptra 공개 API */
#include "caliptra_api.h"
#include "caliptra_types.h"
#include "caliptra_enums.h"

/* 프로젝트 HAL 및 OCP LOCK */
#include "caliptra_driver.h"
#include "caliptra_lock.h"

/* ─────────────────────────────────────────────────────────────────────
 * 예제 1: 완전한 부팅 시퀀스
 * ─────────────────────────────────────────────────────────────────────
 *
 * 이 함수는 SoC ROM/FMC에서 Caliptra를 초기화하는 표준 흐름입니다.
 *
 * WARNING: caliptra_init_fuses()는 시뮬레이션 전용입니다.
 *          실 제품에서는 HW 상태 머신이 Fuse를 프로그래밍합니다.
 */
int example_boot_sequence(const uint8_t *fw_image, uint32_t fw_size)
{
    int ret;

    /* 단계 1: 플랫폼 HAL 초기화 (SoC별 APB 주소 설정) */
    ret = caliptra_platform_init(0x10000000); /* SoC APB 베이스 주소 */
    if (ret != 0) {
        printf("HAL init failed: %d\n", ret);
        return ret;
    }

    /* 단계 2: Fuse 준비 대기 */
    if (!caliptra_ready_for_fuses()) {
        printf("Caliptra not ready for fuses\n");
        return -1;
    }

    /* 단계 3: Fuse 프로그래밍 (시뮬레이션 전용)
     * 실 제품: 이 단계는 HW 상태 머신이 수행 */
    struct caliptra_fuses fuses = {
        .uds_seed         = { /* 48바이트 UDS (0으로 초기화 — 실제는 HSM에서 주입) */ },
        .field_entropy    = { /* 32바이트 Field Entropy */ },
        .vendor_pk_hash   = { /* Vendor ECC/MLDSA 공개키 해시 */ },
        .ecc_revocation   = 0,
        .owner_pk_hash    = { /* Owner 공개키 해시 */ },
        .fw_svn           = { 0 },
        .anti_rollback_disable = false,
        .life_cycle       = Manufacturing,
        .lms_revocation   = 0,
        .mldsa_revocation = 0,
        .fuse_pqc_key_type = 0,
        .soc_stepping_id  = 0,
    };

    ret = caliptra_init_fuses(&fuses);
    if (ret != NO_ERROR) {
        printf("Fuse init failed: %d\n", ret);
        return ret;
    }

    /* 단계 4: BootFSM 시작 */
    ret = caliptra_bootfsm_go();
    if (ret != NO_ERROR) {
        printf("BootFSM go failed: %d\n", ret);
        return ret;
    }

    /* 단계 5: FW 업로드 준비 대기 */
    ret = (int)caliptra_ready_for_firmware();
    if (ret != NO_ERROR) {
        printf("Caliptra FW upload error: 0x%08X\n",
               caliptra_read_fw_fatal_error());
        return ret;
    }

    /* 단계 6: FW 업로드 */
    struct caliptra_buffer fw_buf = {
        .data = fw_image,
        .len  = fw_size,
    };

    ret = caliptra_upload_fw(&fw_buf, false /* 동기 */);
    if (ret != NO_ERROR) {
        printf("FW upload failed: %d\n", ret);
        return ret;
    }

    /* 단계 7: Runtime 준비 대기 */
    ret = (int)caliptra_ready_for_runtime();
    if (ret != NO_ERROR) {
        printf("Caliptra runtime error: 0x%08X\n",
               caliptra_read_fw_fatal_error());
        return ret;
    }

    printf("Caliptra boot complete\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 2: 측정값 Stash (Boot Flow)
 * ─────────────────────────────────────────────────────────────────────
 *
 * SoC ROM에서 부팅 중 측정값을 Caliptra에 Stash합니다.
 * 최대 8개의 측정값을 저장할 수 있습니다.
 */
int example_stash_measurement(const uint8_t *component_hash, uint32_t pcr_index)
{
    struct caliptra_stash_measurement_req req = {
        .hdr           = { .chksum = 0 },
        .metadata      = { 0 },  /* SoC별 측정 컨텍스트 */
        .measurement   = { 0 },  /* 48바이트 SHA384 해시 */
        .context       = { 0 },
        .svn           = 0,
    };
    memcpy(req.measurement, component_hash, 48);

    struct caliptra_stash_measurement_resp resp = {0};

    int ret = caliptra_stash_measurement(&req, &resp, false);
    if (ret != NO_ERROR) {
        printf("Stash measurement failed: %d\n", ret);
    }
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 3: 인증서 획득 (ECC384 + MLDSA87 이중 지원)
 * ─────────────────────────────────────────────────────────────────────
 *
 * Caliptra 2.x는 ECC384와 MLDSA87 두 가지 서명 알고리즘을 지원합니다.
 * 각 인증서 API는 _ecc384_ 또는 _mldsa87_ 변형으로 제공됩니다.
 */
int example_get_certificates(void)
{
    int ret;

    /* IDevID ECC384 인증서 */
    struct caliptra_get_idev_ecc384_cert_resp ecc_idev_resp = {0};
    struct caliptra_get_idev_ecc384_cert_req  ecc_idev_req  = { .hdr = { .chksum = 0 } };
    ret = caliptra_get_idev_ecc384_cert(&ecc_idev_req, &ecc_idev_resp, false);
    if (ret == NO_ERROR) {
        printf("IDevID ECC384 cert size: %u bytes\n", ecc_idev_resp.cert_size);
    }

    /* IDevID MLDSA87 인증서 (양자 내성) */
    struct caliptra_get_idev_mldsa87_cert_resp mldsa_idev_resp = {0};
    struct caliptra_get_idev_mldsa87_cert_req  mldsa_idev_req  = { .hdr = { .chksum = 0 } };
    ret = caliptra_get_idev_mldsa87_cert(&mldsa_idev_req, &mldsa_idev_resp, false);
    if (ret == NO_ERROR) {
        printf("IDevID MLDSA87 cert size: %u bytes\n", mldsa_idev_resp.cert_size);
    }

    /* LDevID ECC384 인증서 */
    struct caliptra_get_ldev_ecc384_cert_resp ldev_resp = {0};
    ret = caliptra_get_ldev_ecc384_cert(&ldev_resp, false);
    if (ret == NO_ERROR) {
        printf("LDevID ECC384 cert size: %u bytes\n", ldev_resp.cert_size);
    }

    /* FMC Alias 인증서 */
    struct caliptra_get_fmc_alias_ecc384_cert_resp fmc_resp = {0};
    ret = caliptra_get_fmc_alias_ecc384_cert(&fmc_resp, false);
    if (ret == NO_ERROR) {
        printf("FMC Alias ECC384 cert size: %u bytes\n", fmc_resp.cert_size);
    }

    /* RT Alias 인증서 */
    struct caliptra_get_rt_alias_ecc384_cert_resp rt_resp = {0};
    ret = caliptra_get_rt_alias_ecc384_cert(&rt_resp, false);
    if (ret == NO_ERROR) {
        printf("RT Alias ECC384 cert size: %u bytes\n", rt_resp.cert_size);
    }

    return NO_ERROR;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 4: PCR Quote (서명된 증명)
 * ─────────────────────────────────────────────────────────────────────
 *
 * PCR 값에 대한 서명된 Quote를 요청합니다.
 * ECC384와 MLDSA87 두 가지 버전이 있습니다.
 */
int example_quote_pcrs(const uint8_t *nonce_32bytes)
{
    struct caliptra_quote_pcrs_req req = {
        .hdr   = { .chksum = 0 },
        .nonce = { 0 },
    };
    memcpy(req.nonce, nonce_32bytes, sizeof(req.nonce));

    /* ECC384 Quote */
    struct caliptra_quote_pcrs_ecc384_resp ecc_resp = {0};
    int ret = caliptra_quote_pcrs_ecc384(&req, &ecc_resp, false);
    if (ret == NO_ERROR) {
        printf("PCR ECC384 Quote obtained\n");
    }

    /* MLDSA87 Quote (양자 내성) */
    struct caliptra_quote_pcrs_mldsa87_resp mldsa_resp = {0};
    ret = caliptra_quote_pcrs_mldsa87(&req, &mldsa_resp, false);
    if (ret == NO_ERROR) {
        printf("PCR MLDSA87 Quote obtained\n");
    }

    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 5: Authorization Manifest + Authorize and Stash
 * ─────────────────────────────────────────────────────────────────────
 *
 * SoC이 이미지를 로드하기 전 Caliptra에 인증을 요청합니다.
 */
int example_authorize_image(
    const uint8_t *manifest_data, uint32_t manifest_size,
    const uint8_t *fw_id, const uint8_t *image_hash_48bytes,
    uint32_t image_size)
{
    int ret;

    /* Authorization Manifest 설정 */
    struct caliptra_set_auth_manifest_req auth_req;
    memset(&auth_req, 0, sizeof(auth_req));
    if (manifest_size <= sizeof(auth_req.manifest)) {
        auth_req.manifest_size = manifest_size;
        memcpy(auth_req.manifest, manifest_data, manifest_size);
    }

    ret = caliptra_set_auth_manifest(&auth_req, false);
    if (ret != NO_ERROR) {
        printf("Set auth manifest failed: %d\n", ret);
        return ret;
    }

    /* 이미지 인증 및 측정값 Stash */
    struct caliptra_authorize_and_stash_req stash_req;
    memset(&stash_req, 0, sizeof(stash_req));
    memcpy(stash_req.fw_id,       fw_id,            sizeof(stash_req.fw_id));
    memcpy(stash_req.measurement, image_hash_48bytes, 48);
    stash_req.svn        = 0;
    stash_req.flags      = 0; /* SKIP_STASH = 0x1 이면 stash 생략 */
    stash_req.source     = IN_REQUEST;
    stash_req.image_size = image_size;

    struct caliptra_authorize_and_stash_resp stash_resp = {0};
    ret = caliptra_authorize_and_stash(&stash_req, &stash_resp, false);
    if (ret != NO_ERROR) {
        printf("Authorize and stash failed: %d\n", ret);
        return ret;
    }

    if (stash_resp.auth_req_result == AUTHORIZE_IMAGE) {
        printf("Image authorized\n");
    } else if (stash_resp.auth_req_result == IMAGE_NOT_AUTHORIZED) {
        printf("Image NOT authorized\n");
        return -1;
    } else if (stash_resp.auth_req_result == IMAGE_HASH_MISMATCH) {
        printf("Image hash mismatch\n");
        return -1;
    }

    return NO_ERROR;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 6: DPE 커맨드 (DICE Protection Environment)
 * ─────────────────────────────────────────────────────────────────────
 *
 * DPE는 DICE 키 파생 및 인증서 발급 서비스입니다.
 * ECC384와 MLDSA87 두 가지 변형이 있습니다.
 */
int example_dpe_derive_context(void)
{
    /* DPE DERIVE_CONTEXT 커맨드 구성 */
    struct caliptra_invoke_dpe_req req = {0};

    /* DPE 커맨드 헤더 (TLV 직렬화) */
    /* dpe_command 필드에 DPE 바이너리 직렬화 데이터를 채웁니다 */
    /* 실제 DPE 직렬화 형식은 caliptra-sw/dpe/README.md 참조 */

    struct caliptra_invoke_dpe_resp resp = {0};

    /* ECC384 DPE 커맨드 */
    int ret = caliptra_invoke_dpe_command(&req, &resp, false);
    if (ret == NO_ERROR) {
        printf("DPE ECC384 command success\n");
    }

    /* MLDSA87 DPE 커맨드 (양자 내성) */
    struct caliptra_invoke_dpe_mldsa87_req mldsa_req = {0};
    struct caliptra_invoke_dpe_resp mldsa_resp = {0};
    ret = caliptra_invoke_dpe_mldsa87_command(&mldsa_req, &mldsa_resp, false);

    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 7: OCP L.O.C.K. MEK 전달 (GENERATE_MEK 방법)
 * ─────────────────────────────────────────────────────────────────────
 *
 * 새 MEK를 생성하고 SSD 암호화 엔진에 로드하는 전체 흐름입니다.
 * MEK plaintext는 SoC FW에 절대 노출되지 않습니다.
 */
int example_lock_generate_and_load_mek(void)
{
    int ret;

    /* 단계 1: 지원 알고리즘 확인 */
    ocp_lock_get_algorithms_resp_t alg_resp = {0};
    ret = caliptra_lock_get_algorithms(&alg_resp, false);
    if (ret != NO_ERROR) {
        printf("GET_ALGORITHMS failed: %d\n", ret);
        return ret;
    }
    printf("HPKE algorithms: 0x%08X\n", alg_resp.hpke_algorithms);

    /* 단계 2: HPKE 핸들 열거 */
    ocp_lock_enumerate_hpke_handles_resp_t enum_resp = {0};
    ret = caliptra_lock_enumerate_hpke_handles(&enum_resp, false);
    if (ret != NO_ERROR || enum_resp.hpke_handle_count == 0) {
        printf("No HPKE handles available\n");
        return -1;
    }
    uint32_t hpke_handle = enum_resp.hpke_handles[0].handle;

    /* 단계 3: HPKE 공개키 획득 (SSD에 전달) */
    ocp_lock_get_hpke_pub_key_resp_t pubkey_resp = {0};
    ret = caliptra_lock_get_hpke_pub_key(hpke_handle, &pubkey_resp, false);
    if (ret != NO_ERROR) {
        printf("GET_HPKE_PUB_KEY failed: %d\n", ret);
        return ret;
    }
    printf("HPKE pub key len: %u\n", pubkey_resp.pub_key_len);
    /* 이 공개키를 NVMe Key Programming 커맨드로 SSD에 전달합니다 */

    /* 단계 4: 새 MEK 생성 */
    ocp_lock_generate_mek_resp_t gen_resp = {0};
    ret = caliptra_lock_generate_mek(&gen_resp, false);
    if (ret != NO_ERROR) {
        printf("GENERATE_MEK failed: %d\n", ret);
        return ret;
    }
    printf("MEK generated (wrapped)\n");

    /* 단계 5: MEK를 암호화 엔진에 로드 */
    uint8_t metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE]  = {0};
    uint8_t aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE]   = {0};
    /* metadata/aux_metadata는 SSD 컨트롤러가 요구하는 컨텍스트 정보 */

    ocp_lock_load_mek_resp_t load_resp = {0};
    ret = caliptra_lock_load_mek(
        metadata, aux_metadata, &gen_resp.wrapped_mek,
        5000 /* 5초 타임아웃 */, &load_resp, false);
    if (ret != NO_ERROR) {
        printf("LOAD_MEK failed: %d\n", ret);
        return ret;
    }

    printf("MEK loaded to encryption engine\n");
    return NO_ERROR;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 8: FIPS 버전 및 자체 테스트
 * ─────────────────────────────────────────────────────────────────────
 */
int example_fips(void)
{
    /* FIPS 버전 조회 */
    struct caliptra_fips_version_resp ver_resp = {0};
    int ret = caliptra_fips_version(&ver_resp, false);
    if (ret == NO_ERROR) {
        printf("FIPS mode: 0x%08X, FIPS version: %u.%u.%u\n",
               ver_resp.mode,
               ver_resp.fips_rev[0], ver_resp.fips_rev[1], ver_resp.fips_rev[2]);
    }

    /* FIPS 자체 테스트 */
    ret = caliptra_self_test_start(false);
    if (ret == NO_ERROR) {
        printf("FIPS self test started\n");
    }

    /* 자체 테스트 결과 확인 */
    ret = caliptra_self_test_get_results(false);
    if (ret == NO_ERROR) {
        printf("FIPS self test passed\n");
    }

    return ret;
}

/* ─────────────────────────────────────────────────────────────────────
 * 예제 9: 비동기 메일박스 사용
 * ─────────────────────────────────────────────────────────────────────
 *
 * async=true로 커맨드를 발행한 후 완료를 폴링합니다.
 */
int example_async_fw_info(void)
{
    struct caliptra_fw_info_resp resp = {0};

    /* 비동기로 커맨드 발행 */
    int ret = caliptra_fw_info(&resp, true /* async */);
    if (ret != NO_ERROR) {
        printf("fw_info async issue failed: %d\n", ret);
        return ret;
    }

    /* 완료 폴링 */
    while (!caliptra_test_for_completion()) {
        caliptra_wait(); /* HAL 구현에 따라 yield/nop */
    }

    /* 응답 수집 */
    ret = caliptra_complete();
    if (ret == NO_ERROR) {
        printf("FW Info: ECC aliases=%u, MLDSA aliases=%u\n",
               resp.attestation_disabled,
               resp.attestation_disabled);
    }

    return ret;
}
