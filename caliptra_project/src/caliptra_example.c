/*
 * Caliptra 2.x SoC 통합 예제
 *
 * 이 파일은 Passive 모드 SoC ROM/FMC에서 Caliptra를 초기화하고
 * 부트 시퀀스에서 측정값을 stash하는 전형적인 흐름을 보여줍니다.
 *
 * 실제 SoC에서는 아래 플랫폼 HAL 함수들을 구현해야 합니다.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../include/caliptra_driver.h"
#include "../include/caliptra_regs.h"

/* ===========================================================================
 * [구현 필요] 플랫폼별 HAL 구현
 * =========================================================================== */

/* SoC의 실제 Caliptra MMIO 베이스 주소 (통합 시 설정) */
#define MY_CALIPTRA_BASE_ADDR  0x10000000UL

static uint32_t platform_reg_read(uint32_t offset)
{
    volatile uint32_t *addr = (volatile uint32_t *)(MY_CALIPTRA_BASE_ADDR + offset);
    return *addr;
}

static void platform_reg_write(uint32_t offset, uint32_t value)
{
    volatile uint32_t *addr = (volatile uint32_t *)(MY_CALIPTRA_BASE_ADDR + offset);
    *addr = value;
}

static bool platform_is_ready_for_fuse(void)
{
    /* SoC 플랫폼의 ready_for_fuse 신호 (GPIO, 레지스터 폴링 등) */
    return false;  /* 구현 필요 */
}

static bool platform_is_ready_for_fw(void)
{
    return false;  /* 구현 필요 */
}

static bool platform_is_ready_for_rtflows(void)
{
    return false;  /* 구현 필요 */
}

static bool platform_is_error_fatal(void)
{
    return false;  /* 구현 필요: cptra_error_fatal 신호 읽기 */
}

static bool platform_is_error_non_fatal(void)
{
    return false;  /* 구현 필요 */
}

static void platform_delay_us(uint32_t us)
{
    /* SoC 타이머 기반 딜레이 구현 */
    volatile uint32_t dummy = us * 100;
    while (dummy--) { /* busy wait placeholder */ }
}

static void platform_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* HAL 구현체 */
static const caliptra_hw_ops_t g_caliptra_ops = {
    .reg_read             = platform_reg_read,
    .reg_write            = platform_reg_write,
    .is_ready_for_fuse    = platform_is_ready_for_fuse,
    .is_ready_for_fw      = platform_is_ready_for_fw,
    .is_ready_for_rtflows = platform_is_ready_for_rtflows,
    .is_error_fatal       = platform_is_error_fatal,
    .is_error_non_fatal   = platform_is_error_non_fatal,
    .delay_us             = platform_delay_us,
    .log                  = platform_log,
};

/* ===========================================================================
 * 예제: Fuse 데이터 (실제 프로젝트에서는 안전한 소스에서 로드)
 * =========================================================================== */

static caliptra_fuse_t g_fuse_data = {
    /* UDS Seed: 실제 값은 제조 시 프로그래밍 (난독화된 512 bit)
     * 예시: 모두 0 (개발/테스트용 debug UDS) */
    .uds_seed = { 0 },

    /* Field Entropy: 소유자가 현장에서 프로그래밍 */
    .field_entropy = { 0 },

    /* Vendor PK Hash: Caliptra FW 서명 검증용 공개키 SHA384 해시 */
    .vendor_pk_hash = {
        /* SHA384 of vendor ECC P384 + ML-DSA public keys */
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
    },

    .ecc_revocation = 0,   /* 폐기된 ECC 키 없음 */
    .lms_revocation = 0,   /* 폐기된 LMS 키 없음 */
    .mldsa_revocation = 0, /* 폐기된 ML-DSA 키 없음 */

    .runtime_svn = { 1, 0, 0, 0 },  /* SVN = 1 (one-hot, bit 0) */
    .anti_rollback_disable = 0,      /* Anti-rollback 활성화 */

    .life_cycle = 0x03,  /* Production */
    .pqc_key_type = CPTRA_FUSE_PQC_KEY_TYPE_MLDSA,  /* ML-DSA 사용 */

    .soc_stepping_id = 0x0001,
};

/* ===========================================================================
 * 예제 1: Passive 모드 Cold Boot 시퀀스
 * SoC ROM에서 호출
 * =========================================================================== */

/*
 * 외부 FW 이미지 로드 함수 (플랫폼별 구현 필요)
 * 예: Flash, NVME, 네트워크 등에서 Caliptra FW 바이너리 로드
 */
extern int platform_load_caliptra_fw(uint8_t **fw_buf, uint32_t *fw_size);
extern void platform_free_fw_buf(uint8_t *fw_buf);

/*
 * SoC FMC 해시 계산 (SoC 플랫폼별 구현)
 * SHA384(SoC FMC 바이너리)를 계산하여 반환
 */
extern int platform_hash_soc_fmc(uint8_t *hash_out_48bytes);

int caliptra_cold_boot_sequence(void)
{
    caliptra_ctx_t ctx;
    caliptra_status_t st;

    printf("[Boot] Caliptra initialization start\n");

    /* 드라이버 초기화 (10초 타임아웃) */
    st = caliptra_driver_init(&ctx, &g_caliptra_ops, 10 * 1000 * 1000);
    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: driver init failed (%d)\n", st);
        return -1;
    }

    /* 1. Fuse 쓰기 준비 대기 */
    printf("[Boot] Waiting for fuse ready...\n");
    st = caliptra_wait_for_fuse_ready(&ctx);
    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: fuse ready timeout (%d)\n", st);
        return -1;
    }

    /* 2. Fuse 레지스터 프로그래밍 + FUSE_WR_DONE */
    printf("[Boot] Programming fuses...\n");
    st = caliptra_program_fuses(&ctx, &g_fuse_data);
    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: fuse programming failed (%d)\n", st);
        return -1;
    }

    /* 3. FW 로드 준비 대기 (Passive 모드) */
    printf("[Boot] Waiting for firmware ready signal...\n");
    st = caliptra_wait_for_fw_ready(&ctx);
    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: fw ready timeout (%d)\n", st);
        return -1;
    }

    /* 4. Caliptra FW 이미지 로드 */
    uint8_t *fw_buf = NULL;
    uint32_t fw_size = 0;
    if (platform_load_caliptra_fw(&fw_buf, &fw_size) != 0) {
        printf("[Boot] ERROR: failed to load Caliptra FW\n");
        return -1;
    }

    printf("[Boot] Loading Caliptra FW (%u bytes)...\n", fw_size);
    st = caliptra_load_firmware(&ctx, fw_buf, fw_size);
    platform_free_fw_buf(fw_buf);

    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: FW load failed (%d)\n", st);
        return -1;
    }

    /* 5. Runtime 준비 대기 */
    printf("[Boot] Waiting for runtime ready...\n");
    st = caliptra_wait_for_rt_ready(&ctx);
    if (st != CALIPTRA_OK) {
        printf("[Boot] ERROR: RT ready timeout (%d)\n", st);
        return -1;
    }

    printf("[Boot] Caliptra runtime ready!\n");

    /* 6. SoC FMC 측정값 Stash */
    uint8_t soc_fmc_hash[CALIPTRA_SHA384_HASH_SIZE] = { 0 };
    if (platform_hash_soc_fmc(soc_fmc_hash) == 0) {
        caliptra_stash_measurement_req_t meas_req = { 0 };
        meas_req.metadata[0] = 'F';
        meas_req.metadata[1] = 'M';
        meas_req.metadata[2] = 'C';
        meas_req.metadata[3] = '0';
        memcpy(meas_req.measurement, soc_fmc_hash, CALIPTRA_SHA384_HASH_SIZE);
        meas_req.svn = 1;

        st = caliptra_stash_measurement(&ctx, &meas_req);
        if (st != CALIPTRA_OK)
            printf("[Boot] WARNING: stash measurement failed (%d)\n", st);
        else
            printf("[Boot] SoC FMC measurement stashed\n");
    }

    return 0;
}

/* ===========================================================================
 * 예제 2: Runtime에서 증명(Attestation) 수집
 * SoC 런타임 펌웨어에서 호출
 * =========================================================================== */

int caliptra_collect_attestation(caliptra_ctx_t *ctx)
{
    caliptra_status_t st;

    /* IDevID 인증서 획득 */
    static uint8_t idevid_cert[CALIPTRA_CERT_MAX_SIZE];
    uint32_t idevid_cert_size = sizeof(idevid_cert);

    st = caliptra_get_idevid_cert(ctx, idevid_cert, &idevid_cert_size);
    if (st != CALIPTRA_OK) {
        printf("[RT] ERROR: get IDevID cert failed (%d)\n", st);
        return -1;
    }
    printf("[RT] IDevID cert: %u bytes\n", idevid_cert_size);

    /* RT Alias 인증서 획득 */
    static uint8_t rt_alias_cert[CALIPTRA_CERT_MAX_SIZE];
    uint32_t rt_cert_size = sizeof(rt_alias_cert);

    st = caliptra_get_rt_alias_cert(ctx, rt_alias_cert, &rt_cert_size);
    if (st != CALIPTRA_OK) {
        printf("[RT] ERROR: get RT Alias cert failed (%d)\n", st);
        return -1;
    }
    printf("[RT] RT Alias cert: %u bytes\n", rt_cert_size);

    /* PCR Quote 생성 (freshness nonce 포함) */
    static uint8_t nonce[32];
    /* 실제 사용 시 검증자에서 받은 nonce 사용 */
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)i;

    static uint8_t pcr_quote[CALIPTRA_PCR_QUOTE_MAX_SIZE];
    uint32_t quote_size = sizeof(pcr_quote);

    st = caliptra_get_pcr_quote(ctx, nonce, pcr_quote, &quote_size);
    if (st != CALIPTRA_OK) {
        printf("[RT] WARNING: get PCR quote failed (%d)\n", st);
    } else {
        printf("[RT] PCR quote: %u bytes\n", quote_size);
    }

    /* 원격 검증자에게 전송 (플랫폼별 구현) */
    /* send_attestation_to_verifier(idevid_cert, rt_alias_cert, pcr_quote, ...); */

    return 0;
}

/* ===========================================================================
 * 예제 3: SPDM을 위한 DPE 서명 오라클
 * =========================================================================== */

int caliptra_spdm_sign_example(caliptra_ctx_t *ctx,
                                const uint8_t *challenge_hash,
                                uint8_t *sig_r_out,
                                uint8_t *sig_s_out)
{
    /* DPE Sign 커맨드를 통해 RT Alias Key로 서명 */
    /* DPE 커맨드 직렬화는 TCG DPE Profile 스펙 참조 */

    /* 간단화된 예시: DPE Sign 요청 구조 */
    typedef struct {
        uint32_t command_id;     /* 0x0000000A = Sign */
        uint32_t context_handle[8];
        uint8_t  label[48];
        uint8_t  is_symmetric;
        uint8_t  to_sign[48];   /* 서명할 해시 */
    } dpe_sign_req_t;

    dpe_sign_req_t dpe_req = { 0 };
    dpe_req.command_id = 0x0000000A;  /* DPE Sign command ID */
    memcpy(dpe_req.to_sign, challenge_hash, 48);

    static uint8_t dpe_resp_buf[512];
    uint32_t resp_size = sizeof(dpe_resp_buf);

    caliptra_status_t st = caliptra_invoke_dpe(ctx,
                                                (const uint8_t *)&dpe_req,
                                                sizeof(dpe_req),
                                                dpe_resp_buf,
                                                &resp_size);
    if (st != CALIPTRA_OK) {
        printf("[SPDM] DPE sign failed (%d)\n", st);
        return -1;
    }

    /* DPE 응답에서 서명 추출 (프로토콜 파싱 필요) */
    /* ... */
    (void)sig_r_out;
    (void)sig_s_out;

    printf("[SPDM] DPE sign succeeded (%u bytes response)\n", resp_size);
    return 0;
}

/* ===========================================================================
 * 예제 4: PCR 확장 (Runtime 중 추가 측정)
 * =========================================================================== */

int caliptra_runtime_measure_example(caliptra_ctx_t *ctx)
{
    /* 예: PCR4에 SoC 구성 파라미터 측정값 확장 */
    uint8_t soc_config_hash[CALIPTRA_SHA384_HASH_SIZE];
    /* 플랫폼별 SHA384 계산 */
    memset(soc_config_hash, 0xAB, CALIPTRA_SHA384_HASH_SIZE);  /* 예시값 */

    caliptra_status_t st = caliptra_extend_pcr(ctx, 4, soc_config_hash);
    if (st != CALIPTRA_OK) {
        printf("[RT] ERROR: PCR4 extend failed (%d)\n", st);
        return -1;
    }
    printf("[RT] PCR4 extended with SoC config measurement\n");

    /* 예: PCR5에 OS 이미지 측정값 확장 */
    uint8_t os_hash[CALIPTRA_SHA384_HASH_SIZE];
    memset(os_hash, 0xCD, CALIPTRA_SHA384_HASH_SIZE);  /* 예시값 */

    st = caliptra_extend_pcr(ctx, 5, os_hash);
    if (st != CALIPTRA_OK) {
        printf("[RT] ERROR: PCR5 extend failed (%d)\n", st);
        return -1;
    }
    printf("[RT] PCR5 extended with OS measurement\n");

    return 0;
}

/* ===========================================================================
 * 예제 5: Fatal 오류 처리 인터럽트 핸들러 패턴
 * =========================================================================== */

static caliptra_ctx_t g_ctx;  /* 전역 컨텍스트 (인터럽트 핸들러에서 접근) */

void cptra_error_fatal_isr(void)
{
    /* 인터럽트 서비스 루틴 */
    caliptra_handle_fatal_error(&g_ctx);

    /* Caliptra 리셋 (플랫폼별 구현) */
    /* platform_assert_cptra_rst_b();
     * platform_delay_us(10);
     * platform_deassert_cptra_rst_b(); */
}

void cptra_error_non_fatal_isr(void)
{
    caliptra_handle_non_fatal_error(&g_ctx);
}

/* ===========================================================================
 * 메인 예제 진입점
 * =========================================================================== */

int main(void)
{
    printf("=== Caliptra 2.x SoC Integration Example ===\n\n");

    /* Cold boot 시퀀스 */
    if (caliptra_cold_boot_sequence() != 0) {
        printf("ERROR: Cold boot sequence failed\n");
        return 1;
    }

    /* 이후 Runtime 사용 예시 */
    caliptra_ctx_t rt_ctx;
    caliptra_driver_init(&rt_ctx, &g_caliptra_ops, 5 * 1000 * 1000);

    /* Runtime 측정값 확장 */
    caliptra_runtime_measure_example(&rt_ctx);

    /* Attestation 수집 */
    caliptra_collect_attestation(&rt_ctx);

    /* 버전 확인 */
    uint32_t version = 0;
    if (caliptra_get_version(&rt_ctx, &version) == CALIPTRA_OK)
        printf("[RT] Caliptra FW version: %d.%d.%d\n",
               (version >> 24) & 0xFF,
               (version >> 16) & 0xFF,
               version & 0xFFFF);

    printf("\n=== Example complete ===\n");
    return 0;
}
