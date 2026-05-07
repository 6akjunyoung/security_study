#ifndef CALIPTRA_MBOX_H
#define CALIPTRA_MBOX_H

/*
 * Caliptra 2.x 메일박스 커맨드 코드 및 요청/응답 구조체
 *
 * 커맨드 코드 및 구조체 상세:
 *   https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md
 *
 * 커맨드 코드는 4바이트 ASCII 코드 또는 숫자로 인코딩됩니다.
 * 모든 커맨드 요청/응답은 4바이트 체크섬(DWORD 합산의 2의 보수)으로 시작합니다.
 */

#include <stdint.h>
#include "caliptra_types.h"

/* ---------------------------------------------------------------------------
 * 메일박스 커맨드 코드
 * 출처: caliptra-sw/runtime/README.md
 * --------------------------------------------------------------------------- */

/* FW 로드 (ROM 단계에서 SoC가 사용) */
#define CALIPTRA_CMD_FIRMWARE_LOAD              0x46574C44U  /* 'FWLD' */

/* 측정값 관련 */
#define CALIPTRA_CMD_STASH_MEASUREMENT          0x4D454153U  /* 'MEAS' */
#define CALIPTRA_CMD_EXTEND_PCR                 0x45585443U  /* Runtime only */
#define CALIPTRA_CMD_GET_PCR_QUOTE              0x50435251U  /* 'PCRQ' */

/* 인증서 / 신원 */
#define CALIPTRA_CMD_GET_IDEVID_CERT            0x49444556U  /* IDevID Cert */
#define CALIPTRA_CMD_GET_LDEVID_CERT            0x4C444556U  /* LDevID Cert */
#define CALIPTRA_CMD_GET_FMC_ALIAS_CERT         0x464D4341U  /* FMC Alias Cert */
#define CALIPTRA_CMD_GET_RT_ALIAS_CERT          0x52544143U  /* RT Alias Cert */
#define CALIPTRA_CMD_GET_IDEVID_CSR             0x49435352U  /* IDevID CSR (1.2+) */
#define CALIPTRA_CMD_GET_FMC_ALIAS_CSR          0x46435352U  /* FMC Alias CSR (1.2+) */
#define CALIPTRA_CMD_CERTIFY_KEY                0x43455254U  /* DPE Leaf Cert */
#define CALIPTRA_CMD_CERTIFY_KEY_EXTENDED       0x43455258U  /* Extended (1.1+) */

/* DPE (DICE Protection Environment) */
#define CALIPTRA_CMD_INVOKE_DPE_COMMAND         0x44504543U  /* 'DPEC' */

/* Authorization Manifest (1.2+) */
#define CALIPTRA_CMD_SET_AUTH_MANIFEST          0x41555448U  /* 'AUTH' */
#define CALIPTRA_CMD_AUTHORIZE_AND_STASH        0x415A5354U  /* 'AZST' */

/* 암호화 서비스 (2.0+) */
#define CALIPTRA_CMD_CRYPTO_IMPORT_KEY          0x434D494BU  /* 'CMIK' */
#define CALIPTRA_CMD_CRYPTO_SIGN                0x434D5349U  /* 'CMSI' */
#define CALIPTRA_CMD_CRYPTO_VERIFY              0x434D5652U  /* 'CMVR' */
#define CALIPTRA_CMD_CRYPTO_HASH                0x434D4841U  /* 'CMHA' */
#define CALIPTRA_CMD_CRYPTO_HMAC                0x434D484DU  /* 'CMHM' */
#define CALIPTRA_CMD_CRYPTO_HKDF                0x434D484BU  /* 'CMHK' */
#define CALIPTRA_CMD_CRYPTO_ENCRYPT_AES         0x434D4145U  /* 'CMAE' */
#define CALIPTRA_CMD_CRYPTO_DECRYPT_AES         0x434D4144U  /* 'CMAD' */
#define CALIPTRA_CMD_CRYPTO_ECDH_KEY_AGREE      0x434D4541U  /* 'CMEA' */
#define CALIPTRA_CMD_CRYPTO_RNG                 0x434D524EU  /* 'CMRN' */
#define CALIPTRA_CMD_CRYPTO_ML_KEM_ENCAP        0x434D4B45U  /* 'CMKE' */
#define CALIPTRA_CMD_CRYPTO_ML_KEM_DECAP        0x434D4B44U  /* 'CMKD' */
#define CALIPTRA_CMD_SIGN_WITH_EXPORTED_ECDSA   0x53574558U  /* (1.2+) */
#define CALIPTRA_CMD_REVOKE_EXPORTED_CDI_HANDLE 0x52455643U  /* (1.2+) */

/* LMS 서명 검증 (1.1+) */
#define CALIPTRA_CMD_LMS_SIGNATURE_VERIFY       0x4C4D5356U  /* 'LMSV' */

/* 기타 서비스 */
#define CALIPTRA_CMD_ADD_SUBJECT_ALT_NAME       0x414C544EU  /* (1.1+) */
#define CALIPTRA_CMD_GET_MEASUREMENT            0x47455441U  /* 측정값 조회 */
#define CALIPTRA_CMD_DISABLE_ATTESTATION        0x44415454U  /* Attestation 비활성화 */
#define CALIPTRA_CMD_FIPS_SELF_TEST             0x46495053U  /* FIPS 자체 테스트 */
#define CALIPTRA_CMD_FIPS_GET_VERSION           0x46495056U  /* FIPS 버전 조회 */
#define CALIPTRA_CMD_FIPS_SHUTDOWN              0x46495053U  /* FIPS 셧다운 */
#define CALIPTRA_CMD_CAPABILITIES               0x43415053U  /* 기능 조회 */
#define CALIPTRA_CMD_VERSION                    0x56455253U  /* 버전 조회 */

/* ---------------------------------------------------------------------------
 * 공통 요청/응답 헤더
 * 모든 커맨드는 요청/응답 첫 DWORD가 체크섬입니다.
 * 체크섬 = -(모든 DWORD의 합) % 2^32 (단, 체크섬 필드 자신은 0으로 취급)
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
} caliptra_req_hdr_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;   /* 0 = FIPS approved, 그 외 = 비승인 모드 코드 */
} caliptra_resp_hdr_t;

/* ---------------------------------------------------------------------------
 * STASH_MEASUREMENT 요청/응답 (최대 8개, ROM 및 Runtime에서 가능)
 * --------------------------------------------------------------------------- */
#define CALIPTRA_MEAS_METADATA_SIZE  4
#define CALIPTRA_MEAS_MAX_SIZE       48  /* SHA384 */

typedef struct {
    uint32_t chksum;
    uint8_t  metadata[CALIPTRA_MEAS_METADATA_SIZE]; /* 측정 대상 식별자 */
    uint8_t  measurement[CALIPTRA_MEAS_MAX_SIZE];   /* SHA384 해시 값 */
    uint8_t  context[CALIPTRA_MEAS_MAX_SIZE];       /* 측정 컨텍스트 */
    uint32_t svn;                                    /* Security Version Number */
} caliptra_stash_measurement_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t dpe_result;  /* DPE 처리 결과 코드 */
} caliptra_stash_measurement_resp_t;

/* ---------------------------------------------------------------------------
 * GET_IDEVID_CERT / GET_LDEVID_CERT / GET_FMC_ALIAS_CERT / GET_RT_ALIAS_CERT
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
} caliptra_get_cert_req_t;

#define CALIPTRA_CERT_MAX_SIZE  4096

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t data_size;
    uint8_t  data[CALIPTRA_CERT_MAX_SIZE];
} caliptra_get_cert_resp_t;

/* ---------------------------------------------------------------------------
 * EXTEND_PCR 요청
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
    uint32_t pcr_idx;                         /* PCR4~30 */
    uint8_t  value[CALIPTRA_SHA384_HASH_SIZE]; /* 확장할 측정값 */
} caliptra_extend_pcr_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
} caliptra_extend_pcr_resp_t;

/* ---------------------------------------------------------------------------
 * GET_PCR_QUOTE 요청/응답
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
    uint32_t nonce[8];  /* 256 bit freshness nonce */
} caliptra_get_pcr_quote_req_t;

#define CALIPTRA_PCR_QUOTE_MAX_SIZE  4096

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t quote_size;
    uint8_t  quote[CALIPTRA_PCR_QUOTE_MAX_SIZE];
} caliptra_get_pcr_quote_resp_t;

/* ---------------------------------------------------------------------------
 * INVOKE_DPE_COMMAND 요청/응답 (DPE 커맨드 래퍼)
 * --------------------------------------------------------------------------- */
#define CALIPTRA_DPE_CMD_MAX_SIZE   4096
#define CALIPTRA_DPE_RESP_MAX_SIZE  4096

typedef struct {
    uint32_t chksum;
    uint32_t data_size;
    uint8_t  data[CALIPTRA_DPE_CMD_MAX_SIZE];  /* DPE 직렬화된 커맨드 */
} caliptra_invoke_dpe_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t data_size;
    uint8_t  data[CALIPTRA_DPE_RESP_MAX_SIZE];  /* DPE 직렬화된 응답 */
} caliptra_invoke_dpe_resp_t;

/* ---------------------------------------------------------------------------
 * SET_AUTH_MANIFEST 요청 (1.2+)
 * --------------------------------------------------------------------------- */
#define CALIPTRA_AUTH_MANIFEST_MAX_SIZE  (128 * 1024)

typedef struct {
    uint32_t chksum;
    uint32_t manifest_size;
    uint8_t  manifest[];  /* Flexible array, 실제 사용 시 별도 버퍼 */
} caliptra_set_auth_manifest_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
} caliptra_set_auth_manifest_resp_t;

/* ---------------------------------------------------------------------------
 * AUTHORIZE_AND_STASH 요청/응답 (1.2+)
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
    uint8_t  fw_id[4];                          /* 펌웨어 식별자 */
    uint8_t  measurement[CALIPTRA_SHA384_HASH_SIZE]; /* 펌웨어 해시 */
    uint8_t  context[CALIPTRA_SHA384_HASH_SIZE];     /* 컨텍스트 */
    uint32_t svn;
    uint32_t flags;  /* bit0=SKIP_STASH */
} caliptra_authorize_and_stash_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t auth_result;  /* 0=authorized, 그 외=거부 코드 */
    uint32_t dpe_result;
} caliptra_authorize_and_stash_resp_t;

/* ---------------------------------------------------------------------------
 * 암호화 서비스 (2.0+) - Key Management
 * --------------------------------------------------------------------------- */

/* Key Handle (Caliptra 내부 키 참조자) */
#define CALIPTRA_KEY_HANDLE_SIZE    32

typedef struct {
    uint8_t handle[CALIPTRA_KEY_HANDLE_SIZE];
} caliptra_key_handle_t;

/* 지원 키 타입 */
typedef enum {
    CALIPTRA_KEY_TYPE_ECDSA_P384   = 0x01,
    CALIPTRA_KEY_TYPE_MLDSA87      = 0x02,
    CALIPTRA_KEY_TYPE_AES_256      = 0x03,
    CALIPTRA_KEY_TYPE_HMAC_SHA384  = 0x04,
    CALIPTRA_KEY_TYPE_ML_KEM_1024  = 0x05,
} caliptra_key_type_t;

/* CRYPTO_SIGN 요청 */
typedef struct {
    uint32_t             chksum;
    caliptra_key_handle_t key_handle;
    uint32_t             flags;          /* bit0=ECDSA, bit1=MLDSA */
    uint8_t              digest[CALIPTRA_SHA384_HASH_SIZE]; /* 서명할 해시 */
} caliptra_crypto_sign_req_t;

/* CRYPTO_SIGN 응답 */
typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint8_t  ecc_sig_r[48];    /* ECDSA R */
    uint8_t  ecc_sig_s[48];    /* ECDSA S */
    uint8_t  mldsa_sig[CALIPTRA_MLDSA87_SIG_SIZE]; /* ML-DSA 서명 (flags에 따라) */
} caliptra_crypto_sign_resp_t;

/* CRYPTO_HASH 요청 */
typedef struct {
    uint32_t chksum;
    uint32_t algorithm;   /* 0=SHA384, 1=SHA512 */
    uint32_t data_size;
    uint8_t  data[];      /* Flexible array */
} caliptra_crypto_hash_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint8_t  hash[CALIPTRA_SHA512_HASH_SIZE]; /* 최대 64바이트 */
} caliptra_crypto_hash_resp_t;

/* CRYPTO_RNG 요청/응답 */
typedef struct {
    uint32_t chksum;
    uint32_t length;  /* 요청 난수 크기 (바이트, 최대 256) */
} caliptra_crypto_rng_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t length;
    uint8_t  data[256];  /* 최대 256바이트 난수 */
} caliptra_crypto_rng_resp_t;

/* ---------------------------------------------------------------------------
 * VERSION / CAPABILITIES
 * --------------------------------------------------------------------------- */
typedef struct {
    uint32_t chksum;
} caliptra_version_req_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint32_t version;  /* [31:24]=Major, [23:16]=Minor, [15:0]=Patch */
} caliptra_version_resp_t;

typedef struct {
    uint32_t chksum;
    uint32_t fips_status;
    uint64_t capabilities;  /* 기능 비트맵 */
} caliptra_capabilities_resp_t;

/* ---------------------------------------------------------------------------
 * 체크섬 헬퍼
 * 체크섬 = ~(모든 DWORD 합) + 1 (2의 보수)
 * --------------------------------------------------------------------------- */
static inline uint32_t caliptra_mbox_calc_checksum(const void *buf, uint32_t len_bytes)
{
    const uint32_t *dwords = (const uint32_t *)buf;
    uint32_t n = len_bytes / 4;
    uint32_t sum = 0;
    for (uint32_t i = 1; i < n; i++)  /* i=0은 체크섬 필드 (0으로 취급) */
        sum += dwords[i];
    return (~sum) + 1U;
}

static inline int caliptra_mbox_verify_checksum(const void *buf, uint32_t len_bytes)
{
    const uint32_t *dwords = (const uint32_t *)buf;
    uint32_t n = len_bytes / 4;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < n; i++)
        sum += dwords[i];
    return (sum == 0) ? 0 : -1;
}

#endif /* CALIPTRA_MBOX_H */
