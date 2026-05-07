#ifndef CALIPTRA_TYPES_H
#define CALIPTRA_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------------------
 * Caliptra 2.x 공통 타입 정의
 * 참조: https://github.com/chipsalliance/caliptra-sw/blob/main/runtime/README.md
 * --------------------------------------------------------------------------- */

/* 반환 코드 */
typedef enum {
    CALIPTRA_OK                  = 0,
    CALIPTRA_ERR_BUSY            = -1,
    CALIPTRA_ERR_TIMEOUT         = -2,
    CALIPTRA_ERR_MBOX_LOCK       = -3,
    CALIPTRA_ERR_MBOX_STATUS     = -4,
    CALIPTRA_ERR_CMD_FAILURE     = -5,
    CALIPTRA_ERR_INVALID_PARAM   = -6,
    CALIPTRA_ERR_BUFFER_TOO_SMALL= -7,
    CALIPTRA_ERR_NOT_READY       = -8,
    CALIPTRA_ERR_FATAL           = -9,
} caliptra_status_t;

/* 메일박스 상태 값 */
typedef enum {
    MBOX_STATUS_CMD_BUSY     = 0x00,
    MBOX_STATUS_DATA_READY   = 0x01,
    MBOX_STATUS_CMD_COMPLETE = 0x02,
    MBOX_STATUS_CMD_FAILURE  = 0x03,
} caliptra_mbox_status_t;

/* 보안 상태 인코딩 (security_state[2:0]) */
typedef enum {
    CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED = 0b000,
    CALIPTRA_SEC_STATE_DBG_LOCKED_MANUFACTURING   = 0b101,
    CALIPTRA_SEC_STATE_DBG_LOCKED_PRODUCTION      = 0b111,
    CALIPTRA_SEC_STATE_DBG_UNLOCKED_PRODUCTION    = 0b011,
} caliptra_security_state_t;

/* 라이프사이클 상태 (LIFE_CYCLE fuse) */
typedef enum {
    CALIPTRA_LC_UNPROVISIONED = 0b00,
    CALIPTRA_LC_MANUFACTURING = 0b01,
    CALIPTRA_LC_UNDEFINED     = 0b10,
    CALIPTRA_LC_PRODUCTION    = 0b11,
} caliptra_lifecycle_t;

/* PCR 인덱스 */
typedef enum {
    CALIPTRA_PCR_ROM_FW_ID       = 0,   /* Caliptra ROM 측정값 */
    CALIPTRA_PCR_FMC_FW_ID       = 1,   /* Caliptra FMC 측정값 */
    CALIPTRA_PCR_RT_FW_ID        = 2,   /* Caliptra Runtime 측정값 */
    CALIPTRA_PCR_CALIPTRA_CFG    = 3,   /* Caliptra 구성 측정값 */
    CALIPTRA_PCR_SOC_BASE        = 4,   /* SoC 측정값 (4~30) */
    CALIPTRA_PCR_SOC_MAX         = 30,
    CALIPTRA_PCR_CUMULATIVE      = 31,  /* 누적 측정값 */
} caliptra_pcr_index_t;

/* SHA384 해시 크기 */
#define CALIPTRA_SHA384_HASH_SIZE   48
#define CALIPTRA_SHA512_HASH_SIZE   64
#define CALIPTRA_PCR_SIZE           CALIPTRA_SHA384_HASH_SIZE

/* ECC P384 키/서명 크기 */
#define CALIPTRA_ECC384_PUBKEY_SIZE  96  /* X(48) + Y(48) */
#define CALIPTRA_ECC384_PRIVKEY_SIZE 48
#define CALIPTRA_ECC384_SIG_SIZE     96  /* R(48) + S(48) */

/* ML-DSA-87 크기 */
#define CALIPTRA_MLDSA87_PUBKEY_SIZE  2592
#define CALIPTRA_MLDSA87_SIG_SIZE     4627

/* UDS Seed 크기 (2.0: 512 bit) */
#define CALIPTRA_UDS_SEED_SIZE       64  /* bytes */

/* Field Entropy 크기 (256 bit, 2 슬롯) */
#define CALIPTRA_FIELD_ENTROPY_SIZE  32  /* bytes total */
#define CALIPTRA_FIELD_ENTROPY_SLOTS  2
#define CALIPTRA_FIELD_ENTROPY_SLOT_SIZE 16

/* 메일박스 최대 페이로드 크기 */
#define CALIPTRA_MBOX_SIZE_BYTES     (128 * 1024)  /* 128 KiB */

/* 메일박스 메시지 공통 헤더 */
typedef struct {
    uint32_t chksum;    /* Checksum: 모든 DWORD의 합산을 2의 보수 */
    uint32_t fips_status;
} caliptra_mbox_resp_hdr_t;

/* Fuse 구성 구조체 */
typedef struct {
    uint32_t uds_seed[16];                  /* 512 bit */
    uint32_t field_entropy[8];              /* 256 bit */
    uint32_t vendor_pk_hash[12];            /* 384 bit (SHA384) */
    uint32_t ecc_revocation;                /* 4 bit one-hot */
    uint32_t owner_pk_hash[12];             /* 384 bit */
    uint32_t fmc_key_manifest_svn;          /* 32 bit (Deprecated 2.0) */
    uint32_t runtime_svn[4];                /* 128 bit one-hot */
    uint32_t anti_rollback_disable;         /* 1 bit */
    uint32_t idevid_cert_attr[24];          /* 768 bit (352 bit 사용) */
    uint32_t idevid_manuf_hsm_id[4];        /* 128 bit (미사용) */
    uint32_t life_cycle;                    /* 2 bit */
    uint32_t lms_revocation;               /* 32 bit one-hot */
    uint32_t mldsa_revocation;             /* 4 bit one-hot (2.0+) */
    uint32_t soc_stepping_id;              /* 16 bit */
    uint32_t pqc_key_type;                 /* 2 bit: bit0=MLDSA, bit1=LMS */
    uint32_t soc_manifest_svn[4];          /* 128 bit */
    uint32_t manuf_debug_unlock_token[16]; /* 512 bit */
    uint32_t hek_ratchet_seed[8];          /* 256 bit, OCP L.O.C.K. HEK 생성 시드 (2.1+, in-field) */
} caliptra_fuse_t;

/* 메일박스 커맨드 디스크립터 */
typedef struct {
    uint32_t     cmd;           /* 커맨드 코드 */
    const void  *req;           /* 요청 데이터 포인터 */
    uint32_t     req_len;       /* 요청 데이터 크기 (바이트) */
    void        *resp;          /* 응답 버퍼 포인터 */
    uint32_t     resp_max_len;  /* 응답 버퍼 최대 크기 */
    uint32_t    *resp_actual_len; /* 실제 응답 크기 출력 */
    uint32_t     timeout_us;    /* 타임아웃 (마이크로초, 0=무한) */
} caliptra_mbox_cmd_t;

#endif /* CALIPTRA_TYPES_H */
