#ifndef CALIPTRA_REGS_H
#define CALIPTRA_REGS_H

/*
 * Caliptra 2.x MMIO 레지스터 맵
 *
 * 주의: 오프셋은 Caliptra MMIO 베이스 주소로부터의 상대 주소입니다.
 * 정확한 오프셋은 caliptra-rtl 공식 레지스터 스펙을 확인하세요:
 *   https://ereg.caliptra.org
 *   https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraHardwareSpecification.md
 *
 * SoC 통합 시 베이스 주소를 caliptra_set_base_addr()로 설정하거나
 * CALIPTRA_BASE_ADDR 매크로를 정의하세요.
 */

#include <stdint.h>

#ifndef CALIPTRA_BASE_ADDR
#define CALIPTRA_BASE_ADDR  0x00000000UL  /* SoC 통합 시 실제 주소로 오버라이드 */
#endif

/* 레지스터 접근 헬퍼 매크로 */
#define CALIPTRA_REG(offset)         (*((volatile uint32_t *)(CALIPTRA_BASE_ADDR + (offset))))
#define CALIPTRA_REG_READ(offset)    (CALIPTRA_REG(offset))
#define CALIPTRA_REG_WRITE(offset,v) (CALIPTRA_REG(offset) = (uint32_t)(v))

/* ---------------------------------------------------------------------------
 * 오류 레지스터 (Sticky, powergood reset)
 * --------------------------------------------------------------------------- */
#define CPTRA_HW_ERROR_FATAL_OFFSET         0x00000000UL
#define CPTRA_HW_ERROR_NON_FATAL_OFFSET     0x00000004UL
#define CPTRA_FW_ERROR_FATAL_OFFSET         0x00000008UL
#define CPTRA_FW_ERROR_NON_FATAL_OFFSET     0x0000000CUL
#define CPTRA_HW_ERROR_ENC_OFFSET           0x00000010UL  /* RO */
#define CPTRA_FW_ERROR_ENC_OFFSET           0x00000014UL  /* RO */
#define CPTRA_FW_EXTENDED_ERROR_INFO_OFFSET 0x00000018UL  /* RO, [7:0] DWORDS */

/* ---------------------------------------------------------------------------
 * 부트 / 상태 레지스터
 * --------------------------------------------------------------------------- */
#define CPTRA_BOOT_STATUS_OFFSET            0x00000038UL  /* RO */
#define CPTRA_FLOW_STATUS_OFFSET            0x0000003CUL  /* RW */
#define CPTRA_RESET_REASON_OFFSET           0x00000040UL  /* RO */
#define CPTRA_SECURITY_STATE_OFFSET         0x00000044UL  /* RO */

/* CPTRA_FLOW_STATUS 비트 */
#define CPTRA_FLOW_STATUS_READY_FOR_FW      (1U << 0)
#define CPTRA_FLOW_STATUS_MAILBOX_FLOW_DONE (1U << 1)
#define CPTRA_FLOW_STATUS_READY_FOR_RT      (1U << 2)

/* ---------------------------------------------------------------------------
 * 제어 레지스터
 * --------------------------------------------------------------------------- */
#define CPTRA_FUSE_WR_DONE_OFFSET           0x000000ACUL  /* RW, 1=Fuse 쓰기 완료 */
#define CPTRA_TIMER_CONFIG_OFFSET           0x000000B0UL  /* RW, WDT 설정 */
#define CPTRA_BOOTFSM_GO_OFFSET             0x000000B4UL  /* RW, 1=Boot FSM 진행 허용 */
#define CPTRA_DBG_MANUF_SERVICE_REG_OFFSET  0x000000B8UL  /* RW, 제조/디버그 서비스 */
#define CPTRA_CLKGATING_EN_OFFSET           0x000000C4UL  /* RW, 클록 게이팅 */
#define CPTRA_GENERIC_INPUT_WIRES_OFFSET    0x000000C8UL  /* RO, [1:0] */
#define CPTRA_GENERIC_OUTPUT_WIRES_OFFSET   0x000000D0UL  /* RO, [1:0] */

/* ---------------------------------------------------------------------------
 * Fuse 레지스터 (ready_for_fuse 이후, FUSE_WR_DONE 전에만 쓰기 가능)
 * --------------------------------------------------------------------------- */
#define CPTRA_FUSE_UDS_SEED_BASE_OFFSET          0x00000200UL  /* 16 DWORDS, 512 bit */
#define CPTRA_FUSE_FIELD_ENTROPY_BASE_OFFSET     0x00000240UL  /* 8 DWORDS, 256 bit */
#define CPTRA_FUSE_VENDOR_PK_HASH_BASE_OFFSET    0x00000260UL  /* 12 DWORDS, 384 bit */
#define CPTRA_FUSE_ECC_REVOCATION_OFFSET         0x00000290UL  /* 4 bit one-hot */
#define CPTRA_FUSE_OWNER_PK_HASH_BASE_OFFSET     0x000002A0UL  /* 12 DWORDS, 384 bit */
#define CPTRA_FUSE_FMC_SVN_OFFSET                0x000002D0UL  /* 32 bit (Deprecated 2.0) */
#define CPTRA_FUSE_RUNTIME_SVN_BASE_OFFSET       0x000002E0UL  /* 4 DWORDS, 128 bit one-hot */
#define CPTRA_FUSE_ANTI_ROLLBACK_DISABLE_OFFSET  0x000002F0UL  /* 1 bit */
#define CPTRA_FUSE_IDEVID_CERT_ATTR_BASE_OFFSET  0x000002F4UL  /* 24 DWORDS, 768 bit */
#define CPTRA_FUSE_IDEVID_MANUF_HSM_ID_BASE_OFFSET 0x00000334UL /* 4 DWORDS (미사용) */
#define CPTRA_FUSE_LIFE_CYCLE_OFFSET             0x00000344UL  /* 2 bit */
#define CPTRA_FUSE_LMS_REVOCATION_OFFSET         0x00000348UL  /* 32 bit one-hot */
#define CPTRA_FUSE_MLDSA_REVOCATION_OFFSET       0x0000034CUL  /* 4 bit one-hot (2.0+) */
#define CPTRA_FUSE_SOC_STEPPING_ID_OFFSET        0x00000350UL  /* 16 bit */
#define CPTRA_FUSE_PQC_KEY_TYPE_OFFSET           0x00000360UL  /* 2 bit */
#define CPTRA_FUSE_SOC_MANIFEST_SVN_BASE_OFFSET  0x00000364UL  /* 4 DWORDS, 128 bit */
#define CPTRA_FUSE_MANUF_DBG_UNLOCK_TOKEN_BASE_OFFSET 0x00000374UL /* 16 DWORDS, 512 bit */
#define CPTRA_FUSE_HEK_RATCHET_SEED_BASE_OFFSET      0x00000394UL /* 8 DWORDS, 256 bit (OCP L.O.C.K., 2.1+) */

/* PQC_KEY_TYPE 비트 */
#define CPTRA_FUSE_PQC_KEY_TYPE_MLDSA  (1U << 0)
#define CPTRA_FUSE_PQC_KEY_TYPE_LMS    (1U << 1)

/* ---------------------------------------------------------------------------
 * 메일박스 레지스터
 * --------------------------------------------------------------------------- */
#define MBOX_LOCK_OFFSET                    0x00001000UL  /* RO, 읽기 시 0=LOCK획득 */
#define MBOX_CMD_OFFSET                     0x00001004UL  /* RW, 커맨드 코드 */
#define MBOX_DLEN_OFFSET                    0x00001008UL  /* RW, 데이터 길이 (바이트) */
#define MBOX_DATAIN_OFFSET                  0x0000100CUL  /* WO, 입력 데이터 FIFO */
#define MBOX_DATAOUT_OFFSET                 0x00001010UL  /* RO, 출력 데이터 FIFO */
#define MBOX_EXECUTE_OFFSET                 0x00001014UL  /* RW, 1=실행, 0=LOCK해제 */
#define MBOX_STATUS_OFFSET                  0x00001018UL  /* RO */
#define MBOX_USER_OFFSET                    0x0000101CUL  /* RO, LOCK을 가진 AXI_USER */

/* MBOX_STATUS 비트 */
#define MBOX_STATUS_CMD_BUSY     0x00U
#define MBOX_STATUS_DATA_READY   0x01U
#define MBOX_STATUS_CMD_COMPLETE 0x02U
#define MBOX_STATUS_CMD_FAILURE  0x03U
#define MBOX_STATUS_ECC_SINGLE   (1U << 2)  /* Single-bit ECC 정정 발생 */
#define MBOX_STATUS_ECC_DOUBLE   (1U << 3)  /* Double-bit ECC 오류 */
#define MBOX_STATUS_MBOX_FSM_PS_MASK  (0x7U << 4) /* FSM 상태 */
#define MBOX_STATUS_SOC_HAS_LOCK (1U << 8)  /* SoC가 LOCK 보유 중 */

/* 예약된 AXI_USER (Caliptra 내부 전용, SoC 사용 불가) */
#define CALIPTRA_MBOX_USER_RESERVED  0xFFFFFFFFU

/* ---------------------------------------------------------------------------
 * 서브시스템 모드 관련 레지스터 (2.0 Subsystem)
 * --------------------------------------------------------------------------- */
#define SS_UDS_SEED_BASE_ADDR_L_OFFSET      0x00000354UL  /* UDS Seed 기본 주소 (하위) */
#define SS_UDS_SEED_BASE_ADDR_H_OFFSET      0x00000358UL  /* UDS Seed 기본 주소 (상위) */
#define SS_CALIPTRA_BASE_ADDR_L_OFFSET      0x0000035CUL  /* Caliptra MMIO 기본 주소 (하위) */
#define SS_CALIPTRA_BASE_ADDR_H_OFFSET      0x00000360UL  /* Caliptra MMIO 기본 주소 (상위) */
#define SS_MCI_BASE_ADDR_L_OFFSET           0x00000364UL  /* MCI 기본 주소 (하위) */
#define SS_MCI_BASE_ADDR_H_OFFSET           0x00000368UL  /* MCI 기본 주소 (상위) */
#define SS_RECOVERY_IFC_BASE_ADDR_L_OFFSET  0x0000036CUL  /* Recovery I/F 기본 주소 (하위) */
#define SS_RECOVERY_IFC_BASE_ADDR_H_OFFSET  0x00000370UL  /* Recovery I/F 기본 주소 (상위) */
#define SS_OTP_FC_BASE_ADDR_L_OFFSET        0x00000374UL  /* OTP FC 기본 주소 (하위) */
#define SS_OTP_FC_BASE_ADDR_H_OFFSET        0x00000378UL  /* OTP FC 기본 주소 (상위) */
#define SS_STRAP_GENERIC_0_OFFSET           0x0000037CUL
#define SS_STRAP_GENERIC_1_OFFSET           0x00000380UL
#define SS_STRAP_GENERIC_2_OFFSET           0x00000384UL
#define SS_STRAP_GENERIC_3_OFFSET           0x00000388UL
#define SS_DBG_MANUF_SERVICE_REG_REQ_OFFSET 0x0000038CUL
#define SS_DBG_MANUF_SERVICE_REG_RSP_OFFSET 0x00000390UL
#define SS_DEBUG_INTENT_OFFSET              0x00000394UL
#define SS_STRAP_CALIPTRA_DMA_AXI_USER_OFFSET 0x00000398UL

/* ---------------------------------------------------------------------------
 * 직접 접근 매크로 (CALIPTRA_BASE_ADDR 기반)
 * --------------------------------------------------------------------------- */
#define CPTRA_HW_ERROR_FATAL        CALIPTRA_REG(CPTRA_HW_ERROR_FATAL_OFFSET)
#define CPTRA_HW_ERROR_NON_FATAL    CALIPTRA_REG(CPTRA_HW_ERROR_NON_FATAL_OFFSET)
#define CPTRA_FW_ERROR_FATAL        CALIPTRA_REG(CPTRA_FW_ERROR_FATAL_OFFSET)
#define CPTRA_FW_ERROR_NON_FATAL    CALIPTRA_REG(CPTRA_FW_ERROR_NON_FATAL_OFFSET)
#define CPTRA_HW_ERROR_ENC          CALIPTRA_REG(CPTRA_HW_ERROR_ENC_OFFSET)
#define CPTRA_FW_ERROR_ENC          CALIPTRA_REG(CPTRA_FW_ERROR_ENC_OFFSET)
#define CPTRA_BOOT_STATUS           CALIPTRA_REG(CPTRA_BOOT_STATUS_OFFSET)
#define CPTRA_FLOW_STATUS           CALIPTRA_REG(CPTRA_FLOW_STATUS_OFFSET)
#define CPTRA_RESET_REASON          CALIPTRA_REG(CPTRA_RESET_REASON_OFFSET)
#define CPTRA_SECURITY_STATE_REG    CALIPTRA_REG(CPTRA_SECURITY_STATE_OFFSET)
#define CPTRA_FUSE_WR_DONE          CALIPTRA_REG(CPTRA_FUSE_WR_DONE_OFFSET)
#define CPTRA_TIMER_CONFIG          CALIPTRA_REG(CPTRA_TIMER_CONFIG_OFFSET)
#define CPTRA_BOOTFSM_GO            CALIPTRA_REG(CPTRA_BOOTFSM_GO_OFFSET)
#define CPTRA_DBG_MANUF_SERVICE_REG CALIPTRA_REG(CPTRA_DBG_MANUF_SERVICE_REG_OFFSET)
#define CPTRA_GENERIC_INPUT_WIRES   CALIPTRA_REG(CPTRA_GENERIC_INPUT_WIRES_OFFSET)
#define CPTRA_GENERIC_OUTPUT_WIRES  CALIPTRA_REG(CPTRA_GENERIC_OUTPUT_WIRES_OFFSET)
#define MBOX_LOCK                   CALIPTRA_REG(MBOX_LOCK_OFFSET)
#define MBOX_CMD                    CALIPTRA_REG(MBOX_CMD_OFFSET)
#define MBOX_DLEN                   CALIPTRA_REG(MBOX_DLEN_OFFSET)
#define MBOX_DATAIN                 CALIPTRA_REG(MBOX_DATAIN_OFFSET)
#define MBOX_DATAOUT                CALIPTRA_REG(MBOX_DATAOUT_OFFSET)
#define MBOX_EXECUTE                CALIPTRA_REG(MBOX_EXECUTE_OFFSET)
#define MBOX_STATUS_REG             CALIPTRA_REG(MBOX_STATUS_OFFSET)

#endif /* CALIPTRA_REGS_H */
