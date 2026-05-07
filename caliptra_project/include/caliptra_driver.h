#ifndef CALIPTRA_DRIVER_H
#define CALIPTRA_DRIVER_H

/*
 * Caliptra 2.x SoC 드라이버 인터페이스
 *
 * 이 헤더는 SoC 펌웨어에서 Caliptra와 통신하기 위한
 * 플랫폼 독립적 드라이버 인터페이스를 정의합니다.
 *
 * 사용법:
 *   1. caliptra_hw_ops_t를 플랫폼에 맞게 구현
 *   2. caliptra_driver_init()으로 드라이버 초기화
 *   3. 부트 플로우에 따라 API 함수 호출
 */

#include "caliptra_types.h"
#include "caliptra_mbox.h"

/* ---------------------------------------------------------------------------
 * 하드웨어 추상화 레이어 (HAL)
 * SoC별로 구현해야 하는 콜백 함수들
 * --------------------------------------------------------------------------- */
typedef struct {
    /* 레지스터 접근 */
    uint32_t (*reg_read)(uint32_t offset);
    void     (*reg_write)(uint32_t offset, uint32_t value);

    /* 신호 상태 읽기 */
    bool     (*is_ready_for_fuse)(void);
    bool     (*is_ready_for_fw)(void);
    bool     (*is_ready_for_rtflows)(void);
    bool     (*is_error_fatal)(void);
    bool     (*is_error_non_fatal)(void);

    /* 딜레이 (바쁜 대기) */
    void     (*delay_us)(uint32_t microseconds);

    /* 로깅 (NULL이면 비활성화) */
    void     (*log)(const char *fmt, ...);
} caliptra_hw_ops_t;

/* ---------------------------------------------------------------------------
 * 드라이버 컨텍스트
 * --------------------------------------------------------------------------- */
typedef struct {
    const caliptra_hw_ops_t *ops;
    uint32_t                 mbox_timeout_us;  /* 메일박스 폴링 타임아웃 */
    bool                     initialized;
} caliptra_ctx_t;

/* ---------------------------------------------------------------------------
 * 초기화
 * --------------------------------------------------------------------------- */

/*
 * caliptra_driver_init - 드라이버 초기화
 * @ctx: 드라이버 컨텍스트 (caller가 할당)
 * @ops: 플랫폼별 HW 연산 구현체
 * @mbox_timeout_us: 메일박스 응답 대기 타임아웃 (0=무한)
 */
caliptra_status_t caliptra_driver_init(caliptra_ctx_t *ctx,
                                        const caliptra_hw_ops_t *ops,
                                        uint32_t mbox_timeout_us);

/* ---------------------------------------------------------------------------
 * 부트 플로우 API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_wait_for_fuse_ready - ready_for_fuse 신호 대기
 * Fuse 레지스터 기록 전 반드시 호출
 */
caliptra_status_t caliptra_wait_for_fuse_ready(caliptra_ctx_t *ctx);

/*
 * caliptra_program_fuses - Fuse 레지스터 일괄 기록 후 FUSE_WR_DONE 설정
 * @fuse: 기록할 Fuse 구성 데이터
 */
caliptra_status_t caliptra_program_fuses(caliptra_ctx_t *ctx,
                                          const caliptra_fuse_t *fuse);

/*
 * caliptra_wait_for_fw_ready - ready_for_fw 신호 대기 (Passive 모드)
 */
caliptra_status_t caliptra_wait_for_fw_ready(caliptra_ctx_t *ctx);

/*
 * caliptra_load_firmware - Caliptra FW 이미지를 메일박스로 전송
 * @fw_image: FW 바이너리 포인터
 * @fw_size:  FW 바이너리 크기 (바이트)
 */
caliptra_status_t caliptra_load_firmware(caliptra_ctx_t *ctx,
                                          const void *fw_image,
                                          uint32_t fw_size);

/*
 * caliptra_wait_for_rt_ready - ready_for_rtflows 신호 대기
 * 이 함수 반환 후 Runtime 커맨드 사용 가능
 */
caliptra_status_t caliptra_wait_for_rt_ready(caliptra_ctx_t *ctx);

/* ---------------------------------------------------------------------------
 * 저수준 메일박스 API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_mbox_send - 메일박스 커맨드 전송 및 응답 수신 (8단계 프로토콜)
 * @cmd: 커맨드 디스크립터
 */
caliptra_status_t caliptra_mbox_send(caliptra_ctx_t *ctx,
                                      caliptra_mbox_cmd_t *cmd);

/* ---------------------------------------------------------------------------
 * 측정값 API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_stash_measurement - SoC 측정값 stash
 * 최대 8개까지 가능. ROM 및 Runtime 단계 모두 지원.
 * @req: 측정 요청 구조체
 */
caliptra_status_t caliptra_stash_measurement(
    caliptra_ctx_t *ctx,
    const caliptra_stash_measurement_req_t *req);

/*
 * caliptra_extend_pcr - PCR 확장 (Runtime 전용, PCR4~30)
 * @pcr_idx:     확장할 PCR 인덱스 (CALIPTRA_PCR_SOC_BASE ~ CALIPTRA_PCR_SOC_MAX)
 * @measurement: SHA384 해시 값 (48바이트)
 */
caliptra_status_t caliptra_extend_pcr(caliptra_ctx_t *ctx,
                                       uint32_t pcr_idx,
                                       const uint8_t *measurement);

/*
 * caliptra_get_pcr_quote - PCR Quote 생성 (서명된 증명)
 * @nonce:      신선도 논스 (32바이트)
 * @quote_buf:  응답 버퍼
 * @quote_size: 버퍼 크기 입력, 실제 크기 출력
 */
caliptra_status_t caliptra_get_pcr_quote(caliptra_ctx_t *ctx,
                                          const uint8_t *nonce,
                                          uint8_t *quote_buf,
                                          uint32_t *quote_size);

/* ---------------------------------------------------------------------------
 * 인증서 API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_get_idevid_cert - IDevID 인증서 획득
 * @cert_buf:  인증서 버퍼
 * @cert_size: 버퍼 크기 입력, 실제 크기 출력
 */
caliptra_status_t caliptra_get_idevid_cert(caliptra_ctx_t *ctx,
                                             uint8_t *cert_buf,
                                             uint32_t *cert_size);

/*
 * caliptra_get_ldevid_cert - LDevID 인증서 획득
 */
caliptra_status_t caliptra_get_ldevid_cert(caliptra_ctx_t *ctx,
                                             uint8_t *cert_buf,
                                             uint32_t *cert_size);

/*
 * caliptra_get_fmc_alias_cert - FMC Alias 인증서 획득
 */
caliptra_status_t caliptra_get_fmc_alias_cert(caliptra_ctx_t *ctx,
                                               uint8_t *cert_buf,
                                               uint32_t *cert_size);

/*
 * caliptra_get_rt_alias_cert - Runtime Alias 인증서 획득
 */
caliptra_status_t caliptra_get_rt_alias_cert(caliptra_ctx_t *ctx,
                                              uint8_t *cert_buf,
                                              uint32_t *cert_size);

/* ---------------------------------------------------------------------------
 * DPE API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_invoke_dpe - DPE 커맨드 전달 (INVOKE_DPE_COMMAND 래퍼)
 * @dpe_cmd:      DPE 직렬화된 요청 데이터
 * @dpe_cmd_size: 요청 크기 (바이트)
 * @dpe_resp:     응답 버퍼
 * @dpe_resp_size: 버퍼 크기 입력, 실제 크기 출력
 */
caliptra_status_t caliptra_invoke_dpe(caliptra_ctx_t *ctx,
                                       const uint8_t *dpe_cmd,
                                       uint32_t dpe_cmd_size,
                                       uint8_t *dpe_resp,
                                       uint32_t *dpe_resp_size);

/* ---------------------------------------------------------------------------
 * 암호화 서비스 API (2.0+)
 * --------------------------------------------------------------------------- */

/*
 * caliptra_crypto_sign - 해시값에 대한 ECDSA/ML-DSA 서명
 * @key_handle: 서명 키 핸들
 * @digest:     서명할 SHA384 해시 (48바이트)
 * @resp:       서명 응답 구조체
 */
caliptra_status_t caliptra_crypto_sign(caliptra_ctx_t *ctx,
                                        const caliptra_key_handle_t *key_handle,
                                        const uint8_t *digest,
                                        uint32_t flags,
                                        caliptra_crypto_sign_resp_t *resp);

/*
 * caliptra_crypto_rng - 암호학적 난수 생성
 * @length:  요청 크기 (최대 256바이트)
 * @out_buf: 출력 버퍼
 */
caliptra_status_t caliptra_crypto_rng(caliptra_ctx_t *ctx,
                                       uint32_t length,
                                       uint8_t *out_buf);

/* ---------------------------------------------------------------------------
 * Authorization Manifest API (1.2+)
 * --------------------------------------------------------------------------- */

/*
 * caliptra_set_auth_manifest - SoC Authorization Manifest 설정
 * @manifest:      매니페스트 데이터
 * @manifest_size: 매니페스트 크기
 */
caliptra_status_t caliptra_set_auth_manifest(caliptra_ctx_t *ctx,
                                              const void *manifest,
                                              uint32_t manifest_size);

/*
 * caliptra_authorize_and_stash - 이미지 인증 및 측정값 stash
 */
caliptra_status_t caliptra_authorize_and_stash(
    caliptra_ctx_t *ctx,
    const caliptra_authorize_and_stash_req_t *req,
    caliptra_authorize_and_stash_resp_t *resp);

/* ---------------------------------------------------------------------------
 * 오류 처리 API
 * --------------------------------------------------------------------------- */

/*
 * caliptra_handle_fatal_error - Fatal 오류 처리 (로깅 + 리셋 준비)
 * 실제 리셋은 SoC 플랫폼 코드에서 수행 (cptra_rst_b 어설션)
 */
void caliptra_handle_fatal_error(caliptra_ctx_t *ctx);

/*
 * caliptra_handle_non_fatal_error - Non-fatal 오류 처리 및 클리어
 */
void caliptra_handle_non_fatal_error(caliptra_ctx_t *ctx);

/* ---------------------------------------------------------------------------
 * 유틸리티
 * --------------------------------------------------------------------------- */

/*
 * caliptra_get_version - Runtime FW 버전 조회
 */
caliptra_status_t caliptra_get_version(caliptra_ctx_t *ctx,
                                        uint32_t *version_out);

/*
 * caliptra_fips_self_test - FIPS 자체 테스트 실행
 */
caliptra_status_t caliptra_fips_self_test(caliptra_ctx_t *ctx);

#endif /* CALIPTRA_DRIVER_H */
