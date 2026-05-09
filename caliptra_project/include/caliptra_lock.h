// Licensed under the Apache-2.0 license
#pragma once

/*
 * OCP L.O.C.K. v1.0 SoC-side API
 *
 * 실제 Caliptra Runtime FW가 구현하는 OCP LOCK 메일박스 커맨드 래퍼입니다.
 * 모든 함수는 caliptra_mailbox_execute()를 통해 Caliptra FW에 요청을 전달합니다.
 *
 * ─────────────────────────────────────────────────────────────────────
 * OCP L.O.C.K. 개요
 * ─────────────────────────────────────────────────────────────────────
 *
 * OCP L.O.C.K.은 SSD MEK(Media Encryption Key) 보안 전달 프로토콜입니다.
 * Caliptra가 MEK를 생성/파생/봉인하고, 암호화된 형태로만 SSD에 전달합니다.
 * SoC FW는 MEK plaintext를 절대 접근하지 않습니다.
 *
 * 키 계층:
 *   HEK (Host Encryption Key)  — Caliptra 내부 퓨즈에서 파생, FW 비가시
 *     └─ MDK (MEK Derivation Key) — HEK + drive_serial로 파생
 *          └─ MEK (Media Encryption Key) — MDK + namespace/LBA로 파생
 *
 * HPKE 알고리즘 지원:
 *   - ECDH-P384 + HKDF-SHA384 + AES-256-GCM
 *   - ML-KEM-1024 + HKDF-SHA384 + AES-256-GCM (양자 내성)
 *   - 하이브리드 (ECDH + ML-KEM, 양자 내성 + 고전 보안)
 *
 * ─────────────────────────────────────────────────────────────────────
 * 일반적인 MEK 전달 시퀀스
 * ─────────────────────────────────────────────────────────────────────
 *
 * 방법 A: GENERATE_MEK (새 MEK 생성)
 *   1. caliptra_lock_get_hpke_pub_key()     — Caliptra HPKE 공개키 획득
 *   2. caliptra_lock_generate_mek()          — 새 MEK 생성 → WrappedKey
 *   3. caliptra_lock_generate_mpk()          — MPK 생성 (Customer AK 포함)
 *   4. caliptra_lock_enable_mpk()            — MPK 활성화
 *   5. caliptra_lock_load_mek()              — 암호화 엔진에 MEK 로드
 *
 * 방법 B: DERIVE_MEK (기존 HEK에서 파생)
 *   1. caliptra_lock_initialize_mek_secret() — MEK 파생 세션 초기화
 *   2. (선택) caliptra_lock_mix_mpk()        — Customer MPK 혼합
 *   3. caliptra_lock_derive_mek()            — MEK 파생
 *   4. caliptra_lock_load_mek()              — 암호화 엔진에 MEK 로드
 *
 * ─────────────────────────────────────────────────────────────────────
 * 빌드 요구사항
 * ─────────────────────────────────────────────────────────────────────
 *
 * Include 경로:
 *   -I caliptra-sw/libcaliptra/inc
 *   -I caliptra_project/include
 *
 * Link:
 *   caliptra-sw/libcaliptra/src/caliptra_api.c
 *   caliptra_project/src/caliptra_driver.c  (HAL 구현)
 *   caliptra_project/src/caliptra_lock.c    (이 헤더의 구현)
 */

#include <stdint.h>
#include <stdbool.h>
#include "caliptra_lock_types.h"

/* caliptra_api.h의 caliptra_mailbox_execute 선언 */
#include "caliptra_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 1: REPORT_HEK_METADATA
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_report_hek_metadata
 *
 * HEK 메타데이터 조회. HEK 가용 여부, 슬롯 수 등을 반환합니다.
 *
 * @req:   요청 구조체 (reserved 필드, total/active slot 힌트)
 * @resp:  응답 구조체
 * @async: true이면 비동기 (caliptra_test_for_completion/caliptra_complete 필요)
 *
 * 반환값: 0=성공, libcaliptra_error 열거형 참조
 */
int caliptra_lock_report_hek_metadata(
    const ocp_lock_report_hek_metadata_req_t *req,
    ocp_lock_report_hek_metadata_resp_t      *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 2: GET_ALGORITHMS
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_get_algorithms
 *
 * 지원 HPKE 알고리즘 및 Access Key 크기 쿼리.
 * MEK 전달 세션 설정 전 반드시 호출하여 지원 알고리즘을 확인하세요.
 */
int caliptra_lock_get_algorithms(
    ocp_lock_get_algorithms_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 3: INITIALIZE_MEK_SECRET
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_initialize_mek_secret
 *
 * MEK 파생 세션 초기화 (DERIVE_MEK 방법 전 필수).
 *
 * @sek: Session Establishment Key (32바이트)
 * @dpk: Drive Private Key (32바이트)
 */
int caliptra_lock_initialize_mek_secret(
    const uint8_t sek[32],
    const uint8_t dpk[32],
    ocp_lock_initialize_mek_secret_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 4: MIX_MPK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_mix_mpk
 *
 * Customer MPK를 MEK 파생에 혼합.
 * INITIALIZE_MEK_SECRET 이후, DERIVE_MEK 이전에 호출합니다.
 *
 * @enabled_mpk: ENABLE_MPK 결과로 얻은 Enabled MPK
 */
int caliptra_lock_mix_mpk(
    const ocp_lock_wrapped_key_t *enabled_mpk,
    ocp_lock_mix_mpk_resp_t      *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 5: DERIVE_MEK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_derive_mek
 *
 * MEK 파생. INITIALIZE_MEK_SECRET 이후 호출합니다.
 *
 * @mek_checksum:  MEK 무결성 검증 값 (16바이트)
 * @metadata:      암호화 엔진 메타데이터 (20바이트)
 * @aux_metadata:  보조 메타데이터 (32바이트)
 * @cmd_timeout:   타임아웃 (밀리초)
 */
int caliptra_lock_derive_mek(
    const uint8_t mek_checksum[16],
    const uint8_t metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    const uint8_t aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE],
    uint32_t cmd_timeout,
    ocp_lock_derive_mek_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 6: ENUMERATE_HPKE_HANDLES
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_enumerate_hpke_handles
 *
 * 사용 가능한 HPKE 핸들 목록 조회.
 * GET_HPKE_PUB_KEY 호출 전 핸들 번호 확인에 사용합니다.
 */
int caliptra_lock_enumerate_hpke_handles(
    ocp_lock_enumerate_hpke_handles_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 7: ROTATE_HPKE_KEY
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_rotate_hpke_key
 *
 * HPKE 키 교체. 새 핸들 번호를 반환합니다.
 * 정기적인 키 롤오버 또는 보안 이벤트 발생 시 호출합니다.
 *
 * @hpke_handle: 교체할 HPKE 핸들
 */
int caliptra_lock_rotate_hpke_key(
    uint32_t hpke_handle,
    ocp_lock_rotate_hpke_key_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 8: GENERATE_MEK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_generate_mek
 *
 * 새 MEK를 생성합니다.
 * 반환된 wrapped_mek는 LOAD_MEK, GENERATE_MPK, REWRAP_MPK에 사용합니다.
 * MEK plaintext는 SoC FW에 절대 노출되지 않습니다.
 */
int caliptra_lock_generate_mek(
    ocp_lock_generate_mek_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 9: GET_HPKE_PUB_KEY
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_get_hpke_pub_key
 *
 * 지정한 HPKE 핸들의 공개키 획득.
 * SoC는 이 공개키를 SSD에 전달하여 HPKE 세션 설정에 사용합니다.
 *
 * @hpke_handle: 공개키를 요청할 HPKE 핸들
 */
int caliptra_lock_get_hpke_pub_key(
    uint32_t hpke_handle,
    ocp_lock_get_hpke_pub_key_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 10: GENERATE_MPK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_generate_mpk
 *
 * MPK(Managed Platform Key) 생성.
 * Customer가 제공한 Access Key(SealedAccessKey)로 MEK를 봉인합니다.
 *
 * @sek:               Session Establishment Key (32바이트)
 * @metadata:          WrappedKey 메타데이터
 * @metadata_len:      메타데이터 크기
 * @sealed_access_key: HPKE로 봉인된 Customer Access Key
 */
int caliptra_lock_generate_mpk(
    const uint8_t                       sek[32],
    const uint8_t                      *metadata,
    uint32_t                            metadata_len,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_generate_mpk_resp_t       *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 11: REWRAP_MPK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_rewrap_mpk
 *
 * MPK 재봉인 — 기존 MPK를 새 Access Key로 교체합니다.
 * Customer Access Key 변경(키 로테이션) 시 사용합니다.
 */
int caliptra_lock_rewrap_mpk(
    const uint8_t                       sek[32],
    const ocp_lock_wrapped_key_t       *current_locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const uint8_t                       new_ak_ciphertext[48],
    ocp_lock_rewrap_mpk_resp_t         *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 12: ENABLE_MPK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_enable_mpk
 *
 * Locked MPK를 Enabled MPK로 전환합니다.
 * Access Key를 검증하고 MEK 접근을 활성화합니다.
 * Enabled MPK는 MIX_MPK의 입력으로 사용됩니다.
 */
int caliptra_lock_enable_mpk(
    const uint8_t                       sek[32],
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    const ocp_lock_wrapped_key_t       *locked_mpk,
    ocp_lock_enable_mpk_resp_t         *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 13: TEST_ACCESS_KEY
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_test_access_key
 *
 * Access Key 검증. SHA2-384 다이제스트로 Access Key 유효성을 확인합니다.
 * MPK 활성화 전 Access Key 유효성을 사전 검증할 때 사용합니다.
 *
 * @nonce: 신선도 논스 (32바이트, 재전송 공격 방지)
 */
int caliptra_lock_test_access_key(
    const uint8_t                       sek[32],
    const uint8_t                       nonce[32],
    const ocp_lock_wrapped_key_t       *locked_mpk,
    const ocp_lock_sealed_access_key_t *sealed_access_key,
    ocp_lock_test_access_key_resp_t    *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 14: GET_STATUS
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_get_status
 *
 * OCP LOCK 상태 레지스터 조회.
 * 디버깅 및 상태 모니터링에 사용합니다.
 */
int caliptra_lock_get_status(
    ocp_lock_get_status_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 15: CLEAR_KEY_CACHE
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_clear_key_cache
 *
 * 키 캐시 무효화. 보안 이벤트 또는 슬립 전 캐시를 초기화합니다.
 *
 * @cmd_timeout: 타임아웃 (밀리초)
 */
int caliptra_lock_clear_key_cache(
    uint32_t cmd_timeout,
    ocp_lock_clear_key_cache_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 16: UNLOAD_MEK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_unload_mek
 *
 * 암호화 엔진에서 MEK 제거. 드라이브 잠금 또는 슬립 시 호출합니다.
 *
 * @metadata:    암호화 엔진 메타데이터 (20바이트)
 * @cmd_timeout: 타임아웃 (밀리초)
 */
int caliptra_lock_unload_mek(
    const uint8_t metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    uint32_t cmd_timeout,
    ocp_lock_unload_mek_resp_t *resp,
    bool async);

/* ─────────────────────────────────────────────────────────────────────
 * 커맨드 17: LOAD_MEK
 * ───────────────────────────────────────────────────────────────────── */

/*
 * caliptra_lock_load_mek
 *
 * 암호화 엔진에 MEK 로드. WrappedKey를 언래핑하여 MEK를 SSD 컨트롤러에 전달합니다.
 * MEK plaintext는 Caliptra 내부에서만 처리되며 SoC FW에 노출되지 않습니다.
 *
 * @metadata:     암호화 엔진 메타데이터 (20바이트)
 * @aux_metadata: 보조 메타데이터 (32바이트)
 * @wrapped_mek:  GENERATE_MEK 또는 DERIVE_MEK로 획득한 WrappedKey
 * @cmd_timeout:  타임아웃 (밀리초)
 */
int caliptra_lock_load_mek(
    const uint8_t                  metadata[OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE],
    const uint8_t                  aux_metadata[OCP_LOCK_ENCRYPTION_ENGINE_AUX_SIZE],
    const ocp_lock_wrapped_key_t  *wrapped_mek,
    uint32_t cmd_timeout,
    ocp_lock_load_mek_resp_t      *resp,
    bool async);

#ifdef __cplusplus
}
#endif
