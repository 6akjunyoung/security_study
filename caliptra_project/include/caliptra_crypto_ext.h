// Licensed under the Apache-2.0 license
#pragma once

/*
 * 이 헤더는 더 이상 존재하지 않습니다.
 *
 * 이전에 정의한 "crypto extension" 커맨드들은
 * 실제 libcaliptra/caliptra-sw에 존재하지 않는 잘못된 커맨드였습니다.
 *
 * Caliptra가 실제로 제공하는 암호 관련 커맨드:
 *
 *   서명 검증:
 *     caliptra_ecdsa384_verify()    — ECDSA-384 서명 검증
 *     caliptra_mldsa87_verify()     — ML-DSA-87 서명 검증
 *     caliptra_lms_verify()         — LMS 서명 검증
 *
 *   DPE (Device Policy Engine, 키 파생/인증서):
 *     caliptra_invoke_dpe_command()         — ECC384 DPE 커맨드
 *     caliptra_invoke_dpe_mldsa87_command() — MLDSA87 DPE 커맨드
 *
 *   Exported ECDSA (DPE exported CDI):
 *     caliptra_sign_with_exported_ecdsa()
 *     caliptra_revoke_exported_cdi_handle()
 *
 *   OCP L.O.C.K. (MEK 키 관리):
 *     include/caliptra_lock.h 참조
 *
 * 모든 API는 caliptra-sw/libcaliptra/inc/caliptra_api.h에 있습니다.
 */

#error "caliptra_crypto_ext.h는 deprecated입니다. caliptra_api.h 또는 caliptra_lock.h를 사용하세요."
