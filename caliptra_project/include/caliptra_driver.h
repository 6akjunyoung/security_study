// Licensed under the Apache-2.0 license
#pragma once

/*
 * Caliptra Platform HAL — SoC 플랫폼이 구현해야 하는 인터페이스
 *
 * 실제 Caliptra SoC-side 라이브러리(libcaliptra)는 caliptra-sw 서브모듈에 있습니다:
 *   caliptra-sw/libcaliptra/inc/caliptra_api.h   ← Caliptra 모든 명령 API
 *   caliptra-sw/libcaliptra/inc/caliptra_types.h ← 요청/응답 구조체
 *   caliptra-sw/libcaliptra/inc/caliptra_if.h    ← 플랫폼이 구현할 HAL (3개 함수)
 *   caliptra-sw/libcaliptra/inc/caliptra_enums.h ← 에러 코드, 열거형
 *
 * 빌드 시스템 include 경로:
 *   -I caliptra-sw/libcaliptra/inc
 *   -I caliptra-sw/registers/generated-src  (레지스터 헤더)
 *
 * ─────────────────────────────────────────────────────────────────────
 * 플랫폼 HAL 구현 방법
 * ─────────────────────────────────────────────────────────────────────
 *
 * libcaliptra는 세 가지 함수만 플랫폼에 요구합니다 (caliptra_if.h 정의):
 *
 *   int  caliptra_write_u32(uint32_t address, uint32_t data);
 *   int  caliptra_read_u32(uint32_t address, uint32_t *data);
 *   void caliptra_wait(void);
 *
 * 이 세 함수를 src/caliptra_driver.c (이 파일의 구현부)에서 제공합니다.
 * Caliptra 레지스터 베이스 주소: 0x30000000 + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR
 *
 * ─────────────────────────────────────────────────────────────────────
 * 일반적인 부팅 시퀀스 (caliptra_api.h 함수 사용)
 * ─────────────────────────────────────────────────────────────────────
 *
 *   1. caliptra_mbox_pauser_set_and_lock(pauser_id)  // AXI PAUSER 설정 (선택)
 *   2. caliptra_ready_for_fuses()                     // Fuse 준비 확인
 *   3. caliptra_init_fuses(&fuses)                    // Fuse 프로그래밍
 *   4. caliptra_bootfsm_go()                          // BootFSM 시작
 *   5. caliptra_ready_for_firmware()                  // FW 업로드 준비 대기
 *   6. caliptra_upload_fw(&fw_buffer, false)          // FW 업로드
 *   7. caliptra_ready_for_runtime()                   // Runtime 준비 대기
 *      (이후 caliptra_api.h의 Runtime 커맨드 사용 가능)
 *
 * WARNING: Fuse 프로그래밍은 HW 상태 머신으로 해야 합니다.
 *          caliptra_init_fuses()는 시뮬레이션 전용입니다.
 *          실 제품에서는 SoC FW가 직접 Fuse 레지스터에 접근하지 않습니다.
 */

#include <stdint.h>
#include <stdbool.h>

/* caliptra_if.h의 3개 HAL 함수 선언
 * (실제 정의는 caliptra-sw/libcaliptra/inc/caliptra_if.h에 있음) */
int  caliptra_write_u32(uint32_t address, uint32_t data);
int  caliptra_read_u32(uint32_t address, uint32_t *data);
void caliptra_wait(void);

/* 플랫폼 초기화 (선택 — SoC별로 필요하면 사용)
 * APB 버스 베이스 주소, 클럭, 인터럽트 등 플랫폼 자원 초기화 */
int caliptra_platform_init(uintptr_t apb_base_addr);
