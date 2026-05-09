// Licensed under the Apache-2.0 license

/*
 * Caliptra Platform HAL 구현 템플릿
 *
 * 이 파일은 libcaliptra가 요구하는 3개 HAL 함수의 구현 템플릿입니다.
 * 실제 SoC 플랫폼에 맞게 수정하세요.
 *
 * libcaliptra가 요구하는 인터페이스: caliptra-sw/libcaliptra/inc/caliptra_if.h
 *
 * Caliptra 레지스터 주소 계산:
 *   libcaliptra가 전달하는 address =
 *     EXTERNAL_PERIPH_BASE (0x30000000) + REG_BLOCK_OFFSET + field_offset
 *
 * 플랫폼에 따라 두 가지 패턴:
 *   A) address를 APB 물리 주소로 직접 사용 (시뮬레이션/FPGA)
 *   B) (address - 0x30000000) 오프셋을 플랫폼 실제 APB 베이스에 더함 (실 SoC)
 */

#include <stdint.h>
#include <stdbool.h>

static uintptr_t g_apb_base = 0;

int caliptra_platform_init(uintptr_t apb_base_addr)
{
    g_apb_base = apb_base_addr;
    return 0;
}

/**
 * caliptra_write_u32 — Caliptra APB 레지스터 쓰기
 *
 * libcaliptra 내부에서 호출. address =
 *   0x30000000 + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR + field_offset (메일박스 계열)
 *   0x30000000 + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR + field_offset (Fuse 계열)
 */
int caliptra_write_u32(uint32_t address, uint32_t data)
{
    /* TODO: 플랫폼에 맞게 구현
     *
     * 예시 A — 직접 메모리 매핑 (FPGA/베어메탈):
     *   volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)address;
     *   *reg = data;
     *   return 0;
     *
     * 예시 B — 오프셋 계산 (실 SoC APB):
     *   uint32_t offset = address - 0x30000000U;
     *   volatile uint32_t *reg = (volatile uint32_t *)(g_apb_base + offset);
     *   *reg = data;
     *   return 0;
     *
     * 예시 C — APB 버스 드라이버 호출:
     *   return platform_apb_write32(address, data);
     */
    (void)address;
    (void)data;
    return -1; /* 구현 필요 */
}

/**
 * caliptra_read_u32 — Caliptra APB 레지스터 읽기
 */
int caliptra_read_u32(uint32_t address, uint32_t *data)
{
    if (!data) return -1;

    /* TODO: 플랫폼에 맞게 구현
     *
     * 예시 A — 직접 메모리 매핑:
     *   volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)address;
     *   *data = *reg;
     *   return 0;
     *
     * 예시 B — 오프셋 계산:
     *   uint32_t offset = address - 0x30000000U;
     *   volatile uint32_t *reg = (volatile uint32_t *)(g_apb_base + offset);
     *   *data = *reg;
     *   return 0;
     */
    (void)address;
    *data = 0;
    return -1; /* 구현 필요 */
}

/**
 * caliptra_wait — Caliptra 응답 대기
 *
 * libcaliptra는 메일박스 BUSY 상태일 때 이 함수를 루프로 호출합니다.
 *
 * 시뮬레이션 환경: HW 모델 클럭을 한 사이클 진행
 * 실 SoC 환경: CPU NOP 사이클 또는 yield
 */
void caliptra_wait(void)
{
    /* TODO: 플랫폼에 맞게 구현
     *
     * 예시 — FPGA/시뮬레이션 (hwmodel):
     *   caliptra_model_step(model);
     *
     * 예시 — 실 SoC 바쁜 대기:
     *   for (volatile int i = 0; i < 100; i++) { __asm__ volatile("nop"); }
     *
     * 예시 — RTOS 환경:
     *   vTaskDelay(pdMS_TO_TICKS(1));
     */
}
