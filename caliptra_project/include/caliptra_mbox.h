// Licensed under the Apache-2.0 license
#pragma once

/*
 * 이 헤더는 libcaliptra 내부 파일입니다. 직접 include하지 마세요.
 *
 * 메일박스 커맨드 코드(enum mailbox_command)는
 *   caliptra-sw/libcaliptra/src/caliptra_mbox.h (internal)
 * 에 정의되어 있으며, caliptra_api.c가 내부적으로 사용합니다.
 *
 * SoC 코드에서 직접 메일박스 커맨드를 사용하려면:
 *   caliptra_mailbox_execute(cmd, &tx_buf, &rx_buf, async)
 * 커맨드 코드는 caliptra-sw/api/src/mailbox.rs의 CommandId 참조.
 *
 * OCP LOCK 커맨드 코드는 include/caliptra_lock_types.h를 사용하세요.
 */

#error "caliptra_mbox.h는 libcaliptra 내부 헤더입니다. include/caliptra_lock_types.h 또는 caliptra_api.h를 사용하세요."
