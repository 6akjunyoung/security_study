# Caliptra 2.x SoC Driver — API 전체 개요

> **관련 파일**
> - `include/caliptra_driver.h` — 부트/초기화/측정/인증서/DPE/암호화/오류 API
> - `include/caliptra_crypto_ext.h` — 확장 암호화 서비스 (Hash/HMAC/HKDF/AES-GCM/ECDH/ML-KEM)
> - `include/caliptra_lock.h` — OCP L.O.C.K. MEK 전달 API
> - `include/caliptra_types.h` — 공통 타입 및 상수

이 페이지는 Caliptra 2.x SoC 드라이버의 **모든 공개 API**를 카테고리별로 정리한 마스터 치트시트입니다.

---

## Key Vault (KV) 모델

> **중요**: Caliptra의 모든 암호 키는 Caliptra 내부 **Key Vault(KV)** 에 저장됩니다.
> SoC FW는 원시(raw) 키 값을 직접 볼 수 없으며, 항상 **불투명 핸들(`caliptra_key_handle_t`)** 로만 키를 참조합니다.
> 이 설계는 키가 메모리에 노출되는 것을 방지하는 Caliptra의 핵심 보안 속성입니다.

---

## 1. Boot / Init — [`api_boot.md`](api_boot.md)

`include/caliptra_driver.h`

| 함수 | 호출 시점 | 설명 |
|---|---|---|
| `caliptra_driver_init(ctx, ops, timeout)` | 어떤 것보다 먼저 | 드라이버 초기화, HAL ops 연결 |
| `caliptra_wait_for_fuse_ready(ctx)` | 리셋 후 | `FLOW_STATUS.ready_for_fuse` 대기 |
| `caliptra_program_fuses(ctx, fuse)` | Fuse ready 후 | 모든 Fuse 레지스터 기록 + `WR_DONE` |
| `caliptra_wait_for_fw_ready(ctx)` | Fuse done 후 | `ready_for_fw` 대기 |
| `caliptra_load_firmware(ctx, fw, size)` | FW ready 후 | FW 이미지 메일박스 로드 |
| `caliptra_wait_for_rt_ready(ctx)` | FW load 후 | `ready_for_rtflows` 대기 |

---

## 2. Mailbox (저수준) — [`api_boot.md`](api_boot.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_mbox_send(ctx, cmd)` | 8단계 프로토콜 직접 실행 |

---

## 3. Measurement / PCR — [`api_measurement.md`](api_measurement.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_stash_measurement(ctx, req)` | 측정값 stash (최대 8개) |
| `caliptra_extend_pcr(ctx, idx, meas)` | PCR4~30 확장 (Runtime) |
| `caliptra_get_pcr_quote(ctx, nonce, buf, size)` | 서명된 PCR Quote 획득 |

---

## 4. Certificate / Identity — [`api_attestation.md`](api_attestation.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_get_idevid_cert(ctx, buf, size)` | IDevID 인증서 |
| `caliptra_get_ldevid_cert(ctx, buf, size)` | LDevID 인증서 |
| `caliptra_get_fmc_alias_cert(ctx, buf, size)` | FMC Alias 인증서 |
| `caliptra_get_rt_alias_cert(ctx, buf, size)` | RT Alias 인증서 |

---

## 5. DPE — [`api_attestation.md`](api_attestation.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_invoke_dpe(ctx, cmd, csz, resp, rsz)` | DICE Protection Environment 커맨드 |

---

## 6. Authorization Manifest — [`api_auth.md`](api_auth.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_set_auth_manifest(ctx, data, size)` | Authorization Manifest 설정 |
| `caliptra_authorize_and_stash(ctx, req, resp)` | 이미지 인증 + 측정값 stash |

---

## 7. Crypto (기본) — [`api_crypto.md`](api_crypto.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_crypto_sign(ctx, key, digest, flags, resp)` | ECDSA / ML-DSA 서명 |
| `caliptra_crypto_rng(ctx, len, buf)` | TRNG 난수 생성 |

---

## 8. Extended Crypto — [`api_crypto.md`](api_crypto.md)

`include/caliptra_crypto_ext.h`

| 함수 | 설명 |
|---|---|
| `caliptra_crypto_hash(ctx, alg, data, dlen, out, olen)` | SHA-384/512 |
| `caliptra_crypto_hmac(ctx, key, data, dlen, out)` | HMAC-SHA384 |
| `caliptra_crypto_hkdf(ctx, ikm, salt, slen, info, ilen, okm_len, out)` | HKDF-SHA384 → KV 핸들 |
| `caliptra_crypto_aes_gcm_encrypt(ctx, key, iv, aad, alen, pt, plen, ct, clen, tag)` | AES-256-GCM 암호화 |
| `caliptra_crypto_aes_gcm_decrypt(ctx, key, iv, aad, alen, ct, clen, tag, pt, plen)` | AES-256-GCM 복호화 |
| `caliptra_crypto_ecdh_key_agree(ctx, priv, peer, out)` | ECDH P-384 키 합의 |
| `caliptra_crypto_ml_kem_encap(ctx, pub, ct, out)` | ML-KEM-1024 캡슐화 |
| `caliptra_crypto_ml_kem_decap(ctx, priv, ct, out)` | ML-KEM-1024 역캡슐화 |
| `caliptra_crypto_import_key(ctx, type, data, size, out)` | 외부 키 → KV 핸들 |
| `caliptra_crypto_verify_signature(ctx, pub, flags, digest, sig, slen, valid)` | 서명 검증 |

---

## 9. OCP L.O.C.K. — [`api_lock.md`](api_lock.md)

`include/caliptra_lock.h`

| 함수 | 수준 | 설명 |
|---|---|---|
| `caliptra_lock_ecdh_encap(ctx, drive_pub, ss_h, eph_pub)` | 저수준 | ECDH KEM (임시키 생성 포함) |
| `caliptra_lock_mlkem_encap(ctx, drive_pub, ct, ss_h)` | 저수준 | ML-KEM-1024 캡슐화 |
| `caliptra_lock_hpke_derive_wrap_key(ctx, ss, mek_ctx, wrap_key)` | 저수준 | HKDF → AES 래핑 키 |
| `caliptra_lock_wrap_mek(ctx, mek, wrap, iv, aad, alen, ct, clen, tag)` | 저수준 | AES-GCM MEK 암호화 |
| `caliptra_lock_deliver_mek_ecdh(ctx, drive_pub, mek, ctx, blob)` | **고수준** | ECDH HPKE 원스텝 |
| `caliptra_lock_deliver_mek_mlkem(ctx, drive_pub, mek, ctx, blob)` | **고수준** | ML-KEM HPKE 원스텝 |
| `caliptra_lock_deliver_mek_hybrid(ctx, ecdh_pub, mlkem_pub, mek, ctx, blob)` | **고수준** | Hybrid HPKE 원스텝 |

---

## 10. Utility / Error — [`api_boot.md`](api_boot.md)

`include/caliptra_driver.h`

| 함수 | 설명 |
|---|---|
| `caliptra_get_version(ctx, ver)` | Runtime FW 버전 조회 |
| `caliptra_fips_self_test(ctx)` | FIPS 자체 테스트 |
| `caliptra_handle_fatal_error(ctx)` | Fatal 오류 로깅 |
| `caliptra_handle_non_fatal_error(ctx)` | Non-fatal 오류 클리어 |

---

## 반환 코드 요약

| 코드 | 값 | 의미 |
|---|---|---|
| `CALIPTRA_OK` | 0 | 성공 |
| `CALIPTRA_ERR_BUSY` | -1 | 메일박스 사용 중 |
| `CALIPTRA_ERR_TIMEOUT` | -2 | 응답 타임아웃 |
| `CALIPTRA_ERR_MBOX_LOCK` | -3 | 메일박스 잠금 실패 |
| `CALIPTRA_ERR_MBOX_STATUS` | -4 | 메일박스 상태 오류 |
| `CALIPTRA_ERR_CMD_FAILURE` | -5 | 커맨드 실패 응답 |
| `CALIPTRA_ERR_INVALID_PARAM` | -6 | 잘못된 파라미터 |
| `CALIPTRA_ERR_BUFFER_TOO_SMALL` | -7 | 버퍼 크기 부족 |
| `CALIPTRA_ERR_NOT_READY` | -8 | 준비 미완료 |
| `CALIPTRA_ERR_FATAL` | -9 | Fatal 오류 |
