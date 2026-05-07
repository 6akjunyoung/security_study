# 암호화 서비스 API (2.0+)

> **관련 파일**
> - `include/caliptra_driver.h` — `caliptra_crypto_sign`, `caliptra_crypto_rng`
> - `include/caliptra_crypto_ext.h` — 확장 암호화 서비스 (Hash/HMAC/HKDF/AES-GCM/ECDH/ML-KEM)
> - `include/caliptra_types.h` — `caliptra_key_handle_t`, `caliptra_key_type_t`, 크기 상수

---

## 1. Key Vault (KV) 모델

Caliptra의 모든 암호화 서비스는 **Key Vault(KV) 핸들** 기반으로 동작합니다.

```
                ┌────────────────────────────┐
                │     Caliptra 내부          │
                │  ┌────────────────────┐    │
SoC FW          │  │   Key Vault (KV)   │    │
  │             │  │  ┌──────────────┐  │    │
  │ 핸들만 보임  │  │  │  Key Slot 0  │  │    │
  │ ◀──────────────│  │  Key Slot 1  │  │    │
  │             │  │  │  ...         │  │    │
  │ 원시 키 접근│  │  │  Key Slot N  │  │    │
  │   불가      │  │  └──────────────┘  │    │
  │             │  └────────────────────┘    │
  │             │       │ 내부 연결          │
  │             │  ┌────▼───────────────┐    │
  │ API 호출 ──────▶  암호화 엔진       │    │
  │             │  │ (AES/SHA/ECDSA...) │    │
  │             └──└────────────────────┘────┘
```

### 핵심 원칙
1. **원시 키 접근 불가**: SoC FW는 `caliptra_key_handle_t`(불투명 정수)만 보관합니다.
2. **키 파생 체인**: HKDF 출력도 KV 핸들로 반환됩니다. 키 원본 값은 항상 KV 내부에 있습니다.
3. **임포트 후 폐기**: `caliptra_crypto_import_key()` 호출 후 원시 키 버퍼를 즉시 제로화하세요.

### `caliptra_key_type_t`

| 열거값 | 용도 |
|---|---|
| `CALIPTRA_KEY_TYPE_ECDSA_P384` | P-384 ECDSA 서명 키 |
| `CALIPTRA_KEY_TYPE_AES_256` | AES-256 대칭키 |
| `CALIPTRA_KEY_TYPE_HMAC_SHA384` | HMAC-SHA384 키 |
| `CALIPTRA_KEY_TYPE_ML_DSA_87` | ML-DSA-87 서명 키 |
| `CALIPTRA_KEY_TYPE_ML_KEM_1024` | ML-KEM-1024 키 캡슐화 키 |

---

## 2. Hash — SHA-384 / SHA-512

```c
#include "caliptra_crypto_ext.h"

/* SHA-384 계산 */
uint8_t  hash_out[CALIPTRA_SHA384_HASH_SIZE]; /* 48바이트 */
uint32_t hash_len = sizeof(hash_out);

caliptra_status_t st = caliptra_crypto_hash(
    &ctx,
    0,               /* 0 = SHA-384, 1 = SHA-512 */
    fw_buf, fw_size, /* 입력 데이터 */
    hash_out, &hash_len);

/* SHA-512 계산 */
uint8_t  hash512[CALIPTRA_SHA512_HASH_SIZE]; /* 64바이트 */
uint32_t hash512_len = sizeof(hash512);

caliptra_crypto_hash(&ctx, 1, data, data_len, hash512, &hash512_len);
```

> Caliptra 외부에서 SHA 엔진을 사용하는 것보다, Caliptra를 통해 계산하면
> FIPS 경계 내에서 해시가 수행되어 측정값의 신뢰성이 높아집니다.

---

## 3. HMAC-SHA384

HMAC 키는 반드시 KV 핸들 형태로 제공해야 합니다.
원시 키가 있다면 먼저 `caliptra_crypto_import_key()`로 임포트합니다.

```c
#include "caliptra_crypto_ext.h"

/* HMAC-SHA384 계산 */
caliptra_key_handle_t hmac_key;

/* 키 임포트 (원시 키 → KV 핸들) */
uint8_t raw_key[48]; /* 384-bit HMAC 키 */
caliptra_crypto_import_key(&ctx,
                            CALIPTRA_KEY_TYPE_HMAC_SHA384,
                            raw_key, sizeof(raw_key),
                            &hmac_key);
memset(raw_key, 0, sizeof(raw_key)); /* 즉시 제로화 */

/* HMAC 계산 */
uint8_t hmac_out[CALIPTRA_SHA384_HASH_SIZE]; /* 48바이트 */

caliptra_status_t st = caliptra_crypto_hmac(
    &ctx,
    &hmac_key,
    message_buf, message_len,
    hmac_out);
```

---

## 4. HKDF-SHA384 — 키 파생

`caliptra_crypto_hkdf()`는 IKM 핸들에서 새 KV 핸들을 파생합니다.
파생된 키도 KV 내부에 저장되며, 출력은 핸들만 반환됩니다.

```c
#include "caliptra_crypto_ext.h"

/*
 * 키 파생 체인 예시:
 *   Root Key → Derived Key 1 → Derived Key 2
 */

/* Root IKM 핸들 (예: Caliptra FW가 파생한 키) */
caliptra_key_handle_t root_key_handle = get_root_key_from_caliptra();

/* 1단계: Context 키 파생 */
const uint8_t salt1[]  = { 0x00 };  /* 솔트 (선택적) */
const uint8_t info1[]  = "soc_context_v1";

caliptra_key_handle_t context_key;
caliptra_status_t st = caliptra_crypto_hkdf(
    &ctx,
    &root_key_handle,
    salt1, sizeof(salt1),
    info1, sizeof(info1) - 1, /* null 제외 */
    48,                        /* OKM 길이 (384-bit) */
    &context_key);

/* 2단계: 세션 키 파생 (context_key에서) */
const uint8_t session_id[16] = { /* 세션별 고유 ID */ };
const uint8_t info2[] = "session_enc_key";

caliptra_key_handle_t session_key;
caliptra_crypto_hkdf(
    &ctx,
    &context_key,
    session_id, sizeof(session_id),
    info2, sizeof(info2) - 1,
    32,                         /* OKM 길이 (256-bit AES용) */
    &session_key);

/* session_key 핸들을 AES-GCM 등에 사용 */
```

---

## 5. AES-256-GCM

### 암호화

```c
#include "caliptra_crypto_ext.h"

caliptra_key_handle_t aes_key; /* KV 핸들 */

/* IV: 암호화마다 고유해야 함 (TRNG 권장) */
uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE]; /* 12바이트 */
caliptra_crypto_rng(&ctx, sizeof(iv), iv);

/* AAD: 추가 인증 데이터 (암호화되지 않지만 인증됨) */
const uint8_t aad[] = "header_metadata";

uint8_t  ct_buf[1024];
uint32_t ct_len = sizeof(ct_buf);
uint8_t  tag[CALIPTRA_AES_GCM_TAG_SIZE]; /* 16바이트 */

caliptra_status_t st = caliptra_crypto_aes_gcm_encrypt(
    &ctx,
    &aes_key,
    iv,
    aad, sizeof(aad) - 1,
    plaintext, plaintext_len,
    ct_buf, &ct_len,
    tag);

/* 전송: iv + aad_len + aad + ct_buf + tag 함께 전달 */
```

### 복호화

```c
uint8_t  pt_buf[1024];
uint32_t pt_len = sizeof(pt_buf);

caliptra_status_t st = caliptra_crypto_aes_gcm_decrypt(
    &ctx,
    &aes_key,
    iv,               /* 암호화 시 사용한 IV */
    aad, aad_len,     /* 암호화와 동일한 AAD */
    ct_buf, ct_len,   /* 암호문 */
    tag,              /* GCM 인증 태그 (검증 포함) */
    pt_buf, &pt_len);

if (st == CALIPTRA_ERR_CMD_FAILURE) {
    /* 태그 검증 실패 — 데이터 위변조 또는 키 불일치 */
}
```

---

## 6. ECDH P-384 — 키 합의

```c
#include "caliptra_crypto_ext.h"

/*
 * ECDH 키 교환 흐름:
 *   1. 자신의 P-384 키쌍을 보유 (priv_key_handle in KV)
 *   2. 상대방 공개키(peer_pub_key)를 수신
 *   3. ECDH 수행 → 공유 비밀 KV 핸들
 *   4. 공유 비밀을 HKDF로 세션 키 파생
 */

caliptra_key_handle_t my_priv_key;  /* P-384 개인키 KV 핸들 */
uint8_t peer_pub_key[CALIPTRA_ECC384_PUBKEY_SIZE]; /* X(48) + Y(48) */

caliptra_key_handle_t shared_secret;
caliptra_status_t st = caliptra_crypto_ecdh_key_agree(
    &ctx,
    &my_priv_key,
    peer_pub_key,
    &shared_secret);

/* 공유 비밀에서 세션 키 파생 */
caliptra_key_handle_t session_key;
caliptra_crypto_hkdf(&ctx, &shared_secret,
                      NULL, 0,
                      (const uint8_t *)"ecdh_session", 12,
                      32, &session_key);
```

---

## 7. ML-KEM-1024 — 캡슐화 / 역캡슐화

ML-KEM-1024는 **양자 내성** 키 캡슐화 메커니즘(FIPS 203)입니다.

### 캡슐화 (발신자 측)

```c
#include "caliptra_crypto_ext.h"

/* 수신자의 ML-KEM-1024 공개키 (1568바이트) */
uint8_t recipient_pub[CALIPTRA_ML_KEM_1024_PUB_SIZE];
receive_recipient_public_key(recipient_pub);

/* 캡슐화: 공개키에서 암호문 + 공유 비밀 생성 */
uint8_t              mlkem_ct[CALIPTRA_ML_KEM_1024_CT_SIZE]; /* 1568바이트 */
caliptra_key_handle_t shared_secret;

caliptra_status_t st = caliptra_crypto_ml_kem_encap(
    &ctx,
    recipient_pub,
    mlkem_ct,       /* 수신자에게 전달할 암호문 */
    &shared_secret);

/* mlkem_ct를 수신자에게 전송 */
/* shared_secret 핸들로 세션 키 파생 */
```

### 역캡슐화 (수신자 측)

```c
/* 자신의 ML-KEM-1024 개인키 KV 핸들 */
caliptra_key_handle_t my_mlkem_priv;

/* 발신자가 보낸 암호문 수신 */
uint8_t received_ct[CALIPTRA_ML_KEM_1024_CT_SIZE];

caliptra_key_handle_t shared_secret;
caliptra_status_t st = caliptra_crypto_ml_kem_decap(
    &ctx,
    &my_mlkem_priv,
    received_ct,
    &shared_secret);

/* 동일한 공유 비밀에서 세션 키 파생 */
```

---

## 8. 서명 — ECDSA / ML-DSA 이중 서명

Caliptra 2.0+는 ECDSA P-384와 ML-DSA-87을 **동시에** 서명할 수 있습니다.

```c
#include "caliptra_driver.h"

/* 서명할 SHA-384 해시 */
uint8_t digest[CALIPTRA_SHA384_HASH_SIZE];
caliptra_crypto_hash(&ctx, 0, message, message_len, digest, NULL);

caliptra_crypto_sign_resp_t resp;

/* flags: 0x01=ECDSA only, 0x02=ML-DSA only, 0x03=Dual sign */
caliptra_status_t st = caliptra_crypto_sign(
    &ctx,
    &signing_key_handle,
    digest,
    0x03,    /* ECDSA + ML-DSA 이중 서명 */
    &resp);

/* resp.ecdsa_sig: ECDSA 서명 (96바이트, R+S) */
/* resp.mldsa_sig: ML-DSA-87 서명 (4627바이트) */
```

---

## 9. 서명 검증

```c
#include "caliptra_crypto_ext.h"

bool is_valid = false;

/* ECDSA P-384 서명 검증 */
caliptra_status_t st = caliptra_crypto_verify_signature(
    &ctx,
    &pub_key_handle,        /* 공개키 KV 핸들 */
    0x01,                   /* flags: 0x01=ECDSA, 0x02=ML-DSA */
    digest,                 /* SHA-384 해시 (48바이트) */
    sig_data, sig_len,      /* 서명 데이터 */
    &is_valid);

if (st != CALIPTRA_OK || !is_valid) {
    /* 서명 검증 실패 */
    reject_image();
}
```

---

## 10. TRNG — 난수 생성

Caliptra의 온칩 TRNG(True Random Number Generator)를 사용합니다.

```c
#include "caliptra_driver.h"

/* 32바이트 난수 생성 (최대 256바이트) */
uint8_t random_buf[32];

caliptra_status_t st = caliptra_crypto_rng(&ctx, sizeof(random_buf), random_buf);

/* IV 생성 예시 */
uint8_t iv[CALIPTRA_AES_GCM_IV_SIZE]; /* 12바이트 */
caliptra_crypto_rng(&ctx, sizeof(iv), iv);
```

---

## 11. 키 임포트

외부 키를 Caliptra KV로 가져와 핸들로 변환합니다.
임포트 후 원시 키 버퍼는 **즉시 제로화**해야 합니다.

```c
#include "caliptra_crypto_ext.h"

/* 예: 외부 AES-256 키를 KV로 임포트 */
uint8_t raw_aes_key[32];
retrieve_key_from_secure_storage(raw_aes_key); /* 보안 스토리지에서 읽기 */

caliptra_key_handle_t kv_handle;
caliptra_status_t st = caliptra_crypto_import_key(
    &ctx,
    CALIPTRA_KEY_TYPE_AES_256,
    raw_aes_key, sizeof(raw_aes_key),
    &kv_handle);

/* 원시 키 버퍼 즉시 제로화 */
memset(raw_aes_key, 0, sizeof(raw_aes_key));

if (st != CALIPTRA_OK) {
    /* 임포트 실패 */
    return st;
}

/* 이제 kv_handle을 AES-GCM 등에 사용 */
```

---

## 크기 상수 요약

| 상수 | 값 | 용도 |
|---|---|---|
| `CALIPTRA_SHA384_HASH_SIZE` | 48 | SHA-384 해시 출력 |
| `CALIPTRA_SHA512_HASH_SIZE` | 64 | SHA-512 해시 출력 |
| `CALIPTRA_ECC384_PUBKEY_SIZE` | 96 | P-384 공개키 (X+Y) |
| `CALIPTRA_ECC384_SIG_SIZE` | 96 | ECDSA 서명 (R+S) |
| `CALIPTRA_MLDSA87_PUBKEY_SIZE` | 2592 | ML-DSA-87 공개키 |
| `CALIPTRA_MLDSA87_SIG_SIZE` | 4627 | ML-DSA-87 서명 |
| `CALIPTRA_ML_KEM_1024_PUB_SIZE` | 1568 | ML-KEM-1024 공개키 |
| `CALIPTRA_ML_KEM_1024_CT_SIZE` | 1568 | ML-KEM-1024 암호문 |
| `CALIPTRA_AES_GCM_IV_SIZE` | 12 | AES-GCM IV |
| `CALIPTRA_AES_GCM_TAG_SIZE` | 16 | AES-GCM 태그 |
