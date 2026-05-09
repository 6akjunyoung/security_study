# 인증서 & DPE API

> 레퍼런스: `caliptra-sw/libcaliptra/inc/caliptra_api.h`
> Runtime 준비 후 사용 가능

Caliptra 2.x는 **ECC-384** 와 **ML-DSA-87 (MLDSA87)** 두 가지 서명 알고리즘을 지원합니다.
각 인증서/CSR API는 두 변형(`_ecc384_` / `_mldsa87_`)으로 제공됩니다.

## 인증서 계층

```
IDevID (IakeCert) ← 실리콘 제조 시 퓨즈에서 파생
    └── LDevID     ← FMC가 파생 (장치 생애주기 키)
         └── FMC Alias ← FMC 측정값 포함
              └── RT Alias  ← Runtime 측정값 포함
```

## 인증서 API

### IDevID 인증서

```c
// IDevID ECC384 인증서 획득
int caliptra_get_idev_ecc384_cert(
    struct caliptra_get_idev_ecc384_cert_req  *req,
    struct caliptra_get_idev_ecc384_cert_resp *resp,
    bool async);

// IDevID MLDSA87 인증서 획득 (양자 내성)
int caliptra_get_idev_mldsa87_cert(
    struct caliptra_get_idev_mldsa87_cert_req  *req,
    struct caliptra_get_idev_mldsa87_cert_resp *resp,
    bool async);
```

### IDevID 정보

```c
// IDevID ECC384 공개키 정보 조회
int caliptra_get_idev_ecc384_info(
    struct caliptra_get_idev_ecc384_info_resp *resp, bool async);

// IDevID MLDSA87 공개키 정보 조회
int caliptra_get_idev_mldsa87_info(
    struct caliptra_get_idev_mldsa87_info_resp *resp, bool async);
```

### IDevID 인증서 삽입 (제조 단계)

```c
// IDevID ECC384 인증서 삽입 (외부 CA 서명)
int caliptra_populate_idev_ecc384_cert(
    struct caliptra_populate_idev_ecc384_cert_req *req, bool async);

// IDevID MLDSA87 인증서 삽입
int caliptra_populate_idev_mldsa87_cert(
    struct caliptra_populate_idev_mldsa87_cert_req *req, bool async);
```

### LDevID 인증서

```c
// LDevID ECC384 인증서
int caliptra_get_ldev_ecc384_cert(
    struct caliptra_get_ldev_ecc384_cert_resp *resp, bool async);

// LDevID MLDSA87 인증서
int caliptra_get_ldev_mldsa87_cert(
    struct caliptra_get_ldev_mldsa87_cert_resp *resp, bool async);
```

### FMC Alias 인증서

```c
// FMC Alias ECC384 인증서
int caliptra_get_fmc_alias_ecc384_cert(
    struct caliptra_get_fmc_alias_ecc384_cert_resp *resp, bool async);

// FMC Alias MLDSA87 인증서
int caliptra_get_fmc_alias_mldsa87_cert(
    struct caliptra_get_fmc_alias_mldsa87_cert_resp *resp, bool async);
```

### RT Alias 인증서

```c
// RT Alias ECC384 인증서
int caliptra_get_rt_alias_ecc384_cert(
    struct caliptra_get_rt_alias_ecc384_cert_resp *resp, bool async);

// RT Alias MLDSA87 인증서
int caliptra_get_rt_alias_mldsa87_cert(
    struct caliptra_get_rt_alias_mldsa87_cert_resp *resp, bool async);
```

### CSR (Certificate Signing Request)

```c
// IDevID ECC384 CSR (제조 단계)
int caliptra_get_idev_ecc384_csr(
    struct caliptra_get_idev_ecc384_csr_resp *resp, bool async);

// IDevID MLDSA87 CSR
int caliptra_get_idev_mldsa87_csr(
    struct caliptra_get_idev_mldsa87_csr_resp *resp, bool async);

// FMC Alias ECC384 CSR
int caliptra_get_fmc_alias_ecc384_csr(
    struct caliptra_get_fmc_alias_ecc384_csr_resp *resp, bool async);

// FMC Alias MLDSA87 CSR
int caliptra_get_fmc_alias_mldsa87_csr(
    struct caliptra_get_fmc_alias_mldsa87_csr_resp *resp, bool async);
```

## DPE (DICE Protection Environment) API

DPE는 DICE 키 파생 및 인증서 발급 서비스입니다.
DPE 커맨드는 직렬화된 바이너리 포맷으로 전달됩니다.

```c
// ECC384 DPE 커맨드 (기본)
int caliptra_invoke_dpe_command(
    struct caliptra_invoke_dpe_req  *req,
    struct caliptra_invoke_dpe_resp *resp,
    bool async);

// MLDSA87 DPE 커맨드 (양자 내성)
int caliptra_invoke_dpe_mldsa87_command(
    struct caliptra_invoke_dpe_mldsa87_req *req,
    struct caliptra_invoke_dpe_resp        *resp,
    bool async);
```

### DPE 커맨드 코드 (`caliptra_enums.h`)

| 커맨드 | 코드 | 설명 |
|--------|------|------|
| `DPE_GET_PROFILE` | 0x1 | 지원 DPE 프로파일 조회 |
| `DPE_INITIALIZE_CONTEXT` | 0x7 | 새 DPE 컨텍스트 생성 |
| `DPE_DERIVE_CONTEXT` | 0x8 | 컨텍스트에서 자식 컨텍스트 파생 |
| `DPE_CERTIFY_KEY` | 0x9 | 컨텍스트 키에 대한 인증서 발급 |
| `DPE_SIGN` | 0xA | DPE 키로 서명 |
| `DPE_ROTATE_CTX_HANDLE` | 0xE | 컨텍스트 핸들 교체 |
| `DPE_DESTROY_CTX` | 0xF | 컨텍스트 파기 |
| `DPE_GET_CERT_CHAIN` | 0x10 | 인증서 체인 조회 |

### DPE DERIVE_CONTEXT 플래그

```c
// caliptra_enums.h
DPE_DERIVE_CONTEXT_FLAG_RETAIN_PARENT_CONTEXT  = (1UL << 29)
DPE_DERIVE_CONTEXT_FLAG_RECURSIVE              = (1UL << 24)
DPE_DERIVE_CONTEXT_FLAG_EXPORT_CDI            = (1UL << 23)
DPE_DERIVE_CONTEXT_FLAG_CREATE_CERTIFICATE    = (1UL << 22)
```

### DPE 프로파일

```c
enum dpe_profile {
    P256Sha256 = 3,  // DPE_PROFILE_256
    P384Sha384 = 4,  // DPE_PROFILE_384
};
```

## DPE Tag/TCI API

```c
// TCI에 태그 연결
int caliptra_dpe_tag_tci(
    struct caliptra_dpe_tag_tci_req *req, bool async);

// 태그로 TCI 조회
int caliptra_dpe_get_tagged_tci(
    struct caliptra_get_tagged_tci_req  *req,
    struct caliptra_get_tagged_tci_resp *resp,
    bool async);
```

## Certify Key Extended

DPE 컨텍스트 외 키에 대한 확장 인증서 발급:

```c
// ECC384 Certify Key Extended
int caliptra_certify_key_extended_ecc384(
    struct caliptra_certify_key_extended_ecc384_req *req,
    struct caliptra_certify_key_extended_resp       *resp,
    bool async);

// MLDSA87 Certify Key Extended
int caliptra_certify_key_extended_mldsa87(
    struct caliptra_certify_key_extended_mldsa87_req *req,
    struct caliptra_certify_key_extended_resp        *resp,
    bool async);
```

**플래그** (`caliptra_enums.h`):
```c
enum certify_key_extended_flags {
    DMTF_OTHER_NAME = (1UL << 31),  // SubjectAltName에 OtherName 포함
};
```

## Add Subject Alt Name

```c
// RT Alias 인증서에 SAN 추가
int caliptra_add_subject_alt_name(
    struct caliptra_add_subject_alt_name_req *req, bool async);
```

## Exported ECDSA (DPE CDI 기반 서명)

```c
// Exported CDI 핸들로 ECDSA 서명
int caliptra_sign_with_exported_ecdsa(
    struct caliptra_sign_with_exported_ecdsa_req  *req,
    struct caliptra_sign_with_exported_ecdsa_resp *resp,
    bool async);

// Exported CDI 핸들 폐기
int caliptra_revoke_exported_cdi_handle(
    struct caliptra_revoke_exported_cdi_handle_req *req, bool async);
```

## FW Info

```c
// Runtime FW 정보 조회 (버전, PCR 상태, attestation 상태)
int caliptra_fw_info(struct caliptra_fw_info_resp *resp, bool async);
```

## Attestation 비활성화

```c
// Attestation 기능 비활성화 (보안 이벤트 대응)
int caliptra_disable_attestation(bool async);
```

## 사용 예제

```c
// ECC384 + MLDSA87 이중 인증서 획득
struct caliptra_get_idev_ecc384_cert_req  ecc_req  = { .hdr = {0} };
struct caliptra_get_idev_ecc384_cert_resp ecc_resp = {0};
caliptra_get_idev_ecc384_cert(&ecc_req, &ecc_resp, false);

struct caliptra_get_idev_mldsa87_cert_req  ml_req  = { .hdr = {0} };
struct caliptra_get_idev_mldsa87_cert_resp ml_resp = {0};
caliptra_get_idev_mldsa87_cert(&ml_req, &ml_resp, false);
```
