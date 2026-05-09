use crate::runner::{hex, try_send, TestResult};
use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, OcpLockEnumerateHpkeHandlesResp, OcpLockGenerateMekResp,
    OcpLockGetAlgorithmsResp, OcpLockGetHpkePubKeyResp, OcpLockGetStatusResp,
    OcpLockRotateHpkeKeyResp,
};
use caliptra_hw_model::DefaultHwModel;
use zerocopy::FromBytes;

pub fn run_all(model: &mut DefaultHwModel) -> Vec<TestResult> {
    let mut results = Vec::new();

    // ── 1. 읽기 전용 (사전 설정 불필요) ────────────────────────────────────────
    results.push(test_get_algorithms(model));
    results.push(test_get_status(model));

    // ── 2. HEK 메타데이터 보고 ────────────────────────────────────────────────
    // OCP_LOCK_REPORT_HEK_METADATA is handled by Caliptra ROM (cold_reset flow),
    // not by the Runtime. It must be sent via InitParams::rom_callback before
    // the Runtime starts. Calling it post-boot returns RUNTIME_UNIMPLEMENTED_COMMAND.
    results.push(TestResult::skip(
        "OCP_LOCK_REPORT_HEK_METADATA",
        "ROM-phase command; must use InitParams::rom_callback before Runtime starts",
    ));

    // ── 3. HPKE 핸들 열거 + 조건부 공개키/갱신 ──────────────────────────────
    let handles = enumerate_hpke_handles(model, &mut results);
    if handles.is_empty() {
        results.push(TestResult::skip(
            "GET_HPKE_PUB_KEY",
            "no HPKE handles (emulator starts with 0 handles)",
        ));
        results.push(TestResult::skip(
            "ROTATE_HPKE_KEY",
            "no HPKE handles to rotate",
        ));
    } else {
        results.push(test_get_hpke_pub_key(model, handles[0]));
        results.push(test_rotate_hpke_key(model, handles[0]));
    }

    // ── 4. MEK 시드 초기화 후 MEK 생성 ──────────────────────────────────────
    // GENERATE_MEK requires the MEK secret to be seeded first via INITIALIZE_MEK_SECRET.
    // Dummy SEK/DPK values (as used in caliptra-sw integration tests) are sufficient.
    results.push(test_initialize_mek_secret(model));
    results.push(test_generate_mek(model));

    // ── 5. 복잡한 키 자료가 필요한 명령 — Skip ───────────────────────────────
    results.push(TestResult::skip(
        "DERIVE_MEK",
        "requires a valid WrappedMEK checksum from GENERATE_MEK flow",
    ));
    results.push(TestResult::skip(
        "LOAD_MEK / UNLOAD_MEK",
        "requires a valid WrappedMEK from GENERATE_MEK",
    ));
    results.push(TestResult::skip(
        "GENERATE_MPK / ENABLE_MPK / MIX_MPK / REWRAP_MPK",
        "requires SEK + SealedAccessKey setup",
    ));
    results.push(TestResult::skip(
        "TEST_ACCESS_KEY",
        "requires a valid locked_mpk + sealed_access_key",
    ));
    results.push(TestResult::skip(
        "CLEAR_KEY_CACHE",
        "destructive side-effect — omitted from automated run",
    ));

    results
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn hpke_algo_str(a: &HpkeAlgorithms) -> String {
    let mut parts = Vec::new();
    if a.contains(HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM) {
        parts.push("ECDH-P384");
    }
    if a.contains(HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM) {
        parts.push("MLKEM1024");
    }
    if a.contains(HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM) {
        parts.push("MLKEM1024+ECDH");
    }
    if parts.is_empty() { "none".into() } else { parts.join("|") }
}

// ─── 개별 테스트 ──────────────────────────────────────────────────────────────

fn test_get_algorithms(model: &mut DefaultHwModel) -> TestResult {
    let name = "OCP_LOCK_GET_ALGORITHMS";
    match try_send(model, CommandId::OCP_LOCK_GET_ALGORITHMS, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match OcpLockGetAlgorithmsResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!(
                    "    hpke={} ak_sizes={:#010x}",
                    hpke_algo_str(&r.hpke_algorithms),
                    r.access_key_sizes.bits()
                );
                TestResult::pass(name)
            }
        },
    }
}

fn test_get_status(model: &mut DefaultHwModel) -> TestResult {
    let name = "OCP_LOCK_GET_STATUS";
    match try_send(model, CommandId::OCP_LOCK_GET_STATUS, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match OcpLockGetStatusResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!("    ctrl_register={:#010x}", r.ctrl_register);
                TestResult::pass(name)
            }
        },
    }
}

fn test_initialize_mek_secret(model: &mut DefaultHwModel) -> TestResult {
    let name = "OCP_LOCK_INITIALIZE_MEK_SECRET";
    // extra: reserved(u32) + sek(32B) + dpk(32B) — dummy test values
    let mut extra = [0u8; 4 + 32 + 32];
    extra[4..36].fill(0xAB);  // sek = test pattern
    extra[36..68].fill(0xCD); // dpk = test pattern
    match try_send(model, CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(_) => TestResult::pass(name),
    }
}

/// 핸들을 열거해서 results에 추가, 핸들 번호 목록을 반환
fn enumerate_hpke_handles(model: &mut DefaultHwModel, results: &mut Vec<TestResult>) -> Vec<u32> {
    let name = "OCP_LOCK_ENUMERATE_HPKE_HANDLES";
    let extra = [0u8; 4]; // reserved u32
    match try_send(model, CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES, &extra) {
        Err(e) => {
            results.push(TestResult::fail(name, e));
            vec![]
        }
        Ok(resp) => match OcpLockEnumerateHpkeHandlesResp::ref_from_prefix(&resp) {
            Err(_) => {
                results.push(TestResult::fail(name, "parse error"));
                vec![]
            }
            Ok((r, _)) => {
                let count = r.hpke_handle_count as usize;
                print!("    count={count}");
                let handles: Vec<u32> = r.hpke_handles[..count.min(r.hpke_handles.len())]
                    .iter()
                    .map(|h| {
                        print!(" handle={:#010x}(algo={})", h.handle, hpke_algo_str(&h.hpke_algorithm));
                        h.handle
                    })
                    .collect();
                println!();
                results.push(TestResult::pass(name));
                handles
            }
        },
    }
}

fn test_get_hpke_pub_key(model: &mut DefaultHwModel, handle: u32) -> TestResult {
    let name = "OCP_LOCK_GET_HPKE_PUB_KEY";
    // extra = reserved(u32) + hpke_handle(u32)
    let mut extra = [0u8; 8];
    extra[4..8].copy_from_slice(&handle.to_le_bytes());

    match try_send(model, CommandId::OCP_LOCK_GET_HPKE_PUB_KEY, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match OcpLockGetHpkePubKeyResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!(
                    "    handle={:#010x} pub_key_len={} pub_key[..8]={}",
                    handle,
                    r.pub_key_len,
                    hex(&r.pub_key[..8.min(r.pub_key_len as usize)])
                );
                TestResult::pass(name)
            }
        },
    }
}

fn test_rotate_hpke_key(model: &mut DefaultHwModel, handle: u32) -> TestResult {
    let name = "OCP_LOCK_ROTATE_HPKE_KEY";
    // extra = reserved(u32) + hpke_handle(u32)
    let mut extra = [0u8; 8];
    extra[4..8].copy_from_slice(&handle.to_le_bytes());

    match try_send(model, CommandId::OCP_LOCK_ROTATE_HPKE_KEY, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match OcpLockRotateHpkeKeyResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!("    old_handle={handle:#010x} → new_handle={:#010x}", r.hpke_handle);
                TestResult::pass(name)
            }
        },
    }
}

fn test_generate_mek(model: &mut DefaultHwModel) -> TestResult {
    let name = "OCP_LOCK_GENERATE_MEK";
    let extra = [0u8; 4]; // reserved u32
    match try_send(model, CommandId::OCP_LOCK_GENERATE_MEK, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match OcpLockGenerateMekResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!(
                    "    wrapped_mek.key_type={} key_len={} salt={}",
                    r.wrapped_mek.key_type,
                    r.wrapped_mek.key_len,
                    hex(&r.wrapped_mek.salt)
                );
                TestResult::pass(name)
            }
        },
    }
}
