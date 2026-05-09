use crate::runner::{hex, parse_var_resp, try_send, TestResult};
use caliptra_api::mailbox::{
    CapabilitiesResp, CommandId, FipsVersionResp, FwInfoResp, GetIdevEcc384InfoResp,
    GetIdevMldsa87InfoResp,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use zerocopy::FromBytes;

// RtFipSelfTestComplete boot status code (RUNTIME_BOOT_STATUS_BASE + 2)
const RT_FIPS_SELF_TEST_COMPLETE: u32 = 0x600 + 2;

pub fn run_all(model: &mut DefaultHwModel) -> Vec<TestResult> {
    vec![
        test_version(model),
        test_fw_info(model),
        test_capabilities(model),
        test_self_test(model),
        test_idev_ecc384_info(model),
        test_idev_mldsa87_info(model),
        test_get_pcr_log(model),
        test_image_info_skip(),
    ]
}

fn test_version(model: &mut DefaultHwModel) -> TestResult {
    let name = "VERSION (FIPS)";
    match try_send(model, CommandId::VERSION, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match FipsVersionResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((v, _)) => {
                println!(
                    "    mode={:#010x} rev={}.{}.{} name={}",
                    v.mode,
                    v.fips_rev[0],
                    v.fips_rev[1],
                    v.fips_rev[2],
                    String::from_utf8_lossy(&v.name).trim_end_matches('\0')
                );
                TestResult::pass(name)
            }
        },
    }
}

fn test_fw_info(model: &mut DefaultHwModel) -> TestResult {
    let name = "FW_INFO";
    match try_send(model, CommandId::FW_INFO, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match FwInfoResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((info, _)) => {
                println!(
                    "    fw_svn={} pqc_type={} attest_dis={}",
                    info.fw_svn,
                    info.image_manifest_pqc_type,
                    info.attestation_disabled != 0
                );
                TestResult::pass(name)
            }
        },
    }
}

fn test_capabilities(model: &mut DefaultHwModel) -> TestResult {
    let name = "CAPABILITIES";
    match try_send(model, CommandId::CAPABILITIES, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match CapabilitiesResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((cap, _)) => {
                println!("    caps={}", hex(&cap.capabilities));
                TestResult::pass(name)
            }
        },
    }
}

fn test_self_test(model: &mut DefaultHwModel) -> TestResult {
    let name = "SELF_TEST (START+GET_RESULTS)";
    if let Err(e) = try_send(model, CommandId::SELF_TEST_START, &[]) {
        return TestResult::fail(name, format!("START: {e}"));
    }
    // The self-test runs in the firmware idle loop (enter_idle).
    // step_until_boot_status fires when boot_status = 0x602 is written,
    // but that happens BEFORE mbox.unlock() in the same idle iteration.
    // Extra steps let the firmware finish unlocking the mailbox.
    model.step_until_boot_status(RT_FIPS_SELF_TEST_COMPLETE, true);
    for _ in 0..100_000 {
        model.step();
    }
    match try_send(model, CommandId::SELF_TEST_GET_RESULTS, &[]) {
        Err(e) => TestResult::fail(name, format!("GET_RESULTS: {e}")),
        Ok(_) => TestResult::pass(name),
    }
}

fn test_idev_ecc384_info(model: &mut DefaultHwModel) -> TestResult {
    let name = "GET_IDEV_ECC384_INFO";
    match try_send(model, CommandId::GET_IDEV_ECC384_INFO, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match GetIdevEcc384InfoResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((info, _)) => {
                println!("    pub_x[..8]={}", hex(&info.idev_pub_x[..8]));
                TestResult::pass(name)
            }
        },
    }
}

fn test_idev_mldsa87_info(model: &mut DefaultHwModel) -> TestResult {
    let name = "GET_IDEV_MLDSA87_INFO";
    match try_send(model, CommandId::GET_IDEV_MLDSA87_INFO, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match GetIdevMldsa87InfoResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((info, _)) => {
                println!("    pub_key[..8]={}", hex(&info.idev_pub_key[..8]));
                TestResult::pass(name)
            }
        },
    }
}

fn test_get_pcr_log(model: &mut DefaultHwModel) -> TestResult {
    let name = "GET_PCR_LOG";
    match try_send(model, CommandId::GET_PCR_LOG, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match parse_var_resp(&resp) {
            Err(e) => TestResult::fail(name, e),
            Ok(data) => {
                println!("    log_size={} bytes", data.len());
                TestResult::pass(name)
            }
        },
    }
}

fn test_image_info_skip() -> TestResult {
    TestResult::skip(
        "GET_IMAGE_INFO",
        "requires SET_AUTH_MANIFEST with registered fw_id first",
    )
}
