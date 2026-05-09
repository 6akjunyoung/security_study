use crate::runner::{hex, parse_var_resp, try_send, TestResult};
use caliptra_api::mailbox::CommandId;
use caliptra_hw_model::DefaultHwModel;

pub fn run_all(model: &mut DefaultHwModel) -> Vec<TestResult> {
    vec![
        // IDevID certs require POPULATE_IDEV first
        TestResult::skip(
            "GET_IDEV_ECC384_CERT",
            "requires POPULATE_IDEV_ECC384_CERT first",
        ),
        TestResult::skip(
            "GET_IDEV_MLDSA87_CERT",
            "requires POPULATE_IDEV_MLDSA87_CERT first",
        ),
        // LDevID / FMC Alias / RT Alias are always available
        test_cert(model, "GET_LDEV_ECC384_CERT", CommandId::GET_LDEV_ECC384_CERT),
        test_cert(model, "GET_LDEV_MLDSA87_CERT", CommandId::GET_LDEV_MLDSA87_CERT),
        test_cert(model, "GET_FMC_ALIAS_ECC384_CERT", CommandId::GET_FMC_ALIAS_ECC384_CERT),
        test_cert(model, "GET_FMC_ALIAS_MLDSA87_CERT", CommandId::GET_FMC_ALIAS_MLDSA87_CERT),
        test_cert(model, "GET_RT_ALIAS_ECC384_CERT", CommandId::GET_RT_ALIAS_ECC384_CERT),
        test_cert(model, "GET_RT_ALIAS_MLDSA87_CERT", CommandId::GET_RT_ALIAS_MLDSA87_CERT),
    ]
}

fn test_cert(model: &mut DefaultHwModel, name: &'static str, cmd: CommandId) -> TestResult {
    match try_send(model, cmd, &[]) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match parse_var_resp(&resp) {
            Err(e) => TestResult::fail(name, e),
            Ok(cert) => {
                if cert.is_empty() {
                    return TestResult::fail(name, "empty certificate");
                }
                if cert[0] != 0x30 {
                    return TestResult::fail(
                        name,
                        format!("expected DER SEQUENCE (0x30), got {:#04x}", cert[0]),
                    );
                }
                println!("    size={} DER[..8]={}", cert.len(), hex(&cert[..8.min(cert.len())]));
                TestResult::pass(name)
            }
        },
    }
}
