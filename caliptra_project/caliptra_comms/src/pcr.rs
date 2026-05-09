use crate::runner::{hex, try_send, TestResult};
use caliptra_api::mailbox::{CommandId, QuotePcrsEcc384Resp, QuotePcrsMldsa87Resp, StashMeasurementResp};
use caliptra_hw_model::DefaultHwModel;
use zerocopy::FromBytes;

pub fn run_all(model: &mut DefaultHwModel) -> Vec<TestResult> {
    vec![
        test_stash_measurement(model),
        test_extend_pcr(model),
        test_increment_pcr_reset_counter(model),
        test_quote_pcrs_ecc384(model),
        test_quote_pcrs_mldsa87(model),
    ]
}

fn test_stash_measurement(model: &mut DefaultHwModel) -> TestResult {
    let name = "STASH_MEASUREMENT";
    // StashMeasurementReq extra: metadata[4] + measurement[48] + context[48] + svn[4]
    let mut extra = [0u8; 4 + 48 + 48 + 4];
    // measurement: sha384 of b"test" (just use a non-zero pattern)
    extra[4..52].fill(0xab);
    match try_send(model, CommandId::STASH_MEASUREMENT, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match StashMeasurementResp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((r, _)) => {
                println!("    dpe_result={:#010x}", r.dpe_result);
                TestResult::pass(name)
            }
        },
    }
}

fn test_extend_pcr(model: &mut DefaultHwModel) -> TestResult {
    let name = "EXTEND_PCR";
    // ExtendPcrReq extra: pcr_idx[4] + data[48]
    let mut extra = [0u8; 4 + 48];
    extra[0..4].copy_from_slice(&4u32.to_le_bytes()); // pcr_idx = 4 (0-3 are reserved)
    extra[4..].fill(0xcd);                             // data pattern
    match try_send(model, CommandId::EXTEND_PCR, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(_) => TestResult::pass(name),
    }
}

fn test_increment_pcr_reset_counter(model: &mut DefaultHwModel) -> TestResult {
    let name = "INCREMENT_PCR_RESET_COUNTER";
    // IncrementPcrResetCounterReq extra: index[4]
    let extra = 0u32.to_le_bytes(); // index = 0
    match try_send(model, CommandId::INCREMENT_PCR_RESET_COUNTER, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(_) => TestResult::pass(name),
    }
}

fn test_quote_pcrs_ecc384(model: &mut DefaultHwModel) -> TestResult {
    let name = "QUOTE_PCRS_ECC384";
    // QuotePcrsEcc384Req extra: nonce[32]
    let extra = [0u8; 32];
    match try_send(model, CommandId::QUOTE_PCRS_ECC384, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match QuotePcrsEcc384Resp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((q, _)) => {
                println!(
                    "    pcr[0][..8]={} sig_r[..8]={}",
                    hex(&q.pcrs[0][..8]),
                    hex(&q.signature_r[..8])
                );
                TestResult::pass(name)
            }
        },
    }
}

fn test_quote_pcrs_mldsa87(model: &mut DefaultHwModel) -> TestResult {
    let name = "QUOTE_PCRS_MLDSA87";
    // QuotePcrsMldsa87Req extra: nonce[32]
    let extra = [0u8; 32];
    match try_send(model, CommandId::QUOTE_PCRS_MLDSA87, &extra) {
        Err(e) => TestResult::fail(name, e),
        Ok(resp) => match QuotePcrsMldsa87Resp::ref_from_prefix(&resp) {
            Err(_) => TestResult::fail(name, "parse error"),
            Ok((q, _)) => {
                println!(
                    "    pcr[0][..8]={} sig[..8]={}",
                    hex(&q.pcrs[0][..8]),
                    hex(&q.signature[..8])
                );
                TestResult::pass(name)
            }
        },
    }
}
