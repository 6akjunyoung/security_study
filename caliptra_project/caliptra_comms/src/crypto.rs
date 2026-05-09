use crate::runner::TestResult;

pub fn run_all() -> Vec<TestResult> {
    vec![
        TestResult::skip(
            "ECDSA384_SIGNATURE_VERIFY",
            "requires a valid ECC384 pub key + signature + hash",
        ),
        TestResult::skip(
            "LMS_SIGNATURE_VERIFY",
            "requires a valid LMS pub key + OTS signature",
        ),
        TestResult::skip(
            "MLDSA87_SIGNATURE_VERIFY",
            "requires a valid MLDSA87 pub key (2592B) + signature (4628B)",
        ),
    ]
}
