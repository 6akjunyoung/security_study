// Caliptra 통신 테스트 - caliptra-hw-model을 이용해 mailbox 명령을 보내고 응답을 검증한다.

use caliptra_api::{
    calc_checksum,
    mailbox::{CommandId, FipsVersionResp, FwInfoResp, MailboxReqHeader, MailboxRespHeader},
};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use zerocopy::{FromBytes, IntoBytes};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// 체크섬을 계산하고 mailbox_execute 를 호출한다.
fn send_cmd(model: &mut DefaultHwModel, cmd: CommandId, extra: &[u8]) -> Vec<u8> {
    let cmd_u32 = u32::from(cmd);
    let chksum = calc_checksum(cmd_u32, extra);
    let hdr = MailboxReqHeader { chksum };
    let mut payload = hdr.as_bytes().to_vec();
    payload.extend_from_slice(extra);

    model
        .mailbox_execute(cmd_u32, &payload)
        .unwrap_or_else(|e| panic!("[cmd 0x{:08x}] mailbox 오류: {:?}", cmd_u32, e))
        .expect("응답 데이터가 없음")
}

/// VarSizeDataResp 형식(hdr 8B + data_size 4B + data) 파싱 – 인증서 명령에 사용
fn parse_var_resp(resp: &[u8]) -> &[u8] {
    let hdr_size = std::mem::size_of::<MailboxRespHeader>(); // 8
    assert!(resp.len() >= hdr_size + 4, "응답이 너무 짧음");
    let data_size = u32::from_le_bytes(resp[hdr_size..hdr_size + 4].try_into().unwrap()) as usize;
    let data_end = hdr_size + 4 + data_size;
    assert!(resp.len() >= data_end, "data_size({data_size})가 응답 길이를 초과함");
    &resp[hdr_size + 4..data_end]
}

// ─── 각 명령 테스트 ───────────────────────────────────────────────────────────

fn test_fips_version(model: &mut DefaultHwModel) {
    println!("\n─── [1] FIPS VERSION (0x{:08x}) ───", u32::from(CommandId::VERSION));
    let resp = send_cmd(model, CommandId::VERSION, &[]);
    let (ver, _) = FipsVersionResp::ref_from_prefix(&resp).expect("FipsVersionResp 파싱 실패");

    println!("  mode     : 0x{:08x}", ver.mode);
    println!(
        "  fips_rev : {}.{}.{}",
        ver.fips_rev[0], ver.fips_rev[1], ver.fips_rev[2]
    );
    println!(
        "  name     : {}",
        String::from_utf8_lossy(&ver.name).trim_end_matches('\0')
    );
    println!("  → OK");
}

fn test_fw_info(model: &mut DefaultHwModel) {
    println!("\n─── [2] FW INFO (0x{:08x}) ───", u32::from(CommandId::FW_INFO));
    let resp = send_cmd(model, CommandId::FW_INFO, &[]);
    let (info, _) = FwInfoResp::ref_from_prefix(&resp).expect("FwInfoResp 파싱 실패");

    println!("  fw_svn          : {}", info.fw_svn);
    println!("  attestation_dis : {}", info.attestation_disabled != 0);
    println!("  pqc_type        : {}", info.image_manifest_pqc_type);
    println!("  rom_revision    : {}", bytes_to_hex(&info.rom_revision));
    println!("  fmc_revision    : {}", bytes_to_hex(&info.fmc_revision));
    println!("  runtime_revision: {}", bytes_to_hex(&info.runtime_revision));
    println!("  → OK");
}

fn test_ldev_cert(model: &mut DefaultHwModel) {
    println!(
        "\n─── [3] GET_LDEV_ECC384_CERT (0x{:08x}) ───",
        u32::from(CommandId::GET_LDEV_ECC384_CERT)
    );
    let resp = send_cmd(model, CommandId::GET_LDEV_ECC384_CERT, &[]);
    let cert = parse_var_resp(&resp);

    println!("  크기           : {} bytes", cert.len());
    println!("  DER 앞 16바이트: {}", bytes_to_hex(&cert[..16.min(cert.len())]));
    assert_eq!(cert[0], 0x30, "DER SEQUENCE 태그(0x30)가 아님");
    println!("  → OK (DER SEQUENCE 확인)");
}

fn test_fmc_alias_cert(model: &mut DefaultHwModel) {
    println!(
        "\n─── [4] GET_FMC_ALIAS_ECC384_CERT (0x{:08x}) ───",
        u32::from(CommandId::GET_FMC_ALIAS_ECC384_CERT)
    );
    let resp = send_cmd(model, CommandId::GET_FMC_ALIAS_ECC384_CERT, &[]);
    let cert = parse_var_resp(&resp);

    println!("  크기           : {} bytes", cert.len());
    println!("  DER 앞 16바이트: {}", bytes_to_hex(&cert[..16.min(cert.len())]));
    assert_eq!(cert[0], 0x30, "DER SEQUENCE 태그(0x30)가 아님");
    println!("  → OK (DER SEQUENCE 확인)");
}

fn test_rt_alias_cert(model: &mut DefaultHwModel) {
    println!(
        "\n─── [5] GET_RT_ALIAS_ECC384_CERT (0x{:08x}) ───",
        u32::from(CommandId::GET_RT_ALIAS_ECC384_CERT)
    );
    let resp = send_cmd(model, CommandId::GET_RT_ALIAS_ECC384_CERT, &[]);
    let cert = parse_var_resp(&resp);

    println!("  크기           : {} bytes", cert.len());
    println!("  DER 앞 16바이트: {}", bytes_to_hex(&cert[..16.min(cert.len())]));
    assert_eq!(cert[0], 0x30, "DER SEQUENCE 태그(0x30)가 아님");
    println!("  → OK (DER SEQUENCE 확인)");
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() {
    let rom_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/caliptra-rom-with-log.bin".into());
    let fw_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp/caliptra-fw.bin".into());

    let rom = std::fs::read(&rom_path)
        .unwrap_or_else(|_| panic!("ROM 파일을 열 수 없음: {rom_path}"));
    let fw = std::fs::read(&fw_path)
        .unwrap_or_else(|_| panic!("FW 파일을 열 수 없음: {fw_path}"));

    println!("ROM : {rom_path} ({} bytes)", rom.len());
    println!("FW  : {fw_path} ({} bytes)", fw.len());
    eprintln!("\n[boot log → stderr]\n");

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            log_writer: Box::new(std::io::stderr()),
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&fw),
            ..Default::default()
        },
    )
    .expect("Caliptra 부팅 실패");

    println!("부팅 완료 — mailbox 통신 테스트 시작");

    test_fips_version(&mut model);
    test_fw_info(&mut model);
    test_ldev_cert(&mut model);
    test_fmc_alias_cert(&mut model);
    test_rt_alias_cert(&mut model);

    println!("\n✓ 모든 명령 성공");
}
