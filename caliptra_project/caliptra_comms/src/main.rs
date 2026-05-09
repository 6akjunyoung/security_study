mod certs;
mod crypto;
mod info;
mod ocp_lock;
mod pcr;
mod runner;

use runner::Status;
use caliptra_hw_model::{BootParams, Fuses, InitParams};

fn main() {
    let rom_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/caliptra-rom-with-log.bin".into());
    let fw_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp/caliptra-fw.bin".into());

    let rom = std::fs::read(&rom_path)
        .unwrap_or_else(|_| panic!("cannot read ROM: {rom_path}"));
    let fw = std::fs::read(&fw_path)
        .unwrap_or_else(|_| panic!("cannot read FW: {fw_path}"));

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
    .expect("Caliptra boot failed");

    println!("\nBoot complete — running mailbox API tests\n");

    // Boot a second model in subsystem mode for OCP L.O.C.K. (requires subsystem_mode + ocp_lock_en).
    eprintln!("\n[OCP L.O.C.K. subsystem model → stderr]\n");
    let mut ocp_model = boot_ocp_lock_model(&rom, &fw);

    let categories: &[(&str, Vec<runner::TestResult>)] = &[
        ("Info / Status",      info::run_all(&mut model)),
        ("Certificates",       certs::run_all(&mut model)),
        ("PCR / Measurements", pcr::run_all(&mut model)),
        ("Crypto Verify",      crypto::run_all()),
        ("OCP L.O.C.K.",       ocp_lock::run_all(&mut ocp_model)),
    ];

    let col_w = 34usize;
    let sep = "─".repeat(col_w + 14);

    for (category, results) in categories {
        println!("┌{sep}┐");
        println!("│  {category:<width$}│", width = col_w + 12);
        println!("├{sep}┤");
        for r in results {
            let (tag, detail) = match &r.status {
                Status::Pass => ("PASS", String::new()),
                Status::Skip(reason) => ("SKIP", format!("({reason})")),
                Status::Fail(reason) => ("FAIL", format!("({reason})")),
            };
            println!("│  {:<col_w$}  {tag:<6}{detail}", r.name);
        }
        println!("└{sep}┘\n");
    }

    // Summary
    let all: Vec<_> = categories.iter().flat_map(|(_, r)| r.iter()).collect();
    let pass  = all.iter().filter(|r| matches!(r.status, Status::Pass)).count();
    let skip  = all.iter().filter(|r| matches!(r.status, Status::Skip(_))).count();
    let fail  = all.iter().filter(|r| matches!(r.status, Status::Fail(_))).count();
    println!("Total: {}  PASS={}  SKIP={}  FAIL={}", all.len(), pass, skip, fail);

    if fail > 0 {
        std::process::exit(1);
    }
}

/// Boot a second Caliptra model in subsystem mode with OCP L.O.C.K. enabled.
///
/// OCP L.O.C.K. commands require subsystem_mode + ocp_lock_en in InitParams.
/// Subsystem mode uses a different boot path (recovery interface) that requires a
/// valid SoC manifest signed with the same keys as the firmware.
///
/// A ROM callback is used to send OCP_LOCK_REPORT_HEK_METADATA during the ROM
/// cold_reset phase. Without this, `hek_available` stays false in persistent data
/// and INITIALIZE_MEK_SECRET / GENERATE_MEK return OCP_LOCK_HEK_UNAVAILABLE.
fn boot_ocp_lock_model(rom: &[u8], fw: &[u8]) -> caliptra_hw_model::DefaultHwModel {
    use caliptra_auth_man_gen::default_test_manifest::{DEFAULT_MCU_FW, default_test_soc_manifest};
    use caliptra_image_crypto::OsslCrypto;
    use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest};
    use zerocopy::{FromBytes, IntoBytes};

    // Parse ImageManifest from the firmware bundle (it is at offset 0).
    let (manifest, _) = ImageManifest::ref_from_prefix(fw)
        .expect("firmware too short to contain ImageManifest");

    // Compute vendor_pk_hash and owner_pk_hash the same way as image_pk_desc_hash().
    let vendor_pk_hash = bytes_to_be_words_48(
        &openssl::sha::sha384(manifest.preamble.vendor_pub_key_info.as_bytes()),
    );
    let owner_pk_hash = bytes_to_be_words_48(
        &openssl::sha::sha384(manifest.preamble.owner_pub_keys.as_bytes()),
    );

    // Firmware was built with --pqc-key-type 1 == MLDSA.
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;

    // Generate a valid SoC manifest signed with the default test keys (same as firmware).
    let soc_manifest_bytes = {
        let m = default_test_soc_manifest(&DEFAULT_MCU_FW, pqc_key_type, 0, OsslCrypto::default());
        m.as_bytes().to_vec()
    };

    // ROM callback: send OCP_LOCK_REPORT_HEK_METADATA during the cold_reset ROM phase.
    // This sets persistent_data.rom.ocp_lock_metadata.hek_available = true so that the
    // Runtime allows INITIALIZE_MEK_SECRET and GENERATE_MEK.
    // HekSeedState::Programmed = 0x1; seed = [0xABDE; 8] (non-empty, non-all-ones).
    let rom_callback: caliptra_hw_model::ModelCallback = Box::new(|model| {
        use caliptra_api::{calc_checksum, mailbox::CommandId};
        use caliptra_hw_model::HwModel;

        let cmd_id = u32::from(CommandId::OCP_LOCK_REPORT_HEK_METADATA);
        // extra: reserved(u32) + total_slots(u16) + active_slots(u16) + seed_state(u16=0x1) + _rsvd(u16)
        let mut extra = [0u8; 12];
        extra[4..6].copy_from_slice(&1u16.to_le_bytes());    // total_slots = 1
        extra[6..8].copy_from_slice(&1u16.to_le_bytes());    // active_slots = 1
        extra[8..10].copy_from_slice(&1u16.to_le_bytes());   // seed_state = 0x1 (Programmed)

        let chksum = calc_checksum(cmd_id, &extra);
        let mut payload = chksum.to_le_bytes().to_vec();
        payload.extend_from_slice(&extra);

        model.mailbox_execute(cmd_id, &payload)
            .expect("REPORT_HEK_METADATA ROM callback failed");
    });

    let mut init = InitParams {
        rom,
        log_writer: Box::new(std::io::sink()),
        subsystem_mode: true,
        ocp_lock_en: true,
        rom_callback: Some(rom_callback),
        ..Default::default()
    };
    init.fuses = Fuses {
        fuse_pqc_key_type: pqc_key_type as u32,
        vendor_pk_hash,
        owner_pk_hash,
        hek_seed: [0xABDE_u32; 8],
        ..Default::default()
    };

    caliptra_hw_model::new(
        init,
        BootParams {
            fw_image: Some(fw),
            soc_manifest: Some(&soc_manifest_bytes),
            mcu_fw_image: Some(&DEFAULT_MCU_FW),
            ..Default::default()
        },
    )
    .expect("OCP L.O.C.K. subsystem model boot failed")
}

/// Convert a 48-byte SHA384 digest to 12 big-endian u32 words (for fuse format).
fn bytes_to_be_words_48(bytes: &[u8; 48]) -> [u32; 12] {
    let words: [u32; 12] = zerocopy::transmute!(*bytes);
    words.map(|w| w.swap_bytes())
}
