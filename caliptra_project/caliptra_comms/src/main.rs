mod certs;
mod crypto;
mod info;
mod pcr;
mod runner;

use runner::Status;
use caliptra_hw_model::{BootParams, InitParams};

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

    let categories: &[(&str, Vec<runner::TestResult>)] = &[
        ("Info / Status",  info::run_all(&mut model)),
        ("Certificates",   certs::run_all(&mut model)),
        ("PCR / Measurements", pcr::run_all(&mut model)),
        ("Crypto Verify",  crypto::run_all()),
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
