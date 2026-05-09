use caliptra_api::{
    calc_checksum,
    mailbox::{CommandId, MailboxReqHeader, MailboxRespHeader},
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use zerocopy::IntoBytes;

pub enum Status {
    Pass,
    Skip(String),
    Fail(String),
}

pub struct TestResult {
    pub name: String,
    pub status: Status,
}

impl TestResult {
    pub fn pass(name: impl Into<String>) -> Self {
        Self { name: name.into(), status: Status::Pass }
    }
    pub fn skip(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { name: name.into(), status: Status::Skip(reason.into()) }
    }
    pub fn fail(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { name: name.into(), status: Status::Fail(reason.into()) }
    }
}

pub fn try_send(model: &mut DefaultHwModel, cmd: CommandId, extra: &[u8]) -> Result<Vec<u8>, String> {
    let cmd_u32 = u32::from(cmd);
    let chksum = calc_checksum(cmd_u32, extra);
    let hdr = MailboxReqHeader { chksum };
    let mut payload = hdr.as_bytes().to_vec();
    payload.extend_from_slice(extra);

    match model.mailbox_execute(cmd_u32, &payload) {
        Err(e) => Err(format!("{e:?}")),
        Ok(None) => Err("no response data".into()),
        Ok(Some(data)) => Ok(data),
    }
}

pub fn parse_var_resp(resp: &[u8]) -> Result<&[u8], String> {
    let hdr_size = core::mem::size_of::<MailboxRespHeader>(); // 8
    if resp.len() < hdr_size + 4 {
        return Err(format!("response too short ({} bytes)", resp.len()));
    }
    let data_size =
        u32::from_le_bytes(resp[hdr_size..hdr_size + 4].try_into().unwrap()) as usize;
    let end = hdr_size + 4 + data_size;
    if resp.len() < end {
        return Err(format!("data_size={data_size} overruns response len={}", resp.len()));
    }
    Ok(&resp[hdr_size + 4..end])
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
