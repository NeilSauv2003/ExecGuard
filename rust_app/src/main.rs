use std::process;

use neli::{
    consts::{
        socket::NlFamily,
        nl::{NlmFFlags, NlmF}
    },
    socket::NlSocketHandle,
    nl::{Nlmsghdr, NlPayload},
    genl::{Genlmsghdr, Nlattr},
    types::{GenlBuffer, Buffer},
    neli_enum,
};

const FAMILY_NAME: &str = "execguard";
const TARGET_PID: u32 = 4242;

#[neli_enum(serialized_type = "u8")]
pub enum NlUserCommand {
    Unspec = 0,
    SendPid = 1,
    SuccessCheck = 2,
}

impl neli::consts::genl::Cmd for NlUserCommand {}

#[neli_enum(serialized_type = "u16")]
pub enum NlUserAttribute {
    Unspec = 0,
    Pid = 1,
}
impl neli::consts::genl::NlAttrType for NlUserAttribute {}

fn request_response() {
    let mut socket = NlSocketHandle::connect(
        NlFamily::Generic,
        None,
        &[],
    ).expect("Error socket creation");

    let family_id;
    match socket.resolve_genl_family(FAMILY_NAME) {
        Ok(id) => family_id = id,
        Err(e) => {
            eprint!("Family '{}' can't be found! Error: {}", FAMILY_NAME, e);
            return;
        }
    };

    println!("Family ID: {}", family_id);

    let mut attrs: GenlBuffer<NlUserAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            NlUserAttribute::Pid,
            TARGET_PID,
        )
        .unwrap(),
    );

    let gnmsghdr = Genlmsghdr::new(
        NlUserCommand::SendPid,
        1,
        attrs,
    );

    let nlmsghdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        Some(process::id()),
        NlPayload::Payload(gnmsghdr),
    );

    println!("[User-Rust]: Sending '{}' via netlink", TARGET_PID);

    socket.send(nlmsghdr).expect("Send must work");
}

fn main() {
    request_response()
}
