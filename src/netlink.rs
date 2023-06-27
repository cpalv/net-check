use core::fmt;

use std::ffi;
use std::io;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{mem, ptr, vec};

use nix::libc;

use nix::libc::{
    AF_INET, AF_NETLINK, AF_UNSPEC, ARPHRD_NETROM, IFLA_EXT_MASK, IFLA_IFNAME, NETLINK_ROUTE,
    NLMSG_DONE, NLMSG_ERROR, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_TABLE,
    RTM_DELROUTE, RTM_GETLINK, RTM_GETROUTE, RTM_NEWROUTE, RTM_SETLINK, RTN_UNICAST, RTN_UNSPEC,
    RTPROT_KERNEL, RTPROT_UNSPEC, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE,
    RT_TABLE_MAIN, RT_TABLE_UNSPEC, SOCK_CLOEXEC, SOCK_RAW,
};
use packed_struct::{prelude::PackedStruct, PackedStructInfo, PackingError};

use crate::map_err_str;

use crate::buffer::{transmute_vec, Buffer, ByteBuffer};

pub const NLMSG_HDR_SZ: usize = mem::size_of::<nlmsghdr>();
pub const NLGMSG_ERR_SZ: usize = mem::size_of::<nlmsgerr>();
pub const RTMMSG_SZ: usize = mem::size_of::<rtmsg>();
pub const IFINFO_SZ: usize = mem::size_of::<ifinfomsg>();
pub const NLA_SZ: usize = mem::size_of::<nlattr>();
pub const ISIZE_SZ: usize = mem::size_of::<isize>();
pub const USIZE_SZ: usize = mem::size_of::<usize>();
pub const U32_SZ: usize = mem::size_of::<u32>();
pub const U16_SZ: usize = mem::size_of::<u16>();
pub const U8_SZ: usize = mem::size_of::<u8>();

#[macro_export]
macro_rules! trust_fall {
    ($e:expr) => {
        unsafe { $e }
    };
}

// HACKS: vars/functions redefined here to make the compiler happy
// https://docs.rs/libc/latest/src/libc/unix/linux_like/linux/mod.rs.html#2885-2886
const NLA_ALIGNTO: i32 = 4;

// https://docs.rs/libc/latest/src/libc/unix/linux_like/linux/mod.rs.html#3926-3928
pub const fn rust_nla_align(len: i32) -> i32 {
    ((len) + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

const NLMSG_ALIGNTO: u32 = 4;

pub const fn rust_nlmsg_align(len: u32) -> u32 {
    ((len) + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

pub const fn rust_is_nlmsg_aligned(len: u32) -> bool {
    (NLMSG_HDR_SZ + (len as usize)) % 4 == 0
}

const SLACK: usize = 3;

fn fun<O: ToString>(_op: O) -> PackingError {
    PackingError::InternalError
}

#[derive(Debug, Clone)]
pub enum RecvErr {
    OsErr(String),
    MsgTrunc,
}

impl fmt::Display for RecvErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OsErr(s) => write!(f, "{s}"),
            Self::MsgTrunc => write!(f, "Message truncated"),
        }
    }
}

#[derive(Debug)]
pub struct NetlinkSocket {
    descriptor: i32,
    sa: libc::sockaddr_nl,
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        // SAFETY:
        // drop (close) may only be called once
        // see section "Deal with error returns from close"
        // https://man7.org/linux/man-pages/man2/close.2.html
        if trust_fall!(libc::close(self.descriptor)) < 0 {
            eprintln!("error dropping {self:?}: {}", io::Error::last_os_error());
            return;
        }
    }
}

impl NetlinkSocket {
    pub fn new() -> io::Result<Self> {
        let sfd = trust_fall!(libc::socket(
            AF_NETLINK,
            SOCK_RAW | SOCK_CLOEXEC,
            NETLINK_ROUTE
        ));
        if sfd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY:
        // safe since libc::sockaddr_nl contains no pointer fields
        // and therefore no null ptr dereference can occur
        //
        // ```
        // println!("addr of null: {:p}", std::ptr::null::<usize>());
        // ```
        let mut sa: libc::sockaddr_nl = trust_fall!(mem::zeroed());
        sa.nl_family = AF_NETLINK as u16;

        Ok(Self {
            descriptor: sfd,
            sa: sa,
        })
    }

    pub fn bind(&self) -> io::Result<&Self> {
        let rc = trust_fall!(libc::bind(
            self.descriptor,
            ptr::addr_of!(self.sa).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_nl>() as u32,
        ));

        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(self)
    }

    pub fn sendto(&self, v: Vec<u8>, flags: i32) -> io::Result<&Self> {
        let rc = trust_fall!(libc::sendto(
            self.descriptor,
            v.as_ptr().cast::<ffi::c_void>(),
            v.len() * SLACK,
            flags,
            ptr::null::<libc::sockaddr>(),
            0,
        ));

        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(self)
    }

    pub fn recvmsg(&self, msghdr: *mut libc::msghdr, flags: i32) -> Result<usize, RecvErr> {
        let len = trust_fall!(libc::recvmsg(self.descriptor, msghdr, flags));
        if len < 0 {
            return Err(RecvErr::OsErr(io::Error::last_os_error().to_string()));
        }

        if trust_fall!((*msghdr).msg_flags) == libc::MSG_TRUNC {
            return Err(RecvErr::MsgTrunc);
        }

        Ok(len as usize)
    }

    pub fn create_msg<B: Buffer>(&mut self, msgbuf: &mut B) -> libc::msghdr {
        let mut iov = libc::iovec {
            iov_base: msgbuf.buf_mut_ptr().cast::<ffi::c_void>(),
            iov_len: msgbuf.sz(),
        };

        libc::msghdr {
            msg_name: ptr::addr_of_mut!(self.sa) as *mut ffi::c_void,
            msg_namelen: mem::size_of::<libc::sockaddr_nl>() as u32,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ptr::null_mut::<ffi::c_void>(),
            msg_controllen: 0,
            msg_flags: 0,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NlmsgType {
    RtmGetLink = RTM_GETLINK,
    RtmSetLink = RTM_SETLINK,
    RtmGetRoute = RTM_GETROUTE,
    RtmAddRoute = RTM_NEWROUTE,
    RtmDelRoute = RTM_DELROUTE,
    NlmsgError = NLMSG_ERROR as u16,
    NlmsgDone = NLMSG_DONE as u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

impl PackedStructInfo for nlmsghdr {
    fn packed_bits() -> usize {
        NLMSG_HDR_SZ * 8
    }
}

impl PackedStruct for nlmsghdr {
    type ByteArray = [u8; NLMSG_HDR_SZ];
    fn pack(&self) -> packed_struct::PackingResult<Self::ByteArray> {
        let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();
        bb.build(self.nlmsg_len.to_ne_bytes())
            .map_err(fun)?
            .build(self.nlmsg_type.to_ne_bytes())
            .map_err(fun)?
            .build(self.nlmsg_flags.to_ne_bytes())
            .map_err(fun)?
            .build(self.nlmsg_seq.to_ne_bytes())
            .map_err(fun)?
            .build(self.nlmsg_pid.to_ne_bytes())
            .map_err(fun)?;

        Ok(bb.buf)
    }

    fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
        let mut tmp = Self::default();

        let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();

        bb.build(*src).map_err(fun)?;

        tmp.nlmsg_len = u32::from_ne_bytes(bb.gib_buf::<U32_SZ>().map_err(fun)?);

        tmp.nlmsg_type = u16::from_ne_bytes(bb.gib_buf::<U16_SZ>().map_err(fun)?);

        tmp.nlmsg_flags = u16::from_ne_bytes(bb.gib_buf::<U16_SZ>().map_err(fun)?);

        tmp.nlmsg_seq = u32::from_ne_bytes(bb.gib_buf::<U32_SZ>().map_err(fun)?);

        tmp.nlmsg_pid = u32::from_ne_bytes(bb.gib_buf::<U32_SZ>().map_err(fun)?);

        Ok(tmp)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct nlmsgerr {
    pub error: isize,
    pub msg: nlmsghdr,
    /*
     * followed by the message contents unless NETLINK_CAP_ACK was set
     * or the ACK indicates success (error == 0)
     * message length is aligned with NLMSG_ALIGN()
     */
    /*
     * followed by TLVs defined in enum nlmsgerr_attrs
     * if NETLINK_EXT_ACK was set
     */
}

impl PackedStructInfo for nlmsgerr {
    fn packed_bits() -> usize {
        (mem::size_of::<isize>() + NLMSG_HDR_SZ) * 8
    }
}

impl PackedStruct for nlmsgerr {
    type ByteArray = [u8; NLGMSG_ERR_SZ];
    fn pack(&self) -> packed_struct::PackingResult<Self::ByteArray> {
        let mut bb = ByteBuffer::<NLGMSG_ERR_SZ>::new();
        bb.build(self.error.to_ne_bytes())
            .map_err(fun)?
            .build(self.msg.pack()?)
            .map_err(fun)?;

        Ok(bb.buf)
    }

    fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
        let mut tmp = Self::default();

        let mut bb = ByteBuffer::<NLGMSG_ERR_SZ>::new();

        bb.build(*src).map_err(fun)?;

        tmp.error = isize::from_ne_bytes(bb.gib_buf::<ISIZE_SZ>().map_err(fun)?);

        tmp.msg = nlmsghdr::unpack(&bb.gib_buf::<NLMSG_HDR_SZ>().map_err(fun)?)?;

        Ok(tmp)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RtnType {
    Unspecified = RTN_UNSPEC,
    Unicast = RTN_UNICAST,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RtmProtocol {
    Kernel = RTPROT_KERNEL,
    Dhcp = 16,
    Unspecified = RTPROT_UNSPEC,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RtScope {
    Link = RT_SCOPE_LINK,
    Universe = RT_SCOPE_UNIVERSE,
    Nowhere = RT_SCOPE_NOWHERE,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RtTable {
    Unspecified = RT_TABLE_UNSPEC,
    Main = RT_TABLE_MAIN,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PackedStruct)]
pub struct rtmsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    #[packed_field(endian = "lsb")]
    pub rtm_flags: u32,
}

#[repr(u16)]
#[derive(Debug)]
pub enum NlaType {
    RtaTable = RTA_TABLE,
    RtaPriority = RTA_PRIORITY,
    RtaGateway = RTA_GATEWAY,
    RtaDestination = RTA_DST,
    RtaPrefSource = RTA_PREFSRC,
    RtaOIF = RTA_OIF,
    IflaExtMask = IFLA_EXT_MASK,
    IflaIfname = IFLA_IFNAME,
}

#[derive(Debug, Clone, Copy)]
pub enum NlaPolicyError {
    Invalid,
}

impl fmt::Display for NlaPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(f, "NLA is invalid"),
        }
    }
}

pub trait NlaPolicyValidator {
    fn validate(&self, nla: &nlattr) -> Result<(), NlaPolicyError>;
}

#[derive(Clone, Copy, Debug)]
pub struct NlaPolicy {
    max_len: usize,
}

impl NlaPolicyValidator for NlaPolicy {
    fn validate(&self, nla: &nlattr) -> Result<(), NlaPolicyError> {
        if (nla.nla_len as usize) > self.max_len {
            return Err(NlaPolicyError::Invalid);
        }
        Ok(())
    }
}

/*****************************************************************
 *		Link layer specific messages.
 ****/

/* struct ifinfomsg
 * passes link level specific information, not dependent
 * on network protocol.
 */

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct ifinfomsg {
    pub ifi_family: u8,
    pub __ifi_pad: u8,
    pub ifi_type: u16,   /* ARPHRD_* */
    pub ifi_index: u32,  /* Link index	*/
    pub ifi_flags: i16,  /* IFF_* flags	*/
    pub ifi_change: i16, /* IFF_* change mask */
    pub __ifi_pad2: u32, // 4 bytes of pad
}

impl PackedStructInfo for ifinfomsg {
    fn packed_bits() -> usize {
        IFINFO_SZ * 8
    }
}

impl PackedStruct for ifinfomsg {
    type ByteArray = [u8; IFINFO_SZ];
    fn pack(&self) -> packed_struct::PackingResult<Self::ByteArray> {
        let mut bb = ByteBuffer::<IFINFO_SZ>::new();
        bb.build(self.ifi_family.to_ne_bytes())
            .map_err(fun)?
            .build(self.__ifi_pad.to_ne_bytes())
            .map_err(fun)?
            .build(self.ifi_type.to_ne_bytes())
            .map_err(fun)?
            .build(self.ifi_index.to_ne_bytes())
            .map_err(fun)?
            .build(self.ifi_flags.to_ne_bytes())
            .map_err(fun)?
            .build(self.ifi_change.to_ne_bytes())
            .map_err(fun)?
            .build(self.__ifi_pad2.to_ne_bytes())
            .map_err(fun)?;

        Ok(bb.buf)
    }

    fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
        let mut tmp = Self::default();

        let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();

        bb.build(*src).map_err(fun)?;

        tmp.ifi_family = bb.gib_checked::<u8>().map_err(fun)?;

        tmp.__ifi_pad = bb.gib_checked::<u8>().map_err(fun)?;

        tmp.ifi_type = bb.gib_checked::<u16>().map_err(fun)?;

        tmp.ifi_index = bb.gib_checked::<u32>().map_err(fun)?;

        tmp.ifi_flags = bb.gib_checked::<i16>().map_err(fun)?;

        tmp.ifi_change = bb.gib_checked::<i16>().map_err(fun)?;

        tmp.__ifi_pad2 = bb.gib_checked::<u32>().map_err(fun)?;

        Ok(tmp)
    }
}

#[derive(Debug)]
pub struct Route {
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub rt_priority: u8,
    pub rta_dst: Ipv4Addr,
    pub rta_gwy: Ipv4Addr,
    pub rta_oif: u32,
}

impl Default for Route {
    fn default() -> Self {
        Self {
            table: 0,
            protocol: 0,
            scope: 0,
            rt_priority: 0,
            rta_dst: Ipv4Addr::new(0, 0, 0, 0),
            rta_gwy: Ipv4Addr::new(0, 0, 0, 0),
            rta_oif: 0,
        }
    }
}

#[derive(Debug)]
pub struct NlAtterData {
    nla: nlattr,
    data: Vec<u8>,
}

// Generic parser for netlink attributes arrays
pub fn parse_nlas<F: Sized + NlaPolicyValidator, B: Buffer>(
    remaining_msg_bytes: &mut i64,
    msgbuf: &mut B,
    nlavp: Option<&F>,
) -> Result<Vec<NlAtterData>, String> {
    let mut v = Vec::new();
    while *remaining_msg_bytes > 0 {
        let nla = msgbuf.gib_please::<nlattr>()?;

        if nlavp.is_some() {
            map_err_str!(nlavp.unwrap().validate(&nla))?;
        }

        let nla_payload_bytes = (nla.nla_len - NLA_SZ as u16) as usize;

        let nlad = NlAtterData {
            nla: nla,
            data: msgbuf.gib_vec(nla_payload_bytes)?,
        };

        let aligned_payload = rust_nla_align(nla_payload_bytes as i32);

        msgbuf.incr((aligned_payload as usize) - nla_payload_bytes);

        v.push(nlad);

        *remaining_msg_bytes -= ((NLA_SZ as i32) + aligned_payload) as i64;
    }

    Ok(v)
}

// https://man7.org/linux/man-pages/man7/netlink.7.html#EXAMPLES
pub fn parse_msg<F: Sized + NlaPolicyValidator, B: Buffer>(
    msgbuf: &mut B,
    nlavp: Option<&F>,
) -> Result<Route, String> {
    let nlhr = map_err_str!(nlmsghdr::unpack(&msgbuf.gib_buf::<NLMSG_HDR_SZ>()?))?;

    if nlhr.nlmsg_type == NlmsgType::NlmsgError as u16 {
        let nle = map_err_str!(nlmsgerr::unpack(&msgbuf.gib_buf::<NLGMSG_ERR_SZ>()?))?;
        return Err(format!("net link message error: {nle:?}"));
    }
    let rtm = map_err_str!(rtmsg::unpack(&msgbuf.gib_buf::<RTMMSG_SZ>()?))?;

    // parse remaining nlattr structs
    let msg_bytes = nlhr.nlmsg_len as i64;
    let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + RTMMSG_SZ) as i64);

    let mut rt = Route {
        scope: rtm.rtm_scope,
        table: rtm.rtm_table,
        protocol: rtm.rtm_protocol,
        ..Default::default()
    };

    let nlas = parse_nlas(&mut remaining_msg_bytes, msgbuf, nlavp)?;

    for nla in nlas {
        match nla.nla.nla_type {
            RTA_TABLE => {
                rt.table = *nla.data.first().unwrap();
            }
            RTA_PRIORITY => {
                rt.rt_priority = *nla.data.first().unwrap();
            }
            RTA_GATEWAY => {
                rt.rta_gwy = Ipv4Addr::new(nla.data[0], nla.data[1], nla.data[2], nla.data[3]);
            }
            RTA_DST => {
                rt.rta_dst = Ipv4Addr::new(nla.data[0], nla.data[1], nla.data[2], nla.data[3]);
            }
            RTA_OIF => {
                rt.rta_oif = u32::from_ne_bytes(transmute_vec::<U32_SZ>(&nla.data)?);
            }
            _ => {}
        }
    }

    Ok(rt)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PackedStruct)]
#[packed_struct(endian = "lsb")]
pub struct nlattr {
    pub nla_len: u16,
    pub nla_type: u16,
    /*#[packed_field(element_size_bytes = "2")]
    pub nla_type: NlaType,*/
}

pub fn create_nlattrs(nla_data: Vec<(NlaType, Vec<u8>)>) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    for (nla_type, bytes) in nla_data {
        let nla_total_len = rust_nla_align((NLA_SZ + bytes.len()) as i32) as usize;
        let nla_pad = nla_total_len - (NLA_SZ + bytes.len());

        let nla = nlattr {
            nla_len: nla_total_len as u16,
            nla_type: nla_type as u16,
        };

        v.append(
            &mut nla
                .pack()
                .map_err(|e| format!("{e}: error converting nlattr to bytes"))?
                .to_vec(),
        );
        v.append(&mut bytes.clone());
        v.append(&mut vec![0; nla_pad]);
    }

    let nla_pad = (rust_nla_align(v.len() as i32) as usize) - v.len();
    v.append(&mut vec![0; nla_pad]);

    Ok(v)
}

pub fn create_nlmsg<B: Buffer>(sa: &mut libc::sockaddr_nl, msgbuf: &mut B) -> libc::msghdr {
    let mut iov = libc::iovec {
        iov_base: msgbuf.buf_mut_ptr().cast::<ffi::c_void>(),
        iov_len: msgbuf.sz(),
    };

    libc::msghdr {
        msg_name: sa as *mut _ as *mut ffi::c_void,
        msg_namelen: mem::size_of::<libc::sockaddr_nl>() as u32,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ptr::null_mut::<ffi::c_void>(),
        msg_controllen: 0,
        msg_flags: 0,
    }
}

pub fn create_ifirequest(
    nlmsg_type: NlmsgType,
    nlmsg_flags: u16,
    if_type: u16,
    if_idx: u32,
    if_flags: i16,
    if_change: i16,
    nla_data: Vec<(NlaType, Vec<u8>)>,
) -> Result<Vec<u8>, String> {
    let ifm = ifinfomsg {
        ifi_family: AF_UNSPEC as u8,
        __ifi_pad: 0,
        ifi_type: if_type,
        ifi_index: if_idx,
        ifi_flags: if_flags,
        ifi_change: if_change,
        __ifi_pad2: 0,
    };

    let mut nlas = create_nlattrs(nla_data)?;

    let msg_buf_len: usize =
        (rust_nlmsg_align((NLMSG_HDR_SZ + IFINFO_SZ) as u32) as usize) + nlas.len();

    let nh = nlmsghdr {
        nlmsg_len: map_err_str!(u32::try_from(msg_buf_len))?,
        nlmsg_type: nlmsg_type as u16,
        nlmsg_flags,
        nlmsg_seq: map_err_str!(u32::try_from(
            map_err_str!(SystemTime::now().duration_since(UNIX_EPOCH))?.as_secs()
        ))?,
        nlmsg_pid: 0,
    };

    let mut fhv = Vec::new();
    if rust_is_nlmsg_aligned(map_err_str!(u32::try_from(IFINFO_SZ))?) {
        fhv.append(&mut map_err_str!(&mut nh.pack())?.to_vec());
        fhv.append(&mut map_err_str!(&mut ifm.pack())?.to_vec());
    } else {
        let total_family_header_len =
            rust_nlmsg_align(map_err_str!(u32::try_from(NLMSG_HDR_SZ + IFINFO_SZ))?) as usize;

        fhv.append(&mut map_err_str!(&mut nh.pack())?.to_vec());
        fhv.append(&mut map_err_str!(&mut ifm.pack())?.to_vec());
        let num_pad_bytes = total_family_header_len - fhv.len();
        fhv.append(&mut vec![0; num_pad_bytes]);
    }

    let mut v = Vec::new();
    v.append(&mut fhv);
    v.append(&mut nlas);

    Ok(v)
}

pub fn create_rtrequest(
    nlmsg_type: NlmsgType,
    nlmsg_flags: u16,
    rtm_dst_len: u8,
    rtm_type: RtnType,
    rtm_protocol: RtmProtocol,
    rtm_scope: RtScope,
    nla_data: Vec<(NlaType, Vec<u8>)>,
) -> Result<Vec<u8>, String> {
    let rt = rtmsg {
        rtm_family: map_err_str!(u8::try_from(AF_INET))?,
        rtm_dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,

        /*rtm_protocol: RTPROT_KERNEL,
        rtm_scope: RT_SCOPE_LINK,*/
        rtm_protocol: rtm_protocol as u8,
        rtm_scope: rtm_scope as u8,
        rtm_type: rtm_type as u8,

        rtm_flags: 0,
    };

    let mut nlas = create_nlattrs(nla_data)?;

    let msg_buf_len: usize =
        (rust_nlmsg_align((NLMSG_HDR_SZ + RTMMSG_SZ) as u32) as usize) + nlas.len();

    let nh = nlmsghdr {
        nlmsg_len: map_err_str!(u32::try_from(msg_buf_len))?,
        nlmsg_type: nlmsg_type as u16,
        nlmsg_flags,
        nlmsg_seq: map_err_str!(u32::try_from(
            map_err_str!(SystemTime::now().duration_since(UNIX_EPOCH))?.as_secs()
        ))?,
        nlmsg_pid: 0,
    };

    let mut fhv = Vec::new();
    if rust_is_nlmsg_aligned(map_err_str!(u32::try_from(RTMMSG_SZ))?) {
        fhv.append(&mut map_err_str!(&mut nh.pack())?.to_vec());
        fhv.append(&mut map_err_str!(&mut rt.pack())?.to_vec());
    } else {
        let total_family_header_len =
            rust_nlmsg_align(map_err_str!(u32::try_from(NLMSG_HDR_SZ + RTMMSG_SZ))?) as usize;

        fhv.append(&mut map_err_str!(&mut nh.pack())?.to_vec());
        fhv.append(&mut map_err_str!(&mut rt.pack())?.to_vec());
        let num_pad_bytes = total_family_header_len - fhv.len();
        fhv.append(&mut vec![0; num_pad_bytes]);
    }

    let mut v = Vec::new();
    v.append(&mut fhv);
    v.append(&mut nlas);

    Ok(v)
}
