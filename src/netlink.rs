use std::ffi::c_void;
use std::{mem, ptr, vec};

use nix::libc::{
    iovec, msghdr, sockaddr_nl, NLMSG_ERROR, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PREFSRC,
    RTA_PRIORITY, RTA_TABLE, RTM_DELROUTE, RTM_GETROUTE, RTM_NEWROUTE, RTN_UNICAST, RTN_UNSPEC,
    RTPROT_KERNEL, RTPROT_UNSPEC, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE,
    RT_TABLE_MAIN, RT_TABLE_UNSPEC,
};
use packed_struct::{prelude::PackedStruct, PackedStructInfo, PackingError};

pub const NLMSG_HDR_SZ: usize = mem::size_of::<nlmsghdr>();
pub const RTMMSG_SZ: usize = mem::size_of::<rtmsg>();
pub const NLA_SZ: usize = mem::size_of::<nlattr>();
pub const U32_SZ: usize = mem::size_of::<u32>();
pub const U16_SZ: usize = mem::size_of::<u16>();

#[macro_export]
macro_rules! trust_fall {
        ($($e:expr)+) => {
            unsafe { $($e)+ }
        };
    }

pub fn transmute_vec<const NUM_BYTES: usize>(v: Vec<u8>) -> Result<[u8; NUM_BYTES], String> {
    let mut scratch = [0; NUM_BYTES];
    match v.len() {
        U16_SZ | U32_SZ | NLMSG_HDR_SZ | RTMMSG_SZ => {
            for (i, byte) in v.iter().enumerate() {
                scratch[i] = *byte;
            }
            Ok(scratch)
        }
        _ => Err(String::from("Cannot transmute byte vector to byte array")),
    }
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

fn fun<O: ToString>(_op: O) -> PackingError {
    PackingError::InternalError
}

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum NlmsgType {
    RtmGetRoute = RTM_GETROUTE,
    RtmAddRoute = RTM_NEWROUTE,
    RtmDelRoute = RTM_DELROUTE,
    NlmsgError = NLMSG_ERROR as u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
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
        let mut tmp = nlmsghdr::default();

        let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();

        bb.build(*src).map_err(fun)?;
        bb.reset();

        tmp.nlmsg_len = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

        tmp.nlmsg_type = u16::from_ne_bytes(bb.take_buf::<U16_SZ>().map_err(fun)?);

        tmp.nlmsg_flags = u16::from_ne_bytes(bb.take_buf::<U16_SZ>().map_err(fun)?);

        tmp.nlmsg_seq = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

        tmp.nlmsg_pid = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

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
    Kernel = RTPROT_KERNEL as u8,
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
#[derive(Debug, Default, PackedStruct)]
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
}

#[repr(C)]
#[derive(Debug, PackedStruct)]
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
        let nla = nlattr {
            nla_len: (NLA_SZ + bytes.len()) as u16,
            nla_type: nla_type as u16,
        }
        .pack()
        .map_err(|e| String::from(format!("{}: error converting nlattr to bytes", e)))?;

        v.append(&mut nla.to_vec());
        v.append(&mut bytes.to_vec());
    }

    let nla_pad = (rust_nla_align(v.len() as i32) as usize) - v.len();
    v.append(&mut vec![0; nla_pad]);

    Ok(v)
}

pub fn create_nlmsg(sa: &mut sockaddr_nl, msgbuf: &mut ByteVec) -> msghdr {
    let mut iov = iovec {
        iov_base: msgbuf.buf_mut_ptr() as *mut c_void,
        iov_len: msgbuf.sz(),
    };

    let mhdr = msghdr {
        msg_name: sa as *mut _ as *mut c_void,
        msg_namelen: mem::size_of::<sockaddr_nl>() as u32,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ptr::null_mut::<c_void>(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    mhdr
}

#[derive(Debug)]
pub struct ByteBuffer<const TOTAL_SZ: usize> {
    current_idx: usize,
    build_idx: usize,
    buf: [u8; TOTAL_SZ],
}

impl<const TOTAL_SZ: usize> ByteBuffer<TOTAL_SZ> {
    pub fn new() -> Self {
        Self {
            current_idx: 0,
            build_idx: 0,
            buf: [0; TOTAL_SZ],
        }
    }

    pub fn build<const BUF_LEN: usize>(
        &mut self,
        added_buf: [u8; BUF_LEN],
    ) -> Result<&mut Self, String> {
        if self.build_idx + added_buf.len() > TOTAL_SZ {
            return Err(String::from("Exceeded buffer capacity"));
        } else {
            for byte in added_buf {
                self.buf[self.build_idx] = byte;
                self.build_idx += 1;
            }
        }
        Ok(self)
    }

    pub fn buf_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    pub fn idx(&self) -> usize {
        self.current_idx
    }

    pub fn incr(&mut self, num_bytes: usize) {
        self.current_idx += num_bytes
    }

    pub fn ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub fn ptr_cast<T>(&mut self) -> Result<*const T, String> {
        let bytes = mem::size_of::<T>();
        if self.current_idx + bytes > TOTAL_SZ {
            return Err(String::from("ptr ran off the highway"));
        }
        let ok = Ok(unsafe { self.buf.as_ptr().offset(self.current_idx as isize) } as *const T);
        self.current_idx += bytes;
        ok
    }

    pub fn transmute_to<T: Copy>(&mut self) -> Result<T, String> {
        let pt = self.ptr_cast::<T>()?;

        Ok(unsafe { *pt })
    }

    pub fn gib_buf(&self) -> &[u8; TOTAL_SZ] {
        &self.buf
    }

    pub fn reset(&mut self) {
        self.current_idx = 0
    }

    pub const fn sz(&self) -> usize {
        TOTAL_SZ
    }

    pub fn take_buf<const NUM_BYTES: usize>(&mut self) -> Result<[u8; NUM_BYTES], String> {
        let end_idx = self.current_idx + NUM_BYTES;
        if end_idx > TOTAL_SZ {
            return Err(String::from("End index exceeds buffer"));
        }

        let mut scratch: [u8; NUM_BYTES] = [0; NUM_BYTES];

        for (i, byte) in self.buf[self.current_idx..end_idx].iter().enumerate() {
            scratch[i] = *byte;
        }

        self.current_idx += NUM_BYTES;
        Ok(scratch)
    }

    pub fn take_vec(&mut self, num_bytes: usize) -> Result<Vec<u8>, String> {
        let end_idx = self.current_idx + num_bytes;
        if end_idx > TOTAL_SZ {
            return Err(String::from("End index exceeds buffer"));
        }

        let mut scratch = Vec::new();

        for byte in self.buf[self.current_idx..end_idx].iter() {
            scratch.push(*byte);
        }

        self.current_idx += num_bytes;
        Ok(scratch)
    }
}

#[derive(Debug)]
pub struct ByteVec {
    current_idx: usize,
    build_idx: usize,
    buf: Vec<u8>,
}

impl ByteVec {
    pub fn new(len: usize) -> Self {
        Self {
            current_idx: 0,
            build_idx: 0,
            buf: vec![0; len],
        }
    }

    pub fn build<const BUF_LEN: usize>(
        &mut self,
        added_buf: [u8; BUF_LEN],
    ) -> Result<&mut Self, String> {
        if self.build_idx + added_buf.len() > self.buf.len() {
            return Err(String::from("Exceeded buffer capacity"));
        } else {
            for byte in added_buf {
                self.buf[self.build_idx] = byte;
                self.build_idx += 1;
            }
        }
        Ok(self)
    }

    pub fn buf_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    pub fn idx(&self) -> usize {
        self.current_idx
    }

    pub fn incr(&mut self, num_bytes: usize) {
        self.current_idx += num_bytes
    }

    pub fn ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub fn ptr_cast<T>(&mut self) -> Result<*const T, String> {
        let bytes = mem::size_of::<T>();
        if self.current_idx + bytes > self.build_idx {
            return Err(String::from(format!(
                "No data beyond idx {} to cast",
                self.build_idx
            )));
        }
        let ok = Ok((unsafe { self.buf.as_ptr().add(self.current_idx) }) as *const T);
        self.current_idx += bytes;
        ok
    }

    pub fn gib_buf<const SZ: usize>(&self) -> &Vec<u8> {
        &self.buf
    }

    pub fn reset(&mut self) -> &mut Self {
        self.current_idx = 0;
        self
    }

    pub fn sz(&self) -> usize {
        self.buf.len()
    }

    pub fn transmute_to<T: Copy>(&mut self) -> Result<T, String> {
        let pt = self.ptr_cast::<T>()?;

        Ok(unsafe { *pt })
    }

    pub fn take_buf<const NUM_BYTES: usize>(&mut self) -> Result<[u8; NUM_BYTES], String> {
        let end_idx = self.current_idx + NUM_BYTES;
        if end_idx > self.buf.len() {
            return Err(String::from("End index exceeds buffer"));
        }

        let mut scratch: [u8; NUM_BYTES] = [0; NUM_BYTES];

        for (i, byte) in self.buf[self.current_idx..end_idx].iter().enumerate() {
            scratch[i] = *byte;
        }

        self.current_idx += NUM_BYTES;
        Ok(scratch)
    }

    pub fn take_vec(&mut self, num_bytes: usize) -> Result<Vec<u8>, String> {
        let end_idx = self.current_idx + num_bytes;
        if end_idx > self.buf.len() {
            return Err(String::from("End index exceeds buffer"));
        }

        let mut scratch = Vec::new();

        for byte in self.buf[self.current_idx..end_idx].iter() {
            scratch.push(*byte);
        }

        self.current_idx += num_bytes;
        Ok(scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Default, PackedStruct)]
    #[packed_struct(endian = "lsb")]
    pub struct ReferenceImpl {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    pub struct msgvec {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    impl PackedStructInfo for msgvec {
        fn packed_bits() -> usize {
            NLMSG_HDR_SZ * 8
        }
    }

    impl PackedStruct for msgvec {
        type ByteArray = [u8; NLMSG_HDR_SZ];
        fn pack(&self) -> packed_struct::PackingResult<Self::ByteArray> {
            let mut bb = ByteVec::new(NLMSG_HDR_SZ);
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

            Ok(transmute_vec::<NLMSG_HDR_SZ>(bb.buf).map_err(fun)?)
        }

        fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
            let mut tmp = msgvec::default();

            let mut bb = ByteVec::new(NLMSG_HDR_SZ);

            bb.build(*src).map_err(fun)?;

            tmp.nlmsg_len = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

            tmp.nlmsg_type = u16::from_ne_bytes(bb.take_buf::<U16_SZ>().map_err(fun)?);

            tmp.nlmsg_flags = u16::from_ne_bytes(bb.take_buf::<U16_SZ>().map_err(fun)?);

            tmp.nlmsg_seq = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

            tmp.nlmsg_pid = u32::from_ne_bytes(bb.take_buf::<U32_SZ>().map_err(fun)?);

            Ok(tmp)
        }
    }

    #[test]
    fn test_pack_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let r = ReferenceImpl {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        assert_eq!(n.pack().unwrap(), r.pack().unwrap())
    }

    #[test]
    fn test_unpack_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let bytes = n.pack().unwrap();

        assert_eq!(n, nlmsghdr::unpack(&bytes).unwrap())
    }

    #[test]
    fn test_pack_vec() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let r = ReferenceImpl {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        assert_eq!(n.pack().unwrap(), r.pack().unwrap())
    }

    #[test]
    fn test_unpack_vec() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let bytes = n.pack().unwrap();

        assert_eq!(n, nlmsghdr::unpack(&bytes).unwrap())
    }

    #[test]
    fn test_ptr_cast_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let mut bb = ByteBuffer::<32>::new();
        bb.build(n.pack().unwrap()).unwrap();

        let np = bb.ptr_cast::<nlmsghdr>().unwrap();

        assert_eq!(n, unsafe { *np })
    }

    #[test]
    fn test_transmute_buffer_to() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let mut bb = ByteBuffer::<32>::new();
        bb.build(n.pack().unwrap()).unwrap();

        let msg = bb.transmute_to::<nlmsghdr>().unwrap();

        assert_eq!(n, msg)
    }

    #[test]
    fn test_ptr_cast_vec() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let mut bb = ByteVec::new(32);
        bb.build(n.pack().unwrap()).unwrap();

        let np = bb.ptr_cast::<nlmsghdr>().unwrap();

        assert_eq!(n, unsafe { *np })
    }

    #[test]
    fn test_transmute_vec_to() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let n = nlmsghdr {
            nlmsg_len: 30,
            nlmsg_type: 5,
            nlmsg_flags: 10,
            nlmsg_seq: now,
            nlmsg_pid: 0,
        };

        let mut bb = ByteVec::new(32);
        bb.build(n.pack().unwrap()).unwrap();

        let msg = bb.transmute_to::<nlmsghdr>().unwrap();

        assert_eq!(n, msg)
    }
}
