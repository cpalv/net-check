use std::mem;

use crate::netlink::{LINKSTAT64_SZ, LINKSTAT_SZ, NLMSG_HDR_SZ, RTMMSG_SZ, U16_SZ, U32_SZ};

macro_rules! write_impl {
    () => {
        fn build<const BUF_LEN: usize>(
            &mut self,
            added_buf: [u8; BUF_LEN],
        ) -> Result<&mut Self, String> {
            if self.build_idx + added_buf.len() > self.buf.len() {
                return Err(format!("Exceeded buffer capacity"));
            }

            for byte in added_buf {
                self.buf[self.build_idx] = byte;
                self.build_idx += 1;
            }

            Ok(self)
        }

        fn buf_mut_ptr(&mut self) -> *mut u8 {
            self.buf.as_mut_ptr()
        }

        fn idx(&self) -> usize {
            self.current_idx
        }

        fn incr(&mut self, num_bytes: usize) -> &mut Self {
            self.current_idx += num_bytes;
            self
        }

        fn ptr(&self) -> *const u8 {
            self.buf.as_ptr()
        }

        // Non-strict (relaxed) casting useful for initializing inner buf
        // via FFI where the implementing struct cannot do book keeping
        fn ptr_cast<T>(&mut self, strict: bool) -> Result<*const T, String> {
            let bytes = mem::size_of::<T>();
            if strict {
                if self.current_idx + bytes > self.build_idx {
                    return Err(format!("No data beyond idx {} to cast", self.build_idx));
                }
            } else {
                if self.current_idx + bytes > self.buf.len() {
                    return Err(format!("ptr ran beyond allocated area"));
                }
            }

            let ok = Ok((unsafe { self.buf.as_ptr().add(self.current_idx) }).cast::<T>());
            self.current_idx += bytes;
            ok
        }

        fn reset(&mut self) -> &mut Self {
            self.current_idx = 0;
            self
        }

        fn sz(&self) -> usize {
            self.buf.len()
        }

        fn box_pup<T: Copy>(&mut self) -> Result<Box<T>, String> {
            let pt = self.ptr_cast::<T>(false)?;

            Ok(Box::<T>::new(unsafe { *pt }))
        }

        fn gib_buf<const NUM_BYTES: usize>(&mut self) -> Result<[u8; NUM_BYTES], String> {
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

        fn gib_vec(&mut self, num_bytes: usize) -> Result<Vec<u8>, String> {
            let end_idx = self.current_idx + num_bytes;
            if end_idx > self.buf.len() {
                return Err(String::from("End index exceeds buffer"));
            }

            let mut scratch = vec![0; num_bytes];

            for (i, byte) in self.buf[self.current_idx..end_idx].iter().enumerate() {
                scratch[i] = *byte;
            }

            self.current_idx += num_bytes;
            Ok(scratch)
        }

        fn gib<T: Copy>(&mut self, strict: bool) -> Result<T, String> {
            let ptr = self.ptr_cast::<T>(strict)?;
            Ok(unsafe { *ptr })
        }

        fn gib_byte(&mut self) -> Result<u8, String> {
            let ptr = self.ptr_cast::<u8>(true)?;
            Ok(unsafe { *ptr })
        }

        fn gib_snac(&mut self) -> Result<u16, String> {
            let ptr = self.ptr_cast::<u16>(true)?;
            Ok(unsafe { *ptr })
        }
    };
}

macro_rules! impl_buff {
    ($buf_sz:ident $struct_name:ident) => {
        impl<const $buf_sz: usize> Buffer for $struct_name<$buf_sz> {
            write_impl!();
        }
    };
    ($struct_name:ident) => {
        impl Buffer for $struct_name {
            write_impl!();
        }
    };
}

pub fn transmute_vec<const NUM_BYTES: usize>(s: &[u8]) -> Result<[u8; NUM_BYTES], String> {
    let mut scratch = [0; NUM_BYTES];
    match s.len() {
        U16_SZ | U32_SZ | NLMSG_HDR_SZ | RTMMSG_SZ | LINKSTAT_SZ | LINKSTAT64_SZ => {
            for (i, byte) in s.iter().enumerate() {
                scratch[i] = *byte;
            }
            Ok(scratch)
        }
        _ => Err(String::from("Cannot transmute byte vector to byte array")),
    }
}

pub trait Buffer {
    fn build<const BUF_LEN: usize>(
        &mut self,
        added_buf: [u8; BUF_LEN],
    ) -> Result<&mut Self, String>;

    fn buf_mut_ptr(&mut self) -> *mut u8;

    fn idx(&self) -> usize;

    fn incr(&mut self, num_bytes: usize) -> &mut Self;

    fn ptr(&self) -> *const u8;

    fn ptr_cast<T>(&mut self, strict: bool) -> Result<*const T, String>;

    fn box_pup<T: Copy>(&mut self) -> Result<Box<T>, String>;

    fn reset(&mut self) -> &mut Self;

    fn sz(&self) -> usize;

    fn gib_buf<const NUM_BYTES: usize>(&mut self) -> Result<[u8; NUM_BYTES], String>;

    fn gib_vec(&mut self, num_bytes: usize) -> Result<Vec<u8>, String>;

    // Non strict useful when inner buffer is initialization from FFI
    // since Buffer book keeping will not be able to track
    fn gib<T: Copy>(&mut self, strict: bool) -> Result<T, String>;

    fn gib_byte(&mut self) -> Result<u8, String>;

    fn gib_snac(&mut self) -> Result<u16, String>;
}

#[derive(Debug)]
pub struct ByteBuffer<const TOTAL_SZ: usize> {
    current_idx: usize,
    build_idx: usize,
    pub buf: [u8; TOTAL_SZ],
}

impl<const TOTAL_SZ: usize> ByteBuffer<TOTAL_SZ> {
    pub const fn new() -> Self {
        Self {
            current_idx: 0,
            build_idx: 0,
            buf: [0; TOTAL_SZ],
        }
    }
}

impl_buff!(TOTAL_SZ ByteBuffer);

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

    pub fn realloc(&mut self, mul: usize) -> &mut Self {
        let start_len = self.buf.len();
        self.buf.resize(start_len * mul, 0);
        self
    }
}

impl_buff!(ByteVec);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use packed_struct::{prelude::PackedStruct, PackingError};

    use crate::netlink::{nlmsghdr, NLMSG_HDR_SZ};

    fn fun<O: ToString>(_op: O) -> PackingError {
        PackingError::InternalError
    }

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

    impl packed_struct::PackedStructInfo for msgvec {
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

            Ok(transmute_vec::<NLMSG_HDR_SZ>(&bb.buf).map_err(fun)?)
        }

        fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
            let mut tmp = msgvec::default();

            let mut bb = ByteVec::new(NLMSG_HDR_SZ);

            bb.build(*src).map_err(fun)?;

            tmp.nlmsg_len = bb.gib_checked::<u32>().map_err(fun)?;

            tmp.nlmsg_type = bb.gib_checked::<u16>().map_err(fun)?;

            tmp.nlmsg_flags = bb.gib_checked::<u16>().map_err(fun)?;

            tmp.nlmsg_seq = bb.gib_checked::<u32>().map_err(fun)?;

            tmp.nlmsg_pid = bb.gib_checked::<u32>().map_err(fun)?;

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

        let np = bb.ptr_cast::<nlmsghdr>(true).unwrap();

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

        let msg = bb.box_pup::<nlmsghdr>().unwrap();

        assert_eq!(n, *(msg.as_ref()))
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

        let np = bb.ptr_cast::<nlmsghdr>(true).unwrap();

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

        let msg = bb.box_pup::<nlmsghdr>().unwrap();

        assert_eq!(n, *(msg.as_ref()))
    }
}
