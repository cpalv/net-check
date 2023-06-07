pub mod netlink {

    use std::mem;

    use packed_struct::{prelude::PackedStruct, PackedStructInfo, PackingError};

    pub const NLMSG_HDR_SZ: usize = mem::size_of::<nlmsghdr>();
    pub const RTMMSG_SZ: usize = mem::size_of::<rtmsg>();
    pub const NLA_SZ: usize = mem::size_of::<nlattr>();
    pub const U32_SZ: usize = mem::size_of::<u32>();
    pub const U16_SZ: usize = mem::size_of::<u16>();

    fn copy_bytes_to_u16(dst: &mut u16, src: [u8; 2]) {
        let mut scratch: [u8; 2] = [0; 2];

        for (i, byte) in src.iter().enumerate() {
            scratch[i] = *byte;
        }

        *dst = u16::from_ne_bytes(scratch);
    }

    fn copy_bytes_to_u32(dst: &mut u32, src: [u8; 4]) {
        let mut scratch: [u8; 4] = [0; 4];

        for (i, byte) in src.iter().enumerate() {
            scratch[i] = *byte;
        }

        *dst = u32::from_ne_bytes(scratch);
    }

    fn fun<O>(_op: O) -> PackingError {
        PackingError::InternalError
    }

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    pub struct nlmsghdr {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    impl PackedStructInfo for nlmsghdr {
        fn packed_bits() -> usize {
            NLMSG_HDR_SZ
        }
    }

    impl PackedStruct for nlmsghdr {
        type ByteArray = [u8; NLMSG_HDR_SZ];
        fn pack(&self) -> packed_struct::PackingResult<Self::ByteArray> {
            let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();
            bb.build(self.nlmsg_len.to_ne_bytes()).map_err(fun)?;
            bb.build(self.nlmsg_type.to_ne_bytes()).map_err(fun)?;
            bb.build(self.nlmsg_flags.to_ne_bytes()).map_err(fun)?;
            bb.build(self.nlmsg_seq.to_ne_bytes()).map_err(fun)?;
            bb.build(self.nlmsg_pid.to_ne_bytes()).map_err(fun)?;

            Ok(bb.buf)
        }

        fn unpack(src: &Self::ByteArray) -> packed_struct::PackingResult<Self> {
            let mut tmp = nlmsghdr::default();

            let mut bb = ByteBuffer::<NLMSG_HDR_SZ>::new();

            bb.build(*src).map_err(|_| PackingError::InternalError)?;

            let mut current_idx = 0;

            copy_bytes_to_u32(
                &mut tmp.nlmsg_len,
                bb.take_buf::<U32_SZ>(current_idx, U32_SZ).map_err(fun)?,
            );

            current_idx += U32_SZ;

            copy_bytes_to_u16(
                &mut tmp.nlmsg_type,
                bb.take_buf::<U16_SZ>(current_idx, U16_SZ).map_err(fun)?,
            );

            current_idx += U16_SZ;

            copy_bytes_to_u16(
                &mut tmp.nlmsg_flags,
                bb.take_buf::<U16_SZ>(current_idx, U16_SZ).map_err(fun)?,
            );

            current_idx += U16_SZ;

            copy_bytes_to_u32(
                &mut tmp.nlmsg_seq,
                bb.take_buf::<U32_SZ>(current_idx, U32_SZ).map_err(fun)?,
            );
            current_idx += U32_SZ;

            copy_bytes_to_u32(
                &mut tmp.nlmsg_pid,
                bb.take_buf::<U32_SZ>(current_idx, U32_SZ).map_err(fun)?,
            );

            Ok(tmp)
        }
    }

    #[derive(Debug, Default, PackedStruct)]
    #[repr(C)]
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

    #[derive(Debug, PackedStruct)]
    #[repr(C)]
    #[packed_struct(endian = "lsb")]
    pub struct nlattr {
        pub nla_len: u16,
        pub nla_type: u16,
    }

    //#[derive(Debug, PackedStruct)]
    #[derive(Debug)]
    #[repr(C)]
    pub struct Nlamsg<const N: usize> {
        pub hdr: nlattr,
        pub payload: [u8; N],
    }

    #[derive(Debug)]
    pub struct ByteBuffer<const N: usize> {
        current_idx: usize,
        total_sz: usize,
        buf: [u8; N],
    }

    impl<const N: usize> ByteBuffer<N> {
        pub fn new() -> Self {
            Self {
                current_idx: 0,
                total_sz: N,
                buf: [0; N],
            }
        }

        pub fn build<const J: usize>(&mut self, added_buf: [u8; J]) -> Result<(), String> {
            if self.current_idx + added_buf.len() > self.total_sz {
                return Err(String::from("Exceeded buffer capacity"));
            } else {
                for byte in added_buf {
                    self.buf[self.current_idx] = byte;
                    self.current_idx += 1;
                }
            }
            Ok(())
        }

        pub fn buf_mut_ptr(&mut self) -> *mut u8 {
            self.buf.as_mut_ptr()
        }

        pub fn gib_buf(&self) -> &[u8; N] {
            &self.buf
        }

        pub fn reset(&mut self) {
            self.current_idx = 0
        }

        pub fn sz(&self) -> usize {
            self.total_sz
        }

        pub fn take_buf<const I: usize>(
            &self,
            start_idx: usize,
            num_bytes: usize,
        ) -> Result<[u8; I], String> {
            let end_idx = start_idx + num_bytes;
            if end_idx > self.total_sz {
                return Err(String::from("End index exceeds buffer"));
            }

            let mut scratch: [u8; I] = [0; I];

            for (i, byte) in self.buf[start_idx..end_idx].iter().enumerate() {
                scratch[i] = *byte;
            }

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

        #[test]
        fn test_pack() {
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
            assert_eq!(n.pack(), r.pack());
        }
    }
}

pub mod nic {

    use core::fmt;
    use core::u16;

    use std::ffi::{c_uchar, c_void};
    use std::io::Error;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::{mem, ptr, thread};

    use nix::ifaddrs::{self, InterfaceAddress};
    use nix::libc::{
        bind, close, ifreq, ioctl, iovec, msghdr, recvmsg, sendto, sockaddr, sockaddr_nl, socket,
        AF_INET, AF_NETLINK, IFF_UP, IFNAMSIZ, IPPROTO_IP, NETLINK_ROUTE, NLM_F_DUMP,
        NLM_F_REQUEST, RTA_TABLE, RTM_GETROUTE, RTN_UNSPEC, RTPROT_UNSPEC, RT_SCOPE_UNIVERSE,
        RT_TABLE_MAIN, RT_TABLE_UNSPEC, SIOCGIFFLAGS, SIOCSIFFLAGS, SOCK_CLOEXEC, SOCK_DGRAM,
        SOCK_RAW,
    };
    use nix::net::if_::InterfaceFlags;
    use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
    use packed_struct::prelude::PackedStruct;

    use crate::netlink::{
        nlattr,
        nlmsghdr,
        rtmsg,
        ByteBuffer,
        NLA_SZ,
        NLMSG_HDR_SZ,
        RTMMSG_SZ, // U16_SZ, U32_SZ,
    };

    fn errstring<E>(err: E) -> String
    where
        E: ToString,
    {
        format!("{}:{} {}", file!(), line!(), err.to_string())
    }

    // HACKS: vars/functions redefined here to make the compiler happy
    // https://docs.rs/libc/latest/src/libc/unix/linux_like/linux/mod.rs.html#2885-2886
    const NLA_ALIGNTO: i32 = 4;

    //const NLMSG_ALIGNTO: u32 = 4;

    // https://docs.rs/libc/latest/src/libc/unix/linux_like/linux/mod.rs.html#3926-3928
    const fn rust_nla_align(len: i32) -> i32 {
        ((len) + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
    }

    /*const fn rust_nlmsg_align(len: u32) -> u32 {
        ((len) + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }*/

    fn quick_socket(domain: i32, sock_type: i32, protocol: i32) -> Result<i32, String> {
        let sfd = unsafe { socket(domain, sock_type, protocol) };
        if sfd < 0 {
            return Err(Error::last_os_error().to_string());
        }
        Ok(sfd)
    }

    fn checked_bind(sfd: i32, sa: *const sockaddr, addr_len: u32) -> Result<(), String> {
        let rc = unsafe { bind(sfd, sa, addr_len) };

        if rc < 0 {
            return Err(Error::last_os_error().to_string());
        }
        Ok(())
    }

    fn checked_sendto(
        sfd: i32,
        buf: *const c_void,
        buf_len: usize,
        flags: i32,
    ) -> Result<(), String> {
        let rc = unsafe { sendto(sfd, buf, buf_len, flags, ptr::null::<sockaddr>(), 0) };

        if rc < 0 {
            return Err(Error::last_os_error().to_string());
        }
        Ok(())
    }

    fn recv_nlmsg() {
        todo!()
    }

    fn rust_close(sfd: i32) -> Result<(), String> {
        if unsafe { close(sfd) } < 0 {
            return Err(Error::last_os_error().to_string());
        }
        Ok(())
    }

    pub fn get_nics() -> Vec<NetworkInterface> {
        let addrs = ifaddrs::getifaddrs().unwrap();
        let mut netifs = vec![];

        for addr in addrs {
            let netif = ifaddrs::getifaddrs()
                .unwrap()
                .filter(|a| a.interface_name == addr.interface_name)
                .fold(
                    NetworkInterface::default(),
                    |mut acc: NetworkInterface, ia: InterfaceAddress| {
                        acc.name = ia.interface_name;
                        acc.interface_flags = ia.flags;
                        // match address type to set fields
                        if let Some(address) = ia.address {
                            match address.family() {
                                Some(AddressFamily::Inet) => {
                                    acc.ip4_address = ia.address;
                                    acc.broadcast = ia.broadcast;
                                    acc.ip4_netmask = ia.netmask;
                                }
                                Some(AddressFamily::Inet6) => {
                                    acc.ip6_addresses.push(ia.address);
                                    acc.ip6_netmasks.push(ia.netmask);
                                }
                                Some(AddressFamily::Packet) => {
                                    acc.ether = address.to_string().to_uppercase()
                                }
                                _ => println!("unsupported address type"),
                            }
                        }
                        acc
                    },
                );

            if !netifs.contains(&netif) {
                netifs.push(netif);
            }
        }

        netifs
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct NetworkInterface {
        pub name: String,
        ip4_address: Option<SockaddrStorage>,
        ip4_netmask: Option<SockaddrStorage>,
        broadcast: Option<SockaddrStorage>,
        ip6_addresses: Vec<Option<SockaddrStorage>>,
        ip6_netmasks: Vec<Option<SockaddrStorage>>,
        ether: String,
        interface_flags: InterfaceFlags,
    }

    impl Default for NetworkInterface {
        fn default() -> Self {
            Self {
                name: String::new(),
                ip4_address: None,
                ip4_netmask: None,
                broadcast: None,
                ip6_addresses: vec![],
                ip6_netmasks: vec![],
                ether: String::new(),
                interface_flags: InterfaceFlags::from_bits_truncate(0),
            }
        }
    }

    impl fmt::Display for NetworkInterface {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut interface_info = format!("Interface: {}\n", self.name);
            if let (Some(ip4_addr), Some(ip4_mask)) = (self.ip4_address, self.ip4_netmask) {
                if let Some(broadcast) = self.broadcast {
                    interface_info.push_str(
                        format!(
                            "IPv4: {}/{} Broadcast: {}\n",
                            ip4_addr.to_string().replace(":0", ""),
                            ip4_mask.as_sockaddr_in().unwrap().ip().count_ones(),
                            broadcast.to_string().replace(":0", "")
                        )
                        .as_str(),
                    );
                } else {
                    // Loopback interface does not have a broadcast address
                    interface_info.push_str(
                        format!(
                            "IPv4: {}/{}\n",
                            ip4_addr.to_string().replace(":0", ""),
                            ip4_mask.as_sockaddr_in().unwrap().ip().count_ones(),
                        )
                        .as_str(),
                    );
                }
            }

            interface_info.push_str(format!("MAC: {}\n", self.ether).as_str());

            for (ip6_address, ip6_netmask) in
                self.ip6_addresses.iter().zip(self.ip6_netmasks.iter())
            {
                if let (Some(ip6_addr), Some(ip6_mask)) = (ip6_address, ip6_netmask) {
                    interface_info.push_str(
                        format!(
                            "IPv6: {}/{}\n",
                            ip6_addr.to_string().replace("]:0", "]"),
                            ip6_mask
                                .as_sockaddr_in6()
                                .unwrap()
                                .ip()
                                .octets()
                                .iter()
                                .fold(0, |mut acc, oct| {
                                    acc += oct.count_ones();
                                    acc
                                })
                        )
                        .as_str(),
                    );
                }
            }
            write!(f, "{interface_info}")
        }
    }

    impl NetworkInterface {
        fn c_ifname(&self) -> Result<[i8; IFNAMSIZ], String> {
            let mut ifname: [i8; IFNAMSIZ] = [0; IFNAMSIZ];
            if self.name.chars().collect::<Vec<char>>().len() > IFNAMSIZ {
                return Err(String::from(format!(
                    "{}:{} - Exceeded interface name buffer capacity",
                    file!(),
                    line!()
                )));
            }

            for (i, c) in self.name.chars().enumerate() {
                ifname[i] = c as i8;
            }
            Ok(ifname)
        }

        pub fn start(&self) -> Result<(), String> {
            let mut ifr = ifreq {
                ifr_name: self.c_ifname()?,
                ifr_ifru: unsafe { std::mem::zeroed() },
            };

            let sfd = quick_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)?;

            unsafe {
                if ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0 {
                    return Err(Error::last_os_error().to_string());
                }

                ifr.ifr_ifru.ifru_flags |= IFF_UP as i16;

                if ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0 {
                    return Err(Error::last_os_error().to_string());
                }
            }

            rust_close(sfd)
        }

        pub fn stop(&self) -> Result<(), String> {
            let mut ifr = ifreq {
                ifr_name: self.c_ifname()?,
                ifr_ifru: unsafe { std::mem::zeroed() },
            };

            let sfd = quick_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)?;

            unsafe {
                if ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0 {
                    return Err(Error::last_os_error().to_string());
                }

                ifr.ifr_ifru.ifru_flags &= !(IFF_UP as i16);

                if ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0 {
                    return Err(Error::last_os_error().to_string());
                }
            }

            rust_close(sfd)
        }

        pub fn restart(&self) -> Result<(), String> {
            self.stop()?;
            thread::sleep(Duration::from_millis(3000));
            self.start()
        }

        pub fn add_route(&self) {
            todo!()
        }

        pub fn del_route(&self) {
            todo!()
        }

        fn send_request(&self, sfd: i32, sa: *const sockaddr) -> Result<(), String> {
            const MSG_BUF_LEN: usize = NLMSG_HDR_SZ
                + RTMMSG_SZ
                + NLA_SZ
                + (rust_nla_align(mem::size_of::<c_uchar>() as i32)) as usize;

            let nl = nlmsghdr {
                nlmsg_len: MSG_BUF_LEN as u32,
                nlmsg_type: RTM_GETROUTE,
                nlmsg_flags: (NLM_F_REQUEST | NLM_F_DUMP) as u16,
                nlmsg_seq: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32,
                nlmsg_pid: 0,
            };
            let nl_buf = nl.pack().map_err(errstring)?;

            let rt = rtmsg {
                rtm_family: AF_INET as u8,
                rtm_dst_len: 0,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: RT_TABLE_UNSPEC,

                rtm_protocol: RTPROT_UNSPEC,
                rtm_scope: RT_SCOPE_UNIVERSE,
                rtm_type: RTN_UNSPEC,

                rtm_flags: 0,
            };
            let rt_buf = rt.pack().map_err(errstring)?;

            const nla: nlattr = nlattr {
                nla_len: 8,
                nla_type: RTA_TABLE,
            };

            const PAYLOAD_SZ: usize = (nla.nla_len - (mem::size_of::<nlattr>() as u16)) as usize;
            let mut payload = ByteBuffer::<PAYLOAD_SZ>::new();
            payload.build([RT_TABLE_MAIN])?;

            let nla_buf = nla.pack().map_err(errstring)?;

            let nl_term = nlmsghdr::default();
            let nl_term_buf = nl_term.pack().map_err(errstring)?;

            const TOTAL_BUF_LEN: usize = MSG_BUF_LEN + mem::size_of::<nlmsghdr>();

            let mut bb = ByteBuffer::<TOTAL_BUF_LEN>::new();

            bb.build(nl_buf)?;
            bb.build(rt_buf)?;
            bb.build(nla_buf)?;
            bb.build(*payload.gib_buf())?;
            bb.build(nl_term_buf)?;

            let buff = bb.gib_buf();

            const SLACK: usize = 3;

            checked_bind(sfd, sa, mem::size_of::<sockaddr_nl>() as u32)?;

            checked_sendto(
                sfd,
                buff.as_ref() as *const _ as *const c_void,
                buff.as_ref().len() * SLACK,
                0,
            )?;

            Ok(())
        }

        pub fn show_routes(&self) -> Result<(), String> {
            let sfd = quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
            let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
            sa.nl_family = AF_NETLINK as u16;

            self.send_request(sfd, &sa as *const _ as *const sockaddr)?;

            let mut nlmsgbuf = ByteBuffer::<8192>::new();

            let mut iov = iovec {
                iov_base: nlmsgbuf.buf_mut_ptr() as *mut c_void,
                iov_len: nlmsgbuf.sz(),
            };

            let mut mhdr = msghdr {
                msg_name: &mut sa as *mut _ as *mut c_void,
                msg_namelen: mem::size_of::<sockaddr_nl>() as u32,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                msg_control: ptr::null::<c_void>().cast_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };

            let len = unsafe { recvmsg(sfd, &mut mhdr, 0) };
            if len < 0 {
                return Err(Error::last_os_error().to_string());
            }
            let nlhr = nlmsghdr::unpack(&nlmsgbuf.take_buf::<NLMSG_HDR_SZ>(0, NLMSG_HDR_SZ)?)
                .map_err(errstring)?;
            let rtm = rtmsg::unpack(&nlmsgbuf.take_buf::<RTMMSG_SZ>(NLMSG_HDR_SZ, RTMMSG_SZ)?)
                .map_err(errstring)?;
            println!("recv'd nlhr: {:?} rtm: {:?}", nlhr, rtm);

            rust_close(sfd)
        }
    }
}
