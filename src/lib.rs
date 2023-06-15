pub mod netlink {
    use std::ffi::c_void;
    use std::{mem, ptr};

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

    pub fn create_nlmsg<const BUF_SZ: usize>(
        sa: &mut sockaddr_nl,
        msgbuf: &mut ByteBuffer<BUF_SZ>,
    ) -> msghdr {
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
        buf: [u8; TOTAL_SZ],
    }

    impl<const TOTAL_SZ: usize> ByteBuffer<TOTAL_SZ> {
        pub fn new() -> Self {
            Self {
                current_idx: 0,
                buf: [0; TOTAL_SZ],
            }
        }

        pub fn build<const BUF_LEN: usize>(
            &mut self,
            added_buf: [u8; BUF_LEN],
        ) -> Result<&mut Self, String> {
            if self.current_idx + added_buf.len() > TOTAL_SZ {
                return Err(String::from("Exceeded buffer capacity"));
            } else {
                for byte in added_buf {
                    self.buf[self.current_idx] = byte;
                    self.current_idx += 1;
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

            assert_eq!(n.pack().unwrap(), r.pack().unwrap())
        }

        #[test]
        fn test_unpack() {
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
    }
}

pub mod nic {
    use core::fmt;

    use std::ffi::c_void;
    use std::io::Error;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::{mem, ptr, thread};

    use nix::ifaddrs::{self, InterfaceAddress};
    use nix::libc::{
        bind, close, if_indextoname, if_nametoindex, ifreq, ioctl, msghdr, recvmsg, sendto,
        sockaddr, sockaddr_nl, socket, AF_INET, AF_NETLINK, IFF_UP, IFNAMSIZ, IPPROTO_IP,
        NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, RTA_DST,
        RTA_GATEWAY, RTA_OIF, RTA_PRIORITY, RTA_TABLE, RT_TABLE_MAIN, SIOCGIFFLAGS, SIOCSIFFLAGS,
        SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW,
    };
    use nix::net::if_::InterfaceFlags;
    use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
    use packed_struct::prelude::PackedStruct;

    use crate::netlink::{
        create_nlattrs, create_nlmsg, nlattr, nlmsghdr, rtmsg, rust_is_nlmsg_aligned,
        rust_nlmsg_align, ByteBuffer, NlaType, NlmsgType, RtScope, RtmProtocol, RtnType, NLA_SZ,
        NLMSG_HDR_SZ, RTMMSG_SZ, U16_SZ, U32_SZ,
    };

    fn errstring<E: ToString>(err: E) -> String {
        format!("{}:{} {}", file!(), line!(), err.to_string())
    }

    #[derive(Debug)]
    struct Route {
        table: u8,
        protocol: u8,
        scope: u8,
        rt_priority: u8,
        rta_dst: Ipv4Addr,
        rta_gwy: Ipv4Addr,
        rta_oif: u32,
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

    fn recv_nlmsg(sfd: i32, mhdr: *mut msghdr, flags: i32) -> Result<usize, String> {
        let len = unsafe { recvmsg(sfd, mhdr, flags) };
        if len < 0 {
            return Err(Error::last_os_error().to_string());
        }
        Ok(len as usize)
    }

    // https://man7.org/linux/man-pages/man7/netlink.7.html#EXAMPLES
    fn parse_msg<const TOTAL_SZ: usize>(
        nlmsgbuf: &mut ByteBuffer<TOTAL_SZ>,
    ) -> Result<Route, String> {
        let nlhr = nlmsghdr::unpack(&nlmsgbuf.take_buf::<NLMSG_HDR_SZ>()?).map_err(errstring)?;
        let rtm = rtmsg::unpack(&nlmsgbuf.take_buf::<RTMMSG_SZ>()?).map_err(errstring)?;

        // parse remaining nlattr structs
        let msg_bytes = nlhr.nlmsg_len as isize;
        let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + RTMMSG_SZ) as u32) as isize;

        let mut rt = Route::default();

        rt.scope = rtm.rtm_scope;
        rt.table = rtm.rtm_table;
        rt.protocol = rtm.rtm_protocol;

        while remaining_msg_bytes > 0 {
            let nla = nlattr::unpack(&nlmsgbuf.take_buf::<NLA_SZ>()?).map_err(errstring)?;

            let remaining_nla_bytes = (nla.nla_len - (NLA_SZ as u16)) as usize;

            match nla.nla_type {
                RTA_TABLE => {
                    rt.table = *nlmsgbuf.take_vec(remaining_nla_bytes)?.get(0).unwrap();
                }
                RTA_PRIORITY => {
                    rt.rt_priority = *nlmsgbuf.take_vec(remaining_nla_bytes)?.get(0).unwrap();
                }
                RTA_GATEWAY => {
                    let octets = transmute_vec::<U32_SZ>(nlmsgbuf.take_vec(remaining_nla_bytes)?)?;
                    rt.rta_gwy = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                }
                RTA_DST => {
                    let octets = transmute_vec::<U32_SZ>(nlmsgbuf.take_vec(remaining_nla_bytes)?)?;
                    rt.rta_dst = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                }
                RTA_OIF => {
                    rt.rta_oif = u32::from_ne_bytes(transmute_vec::<U32_SZ>(
                        nlmsgbuf.take_vec(remaining_nla_bytes)?,
                    )?);
                }
                _ => nlmsgbuf.incr(remaining_nla_bytes),
            }

            remaining_msg_bytes -= nla.nla_len as isize;
        }

        Ok(rt)
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
                                    acc.ip4_host_addr = ia.address;
                                    acc.broadcast = ia.broadcast;
                                    acc.ip4_netmask = ia.netmask;
                                    if let (Some(ip4_host_addr), Some(ip4_netmask)) =
                                        (ia.address, ia.netmask)
                                    {
                                        let net_addr = ip4_host_addr.as_sockaddr_in().unwrap().ip()
                                            & ip4_netmask.as_sockaddr_in().unwrap().ip();
                                        let octets = net_addr.to_be_bytes();
                                        acc.ip4_net_addr =
                                            Some(SockaddrStorage::from(SocketAddrV4::new(
                                                Ipv4Addr::new(
                                                    octets[0], octets[1], octets[2], octets[3],
                                                ),
                                                0,
                                            )));
                                    }
                                    acc.set_gateway();
                                    if let Ok(ifname) = acc.c_ifname() {
                                        acc.if_idx = unsafe { if_nametoindex(ifname.as_ptr()) };
                                    }
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

    fn transmute_vec<const NUM_BYTES: usize>(v: Vec<u8>) -> Result<[u8; NUM_BYTES], String> {
        let mut scratch = [0; NUM_BYTES];
        match v.len() {
            U16_SZ | U32_SZ => {
                for (i, byte) in v.iter().enumerate() {
                    scratch[i] = *byte;
                }
                Ok(scratch)
            }
            _ => Err(String::from("Cannot transmute byte vector to byte array")),
        }
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct NetworkInterface {
        pub name: String,
        ip4_host_addr: Option<SockaddrStorage>,
        ip4_netmask: Option<SockaddrStorage>,
        ip4_net_addr: Option<SockaddrStorage>,
        ip4_gatway: Option<SockaddrStorage>,
        broadcast: Option<SockaddrStorage>,
        ip6_addresses: Vec<Option<SockaddrStorage>>,
        ip6_netmasks: Vec<Option<SockaddrStorage>>,
        ether: String,
        if_idx: u32,
        interface_flags: InterfaceFlags,
    }

    impl Default for NetworkInterface {
        fn default() -> Self {
            Self {
                name: String::new(),
                ip4_host_addr: None,
                ip4_netmask: None,
                ip4_net_addr: None,
                ip4_gatway: None,
                broadcast: None,
                ip6_addresses: vec![],
                ip6_netmasks: vec![],
                ether: String::new(),
                interface_flags: InterfaceFlags::from_bits_truncate(0),
                if_idx: 0,
            }
        }
    }

    impl fmt::Display for NetworkInterface {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut interface_info = format!("Interface: {}\n", self.name);
            if let (Some(ip4_addr), Some(ip4_mask), Some(ip4_net_addr)) =
                (self.ip4_host_addr, self.ip4_netmask, self.ip4_net_addr)
            {
                if let (Some(broadcast), Some(ip4_gwy)) = (self.broadcast, self.ip4_gatway) {
                    interface_info.push_str(
                        format!(
                            "IPv4:\n\tNetwork Address: {}\n\tGateway Address: {}\n\tHost Address: {}/{}\n\tBroadcast: {}\n",
                            ip4_net_addr.to_string().replace(":0", ""),
                            ip4_gwy.to_string().replace(":0", ""),
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

        fn ip4_cidr(&self) -> u8 {
            self.ip4_netmask
                .unwrap()
                .as_sockaddr_in()
                .unwrap()
                .ip()
                .count_ones() as u8
        }

        pub fn start(&self) -> Result<(), String> {
            let mut ifr = ifreq {
                ifr_name: self.c_ifname()?,
                ifr_ifru: unsafe { mem::zeroed() },
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
                ifr_ifru: unsafe { mem::zeroed() },
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

        fn set_gateway(&mut self) -> &Self {
            let sfd = match quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) {
                Ok(socket_file_descriptor) => socket_file_descriptor,
                Err(e) => {
                    eprintln!("unabled to create socket: {e}");
                    return self;
                }
            };
            let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
            sa.nl_family = AF_NETLINK as u16;

            if let Err(e) = checked_bind(
                sfd,
                &sa as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_nl>() as u32,
            ) {
                eprintln!("unable to bind to socket {sfd}: {e}");
                return self;
            }

            let v = match self.create_rtrequest(
                NlmsgType::RtmGetRoute,
                (NLM_F_REQUEST | NLM_F_DUMP) as u16,
                0,
                RtnType::Unspecified,
                RtmProtocol::Unspecified,
                RtScope::Universe,
                vec![(NlaType::RtaTable, vec![RT_TABLE_MAIN])],
            ) {
                Ok(req_vec) => req_vec,
                Err(e) => {
                    eprintln!("unable to create request: {e}");
                    return self;
                }
            };

            const SLACK: usize = 3;
            if let Err(e) = checked_sendto(
                sfd,
                v.as_ptr() as *const _ as *const c_void,
                v.len() * SLACK,
                0,
            ) {
                eprintln!("error sending get route request: {e}");
                return self;
            }

            let mut msgbuf = ByteBuffer::<8192>::new();
            let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            let rx_bytes = match recv_nlmsg(sfd, &mut mhdr, 0) {
                Ok(received_bytes) => received_bytes as usize,
                Err(e) => {
                    eprintln!("error on receive msg: {e}");
                    return self;
                }
            };

            while msgbuf.idx() < rx_bytes {
                let rt = match parse_msg(&mut msgbuf) {
                    Ok(route) => route,
                    Err(e) => {
                        eprintln!("error parsing message: {e}");
                        return self;
                    }
                };

                let mut route_ifname: [i8; IFNAMSIZ] = [0; IFNAMSIZ];
                let current_ifname = match self.c_ifname() {
                    Ok(interface_name) => interface_name,
                    Err(e) => {
                        eprintln!("unable to get the name of this interface: {e}");
                        return self;
                    }
                };

                unsafe { if_indextoname(rt.rta_oif, route_ifname.as_mut_ptr()) };
                if (route_ifname == current_ifname) && (rt.rta_gwy != Ipv4Addr::new(0, 0, 0, 0)) {
                    self.ip4_gatway = Some(SockaddrStorage::from(SocketAddrV4::new(rt.rta_gwy, 0)));
                    return self;
                }
            }
            self.ip4_gatway = None;
            self
        }

        pub fn add_route(
            &self,
            rtm_protocol: RtmProtocol,
            rtm_scope: RtScope,
        ) -> Result<(), String> {
            let sfd = quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
            let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
            sa.nl_family = AF_NETLINK as u16;

            checked_bind(
                sfd,
                &sa as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_nl>() as u32,
            )?;

            let v = match (rtm_protocol, rtm_scope) {
                (RtmProtocol::Kernel, RtScope::Link) => self.create_rtrequest(
                    NlmsgType::RtmAddRoute,
                    (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
                    self.ip4_cidr(),
                    RtnType::Unicast,
                    rtm_protocol,
                    rtm_scope,
                    vec![
                        (
                            NlaType::RtaDestination,
                            self.ip4_net_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (
                            NlaType::RtaPrefSource,
                            self.ip4_host_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (NlaType::RtaPriority, 100_u32.to_ne_bytes().to_vec()),
                        (NlaType::RtaOIF, self.if_idx.to_ne_bytes().to_vec()),
                    ],
                )?,
                (RtmProtocol::Dhcp, RtScope::Universe) => self.create_rtrequest(
                    NlmsgType::RtmAddRoute,
                    (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16,
                    0,
                    RtnType::Unicast,
                    rtm_protocol,
                    rtm_scope,
                    vec![
                        (
                            NlaType::RtaGateway,
                            self.ip4_gatway
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (
                            NlaType::RtaPrefSource,
                            self.ip4_host_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (NlaType::RtaPriority, 100_u32.to_ne_bytes().to_vec()),
                        (NlaType::RtaOIF, self.if_idx.to_ne_bytes().to_vec()),
                    ],
                )?,
                (_, _) => vec![],
            };

            if v.is_empty() {
                return Err(String::from(format!(
                    "Unable to create request for protocol: {:?} and scope: {:?}",
                    rtm_protocol, rtm_scope
                )));
            }

            const SLACK: usize = 3;
            checked_sendto(
                sfd,
                v.as_ptr() as *const _ as *const c_void,
                v.len() * SLACK,
                0,
            )?;

            let mut msgbuf = ByteBuffer::<8192>::new();
            let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            let rx_bytes = recv_nlmsg(sfd, &mut mhdr, 0)?;

            while msgbuf.idx() < rx_bytes {
                parse_msg(&mut msgbuf)?;
            }

            rust_close(sfd)
        }

        pub fn del_route(
            &self,
            rtm_protocol: RtmProtocol,
            rtm_scope: RtScope,
        ) -> Result<(), String> {
            let sfd = quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
            let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
            sa.nl_family = AF_NETLINK as u16;

            checked_bind(
                sfd,
                &sa as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_nl>() as u32,
            )?;

            let v = match (rtm_protocol, rtm_scope) {
                (RtmProtocol::Kernel, RtScope::Link) => self.create_rtrequest(
                    NlmsgType::RtmDelRoute,
                    (NLM_F_REQUEST | NLM_F_ACK) as u16,
                    self.ip4_cidr(),
                    RtnType::Unspecified,
                    rtm_protocol,
                    rtm_scope,
                    vec![
                        (
                            NlaType::RtaDestination,
                            self.ip4_net_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (
                            NlaType::RtaPrefSource,
                            self.ip4_host_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (NlaType::RtaPriority, 100_u32.to_ne_bytes().to_vec()),
                        (NlaType::RtaOIF, self.if_idx.to_ne_bytes().to_vec()),
                    ],
                )?,
                (RtmProtocol::Dhcp, RtScope::Nowhere) => self.create_rtrequest(
                    NlmsgType::RtmDelRoute,
                    (NLM_F_REQUEST | NLM_F_ACK) as u16,
                    0,
                    RtnType::Unspecified,
                    rtm_protocol,
                    rtm_scope,
                    vec![
                        (
                            NlaType::RtaGateway,
                            self.ip4_gatway
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (
                            NlaType::RtaPrefSource,
                            self.ip4_host_addr
                                .unwrap()
                                .as_sockaddr_in()
                                .unwrap()
                                .ip()
                                .to_be_bytes()
                                .to_vec(),
                        ),
                        (NlaType::RtaPriority, 100_u32.to_ne_bytes().to_vec()),
                        (NlaType::RtaOIF, self.if_idx.to_ne_bytes().to_vec()),
                    ],
                )?,
                (_, _) => vec![],
            };

            if v.is_empty() {
                return Err(String::from(format!(
                    "Unable to create request for protocol: {:?} and scope: {:?}",
                    rtm_protocol, rtm_scope
                )));
            }

            const SLACK: usize = 3;
            checked_sendto(
                sfd,
                v.as_ptr() as *const _ as *const c_void,
                v.len() * SLACK,
                0,
            )?;

            let mut msgbuf = ByteBuffer::<8192>::new();
            let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            let rx_bytes = recv_nlmsg(sfd, &mut mhdr, 0)?;

            while msgbuf.idx() < rx_bytes {
                parse_msg(&mut msgbuf)?;
            }

            rust_close(sfd)
        }

        fn create_rtrequest(
            &self,
            nlmsg_type: NlmsgType,
            nlmsg_flags: u16,
            rtm_dst_len: u8,
            rtm_type: RtnType,
            rtm_protocol: RtmProtocol,
            rtm_scope: RtScope,
            nla_data: Vec<(NlaType, Vec<u8>)>,
        ) -> Result<Vec<u8>, String> {
            let rt = rtmsg {
                rtm_family: AF_INET as u8,
                rtm_dst_len: rtm_dst_len,
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
                nlmsg_len: msg_buf_len as u32,
                nlmsg_type: nlmsg_type as u16,
                nlmsg_flags: nlmsg_flags,
                nlmsg_seq: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(errstring)?
                    .as_secs() as u32,
                nlmsg_pid: 0,
            };

            let mut fhv = Vec::new();
            if !rust_is_nlmsg_aligned(RTMMSG_SZ as u32) {
                let total_family_header_len =
                    rust_nlmsg_align((NLMSG_HDR_SZ + RTMMSG_SZ) as u32) as usize;

                fhv.append(&mut nh.pack().map_err(errstring)?.to_vec());
                fhv.append(&mut rt.pack().map_err(errstring)?.to_vec());
                let num_pad_bytes = total_family_header_len - fhv.len();
                fhv.append(&mut vec![0; num_pad_bytes]);
            } else {
                fhv.append(&mut nh.pack().map_err(errstring)?.to_vec());
                fhv.append(&mut rt.pack().map_err(errstring)?.to_vec());
            }

            let mut v = Vec::new();
            v.append(&mut fhv);
            v.append(&mut nlas);

            Ok(v)
        }

        pub fn show_routes(&self) -> Result<(), String> {
            let sfd = quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
            let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
            sa.nl_family = AF_NETLINK as u16;

            checked_bind(
                sfd,
                &sa as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_nl>() as u32,
            )?;

            let v = self.create_rtrequest(
                NlmsgType::RtmGetRoute,
                (NLM_F_REQUEST | NLM_F_DUMP) as u16,
                0,
                RtnType::Unspecified,
                RtmProtocol::Unspecified,
                RtScope::Universe,
                vec![(NlaType::RtaTable, vec![RT_TABLE_MAIN])],
            )?;

            const SLACK: usize = 3;
            checked_sendto(
                sfd,
                v.as_ptr() as *const _ as *const c_void,
                v.len() * SLACK,
                0,
            )?;

            let mut msgbuf = ByteBuffer::<8192>::new();
            let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            let rx_bytes = recv_nlmsg(sfd, &mut mhdr, 0)?;

            let mut i = 0;
            while msgbuf.idx() < rx_bytes {
                let rt = parse_msg(&mut msgbuf)?;
                println!("Route {i}: {:?}", rt);
                i += 1;
            }

            rust_close(sfd)
        }
    }
}
