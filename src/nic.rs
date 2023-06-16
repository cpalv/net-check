use core::fmt;

use std::ffi::c_void;
use std::io::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{mem, ptr, thread};

use nix::ifaddrs::{self, InterfaceAddress};
use nix::libc::{
    bind, close, if_indextoname, if_nametoindex, ifreq, ioctl, msghdr, recvmsg, sendto, sockaddr,
    sockaddr_nl, socket, AF_INET, AF_NETLINK, IFF_UP, IFNAMSIZ, IPPROTO_IP, MSG_PEEK, MSG_TRUNC,
    NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, RTA_DST,
    RTA_GATEWAY, RTA_OIF, RTA_PRIORITY, RTA_TABLE, RT_TABLE_MAIN, SIOCGIFFLAGS, SIOCSIFFLAGS,
    SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW,
};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};
use packed_struct::prelude::PackedStruct;

use crate::netlink::{
    create_nlattrs, create_nlmsg, nlattr, nlmsghdr, rtmsg, rust_is_nlmsg_aligned, rust_nlmsg_align,
    transmute_vec, ByteVec, NlaType, NlmsgType, RtScope, RtmProtocol, RtnType, NLA_SZ,
    NLMSG_HDR_SZ, RTMMSG_SZ, U32_SZ,
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

fn checked_sendto(sfd: i32, buf: *const c_void, buf_len: usize, flags: i32) -> Result<(), String> {
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
fn parse_msg(nlmsgbuf: &mut ByteVec) -> Result<Route, String> {
    let nlhr = nlmsghdr::unpack(&nlmsgbuf.take_buf::<NLMSG_HDR_SZ>()?).map_err(errstring)?;
    let rtm = rtmsg::unpack(&nlmsgbuf.take_buf::<RTMMSG_SZ>()?).map_err(errstring)?;

    // parse remaining nlattr structs
    let msg_bytes = nlhr.nlmsg_len as isize;
    let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + RTMMSG_SZ) as isize);

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

        for (ip6_address, ip6_netmask) in self.ip6_addresses.iter().zip(self.ip6_netmasks.iter()) {
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

        let mut msgbuf = ByteVec::new(8192);
        let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

        let mut rx_bytes = match recv_nlmsg(sfd, &mut mhdr, 0) {
            Ok(received_bytes) => received_bytes,
            Err(e) => {
                eprintln!("error on receive msg: {e}");
                return self;
            }
        };

        while mhdr.msg_flags == MSG_TRUNC {
            let new_buf_sz = msgbuf.sz() * 4;
            msgbuf = ByteVec::new(new_buf_sz);
            mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            rx_bytes = match recv_nlmsg(sfd, &mut mhdr, 0) {
                Ok(received_bytes) => received_bytes,
                Err(e) => {
                    eprintln!("error on receive msg: {e}");
                    return self;
                }
            };
        }

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

    pub fn add_route(&self, rtm_protocol: RtmProtocol, rtm_scope: RtScope) -> Result<(), String> {
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

        let mut msgbuf = ByteVec::new(8192);
        let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

        let mut rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;

        while mhdr.msg_flags == MSG_TRUNC {
            let new_buf_sz = msgbuf.sz() * 4;
            msgbuf = ByteVec::new(new_buf_sz);
            mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;
        }

        while msgbuf.idx() < rx_bytes {
            parse_msg(&mut msgbuf)?;
        }

        rust_close(sfd)
    }

    pub fn del_route(&self, rtm_protocol: RtmProtocol, rtm_scope: RtScope) -> Result<(), String> {
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

        let mut msgbuf = ByteVec::new(8192);
        let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

        let mut rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;

        while mhdr.msg_flags == MSG_TRUNC {
            let new_buf_sz = msgbuf.sz() * 4;
            msgbuf = ByteVec::new(new_buf_sz);
            mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;
        }

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

        const BUF_SZ: usize = 64;
        let mut msgbuf = ByteVec::new(BUF_SZ);
        let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

        let mut rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;

        while mhdr.msg_flags == MSG_TRUNC {
            let new_buf_sz = msgbuf.sz() * 4;
            msgbuf = ByteVec::new(new_buf_sz);
            mhdr = create_nlmsg(&mut sa, &mut msgbuf);

            rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC)?;
        }

        let mut i = 0;
        while msgbuf.idx() < rx_bytes {
            let rt = parse_msg(&mut msgbuf)?;
            println!("Route {i}: {:?}", rt);
            i += 1;
        }

        rust_close(sfd)
    }
}
