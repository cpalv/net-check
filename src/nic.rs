use core::fmt;

use std::ffi::c_void;
use std::io;
use std::io::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use std::{mem, ptr, thread};

use nix::ifaddrs::{self, InterfaceAddress};
use nix::libc::{
    bind, close, if_indextoname, if_nametoindex, ifreq, ioctl, msghdr, recvmsg, sendto, sockaddr,
    sockaddr_nl, socket, AF_INET, AF_NETLINK, ARPHRD_NETROM, IFF_UP, IFLA_STATS, IFLA_STATS64,
    IFNAMSIZ, IPPROTO_IP, MSG_PEEK, MSG_TRUNC, NETLINK_ROUTE, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
    NLM_F_EXCL, NLM_F_REQUEST, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PRIORITY, RTA_TABLE,
    RTEXT_FILTER_SKIP_STATS, RTEXT_FILTER_VF, RT_TABLE_MAIN, SIOCGIFFLAGS, SIOCSIFFLAGS,
    SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW,
};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};

use crate::buffer::{transmute_vec, Buffer, ByteBuffer, ByteVec};
use crate::netlink;
use crate::netlink::{
    create_nlmsg, create_rtrequest, ifinfomsg, nlattr, nlmsghdr, rtmsg, LinkStat,
    LinkStat64, NetlinkSocket, NlaPolicy, NlaPolicyValidator, NlaType, NlmsgType, Route, RtScope,
    RtmProtocol, RtnType, NLA_SZ, NLMSG_HDR_SZ, RTMMSG_SZ, U32_SZ,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;
const GB: usize = 1024 * MB;
const TB: usize = 1024 * GB;

const BUF_SZ: usize = 8 * KB;
const SLACK: usize = 3;

pub fn errstring<E: ToString>(err: E) -> String {
    format!("{}:{} {}", file!(), line!(), err.to_string())
}

#[macro_export]
macro_rules! map_err_str {
    ($e:expr) => {
        $e.map_err($crate::nic::errstring)
    };
}

macro_rules! parse {
    ($buf:ident, $remaining_bytes:ident, $($search:ident => $match_arms:block)+) => {
        while $remaining_bytes > 0 {
            let nla = $buf.gib::<nlattr>(false)?;

            if nla.nla_len < NLA_SZ as u16 {
                return Err(format!("unable to parse netlink attributes, nla must be at least {NLA_SZ} bytes + data, it is likely that either alignment or parsing is off"))
            }

            let nla_payload_bytes = (nla.nla_len - NLA_SZ as u16) as usize;

            let aligned_payload = netlink::rust_nla_align(nla_payload_bytes as i32);

            match nla.nla_type {
                $($search => $match_arms)+
                _ => {
                    $buf.incr(nla_payload_bytes);
                    $buf.incr((aligned_payload as usize) - nla_payload_bytes);
                }
            };

            $remaining_bytes -= ((NLA_SZ as i32) + aligned_payload) as i64;
        }
    };
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

#[derive(Debug, Clone)]
enum RecvErr {
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

fn recv_nlmsg(sfd: i32, mhdr: *mut msghdr, flags: i32) -> Result<usize, RecvErr> {
    let len = unsafe { recvmsg(sfd, mhdr, flags) };
    if len < 0 {
        return Err(RecvErr::OsErr(Error::last_os_error().to_string()));
    }

    if unsafe { (*mhdr).msg_flags } == MSG_TRUNC {
        return Err(RecvErr::MsgTrunc);
    }

    Ok(len as usize)
}

// https://man7.org/linux/man-pages/man7/netlink.7.html#EXAMPLES
fn parse_msg<F: Sized + NlaPolicyValidator, B: Buffer>(
    msgbuf: &mut B,
    nlavp: Option<&F>,
) -> Result<Route, String> {
    let nlhr = msgbuf.gib::<nlmsghdr>(false)?;
    let rtm = msgbuf.gib::<rtmsg>(false)?;

    // parse remaining nlattr structs
    let msg_bytes = nlhr.nlmsg_len as i64;
    let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + RTMMSG_SZ) as i64);

    let mut rt = Route {
        scope: rtm.rtm_scope,
        table: rtm.rtm_table,
        protocol: rtm.rtm_protocol,
        ..Default::default()
    };

    while remaining_msg_bytes > 0 {
        let nla = msgbuf.gib::<nlattr>(false)?;

        if nlavp.is_some() {
            nlavp.unwrap().validate(&nla).map_err(errstring)?;
        }

        let nla_payload_bytes = (nla.nla_len - (NLA_SZ as u16)) as usize;

        let aligned_payload = netlink::rust_nla_align(nla_payload_bytes as i32);

        match nla.nla_type {
            RTA_TABLE => {
                rt.table = *msgbuf.gib_vec(nla_payload_bytes)?.first().unwrap();
            }
            RTA_PRIORITY => {
                rt.rt_priority = *msgbuf.gib_vec(nla_payload_bytes)?.first().unwrap();
            }
            RTA_GATEWAY => {
                let octets = msgbuf.gib_vec(nla_payload_bytes)?;
                rt.rta_gwy = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            }
            RTA_DST => {
                let octets = msgbuf.gib_vec(nla_payload_bytes)?;
                rt.rta_dst = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            }
            RTA_OIF => {
                rt.rta_oif = u32::from_ne_bytes(transmute_vec::<U32_SZ>(
                    &msgbuf.gib_vec(nla_payload_bytes)?,
                )?);
            }
            _ => {
                msgbuf.incr(nla_payload_bytes);
                msgbuf.incr((aligned_payload as usize) - nla_payload_bytes);
            }
        }

        remaining_msg_bytes -= i64::from(nla.nla_len);
    }

    Ok(rt)
}

fn rust_close(sfd: i32) -> Result<(), String> {
    if unsafe { close(sfd) } < 0 {
        return Err(Error::last_os_error().to_string());
    }
    Ok(())
}

fn get_gateway(ifname: [i8; IFNAMSIZ]) -> Option<SockaddrStorage> {
    let sfd = match quick_socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) {
        Ok(socket_file_descriptor) => socket_file_descriptor,
        Err(e) => {
            eprintln!("unabled to create socket: {e}");
            return None;
        }
    };
    let mut sa: sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = match u16::try_from(AF_NETLINK) {
        Ok(netlink) => netlink,
        Err(e) => {
            eprintln!("{e}");
            return None;
        }
    };

    let stuct_size = match map_err_str!(u32::try_from(mem::size_of::<sockaddr_nl>())) {
        Ok(size) => size,
        Err(e) => {
            eprintln!("{e}");
            return None;
        }
    };

    let flags = match u16::try_from(NLM_F_REQUEST | NLM_F_DUMP) {
        Ok(flags) => flags,
        Err(e) => {
            eprintln!("{e}");
            return None;
        }
    };

    if let Err(e) = checked_bind(sfd, ptr::addr_of!(sa).cast::<sockaddr>(), stuct_size) {
        eprintln!("unable to bind to socket {sfd}: {e}");
        return None;
    }

    let v = match create_rtrequest(
        NlmsgType::RtmGetRoute,
        flags,
        0,
        RtnType::Unspecified,
        RtmProtocol::Unspecified,
        RtScope::Universe,
        vec![(NlaType::RtaTable, vec![RT_TABLE_MAIN])],
    ) {
        Ok(req_vec) => req_vec,
        Err(e) => {
            eprintln!("unable to create request: {e}");
            return None;
        }
    };

    if let Err(e) = checked_sendto(sfd, v.as_ptr().cast::<c_void>(), v.len() * SLACK, 0) {
        eprintln!("error sending get route request: {e}");
        return None;
    }

    let mut msgbuf = ByteVec::new(8192);
    let mut mhdr = create_nlmsg(&mut sa, &mut msgbuf);

    let mut rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC);

    while let Err(e) = rx_bytes {
        if msgbuf.sz() > TB {
            eprintln!("Ok.. thats enough: {e}");
            return None;
        }
        msgbuf.realloc(4);
        mhdr = create_nlmsg(&mut sa, &mut msgbuf);

        rx_bytes = recv_nlmsg(sfd, &mut mhdr, MSG_PEEK | MSG_TRUNC);
    }

    while msgbuf.idx() < rx_bytes.clone().ok().unwrap() {
        let rt = match parse_msg::<NlaPolicy, ByteVec>(&mut msgbuf, None) {
            Ok(route) => route,
            Err(e) => {
                eprintln!("error parsing message: {e}");
                return None;
            }
        };

        let mut route_ifname: [i8; IFNAMSIZ] = [0; IFNAMSIZ];

        unsafe { if_indextoname(rt.rta_oif, route_ifname.as_mut_ptr()) };
        if (route_ifname == ifname) && (rt.rta_gwy != Ipv4Addr::new(0, 0, 0, 0)) {
            return Some(SockaddrStorage::from(SocketAddrV4::new(rt.rta_gwy, 0)));
        }
    }
    None
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
                                if let Ok(ifname) = acc.c_ifname() {
                                    acc.if_idx = unsafe { if_nametoindex(ifname.as_ptr()) };
                                    acc.ip4_gatway = get_gateway(ifname);
                                }
                            }
                            Some(AddressFamily::Inet6) => {
                                acc.ip6_addresses.push(ia.address);
                                acc.ip6_netmasks.push(ia.netmask);
                            }
                            Some(AddressFamily::Packet) => {
                                acc.ether = address.to_string().to_uppercase();
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
        if self.name.chars().count() > IFNAMSIZ {
            return Err(format!(
                "{}:{} - Exceeded interface name buffer capacity",
                file!(),
                line!()
            ));
        }

        for (i, c) in self.name.chars().enumerate() {
            ifname[i] = c as i8;
        }
        Ok(ifname)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn ip4_cidr(&self) -> u8 {
        // the max number of bits in a 32-bit will
        // not exceed the max value a u8 can represent
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

    pub fn add_route(&self, rtm_protocol: RtmProtocol, rtm_scope: RtScope) -> Result<(), String> {
        let mut nls = match NetlinkSocket::new() {
            Ok(netlink_socket) => netlink_socket,
            Err(e) => return Err(e.to_string()),
        };

        match nls.bind() {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let flags = map_err_str!(u16::try_from(
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
        ))?;

        let v = match (rtm_protocol, rtm_scope) {
            (RtmProtocol::Kernel, RtScope::Link) => create_rtrequest(
                NlmsgType::RtmAddRoute,
                flags,
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
            (RtmProtocol::Dhcp, RtScope::Universe) => create_rtrequest(
                NlmsgType::RtmAddRoute,
                flags,
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
            return Err(format!(
                "Unable to create request for protocol: {rtm_protocol:?} and scope: {rtm_scope:?}"
            ));
        }

        match nls.sendto(v, 0) {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let mut msgbuf = ByteBuffer::<BUF_SZ>::new();
        let mut mhdr = nls.create_msg(&mut msgbuf);

        let rx_bytes = match nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC) {
            Ok(recvd) => recvd,
            Err(e) => return Err(format!("{e}")),
        };

        while msgbuf.idx() < rx_bytes {
            parse_msg::<NlaPolicy, ByteBuffer<BUF_SZ>>(&mut msgbuf, None)?;
        }

        Ok(())
    }

    pub fn del_route(&self, rtm_protocol: RtmProtocol, rtm_scope: RtScope) -> Result<(), String> {
        let mut nls = match NetlinkSocket::new() {
            Ok(netlink_socket) => netlink_socket,
            Err(e) => return Err(e.to_string()),
        };

        match nls.bind() {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let v = match (rtm_protocol, rtm_scope) {
            (RtmProtocol::Kernel, RtScope::Link) => create_rtrequest(
                NlmsgType::RtmDelRoute,
                map_err_str!(u16::try_from(NLM_F_REQUEST | NLM_F_ACK))?,
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
            (RtmProtocol::Dhcp, RtScope::Nowhere) => create_rtrequest(
                NlmsgType::RtmDelRoute,
                map_err_str!(u16::try_from(NLM_F_REQUEST | NLM_F_ACK))?,
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
            return Err(format!(
                "Unable to create request for protocol: {rtm_protocol:?} and scope: {rtm_scope:?}",
            ));
        }

        match nls.sendto(v, 0) {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let mut msgbuf = ByteBuffer::<BUF_SZ>::new();
        let mut mhdr = nls.create_msg(&mut msgbuf);

        let rx_bytes = match nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC) {
            Ok(recvd) => recvd,
            Err(e) => return Err(format!("{e}")),
        };

        while msgbuf.idx() < rx_bytes {
            parse_msg::<NlaPolicy, ByteBuffer<BUF_SZ>>(&mut msgbuf, None)?;
        }

        Ok(())
    }

    pub fn show_routes(&self) -> io::Result<()> {
        let mut nls = NetlinkSocket::new()?;
        nls.bind()?;

        let v = match create_rtrequest(
            NlmsgType::RtmGetRoute,
            (NLM_F_REQUEST | NLM_F_DUMP) as u16,
            0,
            RtnType::Unspecified,
            RtmProtocol::Unspecified,
            RtScope::Universe,
            vec![(NlaType::RtaTable, vec![RT_TABLE_MAIN])],
        ) {
            Ok(v) => v,
            Err(e) => return Err(Error::new(io::ErrorKind::OutOfMemory, e)),
        };

        nls.sendto(v, 0)?;

        let mut msgbuf = ByteVec::new(BUF_SZ);
        let mut mhdr = nls.create_msg(&mut msgbuf);

        let mut rx_bytes = nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC);

        while let Err(e) = rx_bytes {
            match e {
                netlink::RecvErr::OsErr(s) => {
                    return Err(Error::new(io::ErrorKind::OutOfMemory, s))
                }
                netlink::RecvErr::MsgTrunc => {
                    if msgbuf.sz() > TB {
                        return Err(Error::new(
                            io::ErrorKind::OutOfMemory,
                            format!("Ok.. thats enough: {e}"),
                        ));
                    }
                    msgbuf.realloc(4);
                    mhdr = nls.create_msg(&mut msgbuf);

                    rx_bytes = nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC);
                }
            }
        }

        let mut i = 0;
        while msgbuf.idx() < rx_bytes.clone().ok().unwrap() {
            let rt = match parse_msg::<NlaPolicy, ByteVec>(&mut msgbuf, None) {
                Ok(route) => route,
                Err(e) => return Err(Error::new(io::ErrorKind::InvalidData, e)),
            };

            println!("Route {i}: {rt:?}");
            i += 1;
        }

        Ok(())
    }

    pub fn stats(&self) -> Result<(), String> {
        let mut nls = match NetlinkSocket::new() {
            Ok(netlink_socket) => netlink_socket,
            Err(e) => return Err(e.to_string()),
        };

        match nls.bind() {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let v = netlink::create_ifirequest(
            NlmsgType::RtmGetLink,
            NLM_F_REQUEST as u16,
            ARPHRD_NETROM as u16,
            self.if_idx,
            0,
            0,
            vec![(
                NlaType::IflaExtMask,
                vec![((RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS) as u8)],
            )],
        )?;

        match nls.sendmsg(v, 0) {
            Ok(_) => {}
            Err(e) => return Err(format!("{e}")),
        };

        let mut msgbuf = ByteVec::new(BUF_SZ);
        let mhdr = nls.create_msg(&mut msgbuf);

        let rx_bytes = match nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC) {
            Ok(recvd) => recvd,
            Err(e) => return Err(format!("{e}")),
        };

        let nlhr = msgbuf.gib::<nlmsghdr>(false)?;
        let _ = msgbuf.gib::<ifinfomsg>(false)?;

        let ifm_sz = mem::size_of::<ifinfomsg>();
        let msg_bytes = nlhr.nlmsg_len as i64;

        let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + ifm_sz) as i64);

        let mut stats = None;
        parse!(msgbuf, remaining_msg_bytes, IFLA_STATS => {
            stats = Some(msgbuf.gib::<LinkStat>(false)?);
            break;
        });

        if stats.is_some() {
            println!("{:?}", stats.unwrap());
        }

        Ok(())
    }

    pub fn stats64(&self) -> Result<(), String> {
        let mut nls = match NetlinkSocket::new() {
            Ok(netlink_socket) => netlink_socket,
            Err(e) => return Err(e.to_string()),
        };

        match nls.bind() {
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        };

        let v = netlink::create_ifirequest(
            NlmsgType::RtmGetLink,
            NLM_F_REQUEST as u16,
            ARPHRD_NETROM as u16,
            self.if_idx,
            0,
            0,
            vec![(
                NlaType::IflaExtMask,
                vec![((RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS) as u8)],
            )],
        )?;

        match nls.sendmsg(v, 0) {
            Ok(_) => {}
            Err(e) => return Err(format!("{e}")),
        };

        let mut msgbuf = ByteVec::new(BUF_SZ);
        let mhdr = nls.create_msg(&mut msgbuf);

        let rx_bytes = match nls.recvmsg(mhdr, MSG_PEEK | MSG_TRUNC) {
            Ok(recvd) => recvd,
            Err(e) => return Err(format!("{e}")),
        };

        let nlhr = msgbuf.gib::<nlmsghdr>(false)?;
        let _ = msgbuf.gib::<ifinfomsg>(false)?;

        let ifm_sz = mem::size_of::<ifinfomsg>();
        let msg_bytes = nlhr.nlmsg_len as i64;

        let mut remaining_msg_bytes = msg_bytes - ((NLMSG_HDR_SZ + ifm_sz) as i64);

        let mut stats = None;
        parse!(msgbuf, remaining_msg_bytes, IFLA_STATS64 => {
            stats = Some(msgbuf.gib::<LinkStat64>(false)?);
            break;
        });

        if stats.is_some() {
            println!("{:?}", stats.unwrap());
        }

        Ok(())
    }
}
