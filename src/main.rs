use core::fmt;

use std::io::Error;
use std::thread;
use std::time::Duration;

use nix::ifaddrs::{self, InterfaceAddress};
use nix::libc::{
    ifreq, ioctl, socket, AF_INET, IFF_UP, IFNAMSIZ, IPPROTO_IP, SIOCGIFFLAGS, SIOCSIFFLAGS,
    SOCK_DGRAM,
};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};

fn quick_socket() -> Result<i32, String> {
    let sfd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) };
    if sfd < 0 {
        return Err(Error::last_os_error().to_string());
    }
    Ok(sfd)
}

fn set_ifflag(ifname: [i8; IFNAMSIZ], sfd: i32, flag: i16) -> Result<(), String> {
    let mut ifr = ifreq {
        ifr_name: ifname,
        ifr_ifru: unsafe { std::mem::zeroed() },
    };
    unsafe {
        if ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0 {
            return Err(Error::last_os_error().to_string());
        }

        ifr.ifr_ifru.ifru_flags |= flag;
        if ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0 {
            return Err(Error::last_os_error().to_string());
        }
    }
    Ok(())
}

fn clear_ifflag(ifname: [i8; IFNAMSIZ], sfd: i32, flag: i16) -> Result<(), String> {
    let mut ifr = ifreq {
        ifr_name: ifname,
        ifr_ifru: unsafe { std::mem::zeroed() },
    };
    unsafe {
        if ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0 {
            return Err(Error::last_os_error().to_string());
        }
        ifr.ifr_ifru.ifru_flags &= !(flag);
        if ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0 {
            return Err(Error::last_os_error().to_string());
        }
    }
    Ok(())
}

fn get_nics() -> Vec<NetworkInterface> {
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

#[derive(Clone, Debug, PartialEq)]
struct NetworkInterface {
    name: String,
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
    fn c_ifname(&self) -> [i8; IFNAMSIZ] {
        let mut ifname: [i8; IFNAMSIZ] = [0; IFNAMSIZ];
        for (i, c) in self.name.chars().enumerate() {
            ifname[i] = c as i8;
        }
        ifname
    }

    fn start(&self) -> Result<(), String> {
        set_ifflag(self.c_ifname(), quick_socket()?, IFF_UP as i16)
    }

    fn stop(&self) -> Result<(), String> {
        clear_ifflag(self.c_ifname(), quick_socket()?, IFF_UP as i16)
    }

    fn restart(&self) -> Result<(), String> {
        self.stop()?;
        thread::sleep(Duration::from_millis(3000));
        self.start()
    }
}

fn main() {
    let netifs = get_nics();

    for netif in netifs {
        println!("{netif}");
        if netif.name == "enp6s0" {
            println!("restarting {}", netif.name);
            if let Err(res) = netif.restart() {
                println!("{res}");
            }
        }
    }
}
