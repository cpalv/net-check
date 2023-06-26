mod buffer;
mod netlink;
mod nic;

fn main() {
    let netifs = nic::get_nics();

    if let Some(inerface) = netifs.iter().find(|&netif| netif.name == "enp6s0") {
        println!("found interface with name {}", inerface.name);
    }

    for netif in netifs {
        if let Err(e) = netif.show_routes() {
            eprintln!("{e}");
        }

        println!();
        /*if netif.name == "enp6s0" {
            println!("restarting {}", netif.name);
            if let Err(res) = netif.restart() {
                eprintln!("{res}");
            }
        }*/
    }
}
