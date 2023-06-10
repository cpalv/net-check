use netinterfacectl::nic::get_nics;

fn main() {
    let netifs = get_nics();

    if let Some(inerface) = netifs.iter().find(|&netif| netif.name == "enp6s0") {
        println!("found interface with name {}", inerface.name);
    }

    for netif in netifs {
        println!("{netif}");
        if let Err(e) = netif.show_routes() {
            eprintln!("{e}");
        }
        /*if netif.name == "enp6s0" {
            println!("restarting {}", netif.name);
            if let Err(res) = netif.restart() {
                println!("{res}");
            }
        }*/
    }
}
