use std::net::{IpAddr, IpAddr::V4, IpAddr::V6};

use crate::netlink::{RtScope, RtmProtocol};
use crate::nic;
use clap::{Args, Parser, Subcommand, ValueEnum};

macro_rules! ee {
    ($f:expr) => {
        if let Err(e) = $f {
            eprintln!("{e}");
            return 1;
        }

        return 0;
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RouteSubCommand {
    Add,
    Del,
    Show,
}

#[derive(Args)]
struct RouteCommand {
    #[arg(value_enum)]
    rscmd: RouteSubCommand,
    #[arg(value_enum)]
    protocol: Option<RtmProtocol>,
    #[arg(value_enum)]
    scope: Option<RtScope>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Stop,
    Restart,
    Show,
    Route(RouteCommand),
}

#[derive(Parser)]
#[command(author, version, about)]
pub struct CliApp {
    /// Network interface to operate on
    interface: Option<String>,

    #[command(subcommand)]
    cmds: Option<Commands>,
}

impl CliApp {
    pub fn run() -> i32 {
        let cli = CliApp::parse();

        if let Some(ifname) = cli.interface.as_deref() {
            let netifs = nic::get_nics();

            if let Some(interface) = netifs.iter().find(|&netif| netif.name == ifname) {
                match &cli.cmds {
                    Some(Commands::Start) => {
                        ee!(interface.start());
                    }
                    Some(Commands::Stop) => {
                        ee!(interface.stop());
                    }
                    Some(Commands::Restart) => {
                        ee!(interface.restart());
                    }
                    Some(Commands::Show) => {
                        println!("{interface}");
                        match interface.stats64() {
                            Ok(stats) => {
                                println!("{stats}");
                                return 0;
                            }
                            Err(e) => {
                                eprintln!("{e}");
                                return 1;
                            }
                        };
                    }
                    Some(Commands::Route(rcmd)) => match rcmd.rscmd {
                        RouteSubCommand::Add => {
                            if rcmd.protocol.is_none()
                                || rcmd.scope.is_none()
                                || rcmd.src.is_none()
                                || rcmd.dst.is_none()
                            {
                                eprintln!("Add command requires that protocol, scope, source and destination IPs are specified");
                                return 1;
                            }
                            ee!(interface.add_route(
                                rcmd.protocol.unwrap(),
                                rcmd.scope.unwrap(),
                                rcmd.src.unwrap(),
                                rcmd.dst.unwrap(),
                            ));
                        }
                        RouteSubCommand::Del => {
                            if rcmd.protocol.is_none()
                                || rcmd.scope.is_none()
                                || rcmd.src.is_none()
                                || rcmd.dst.is_none()
                            {
                                eprintln!("Delete command requires that protocol, scope, source and destination IPs are specified");
                                return 1;
                            }

                            ee!(interface.del_route(
                                rcmd.protocol.unwrap(),
                                rcmd.scope.unwrap(),
                                rcmd.src.unwrap(),
                                rcmd.dst.unwrap(),
                            ));
                        }
                        RouteSubCommand::Show => {
                            ee!(interface.show_routes());
                        }
                    },
                    None => {
                        for netif in netifs {
                            println!("{netif}");
                        }
                        return 0;
                    }
                };
            } else {
                eprintln!("{ifname} is not an existing interface");
                return 1;
            }
        }

        return 1;
    }
}
