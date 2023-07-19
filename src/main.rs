mod buffer;
mod cmd;
mod netlink;
mod nic;

use std::process;

fn main() {
    process::exit(cmd::CliApp::run())
}
