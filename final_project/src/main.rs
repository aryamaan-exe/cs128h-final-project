mod capture;

use clap::Parser;
use pcap::Device;

#[derive(Parser, Debug)]
struct Args {
    // network interface to capture on: ethernet, wifi card, etc.
    #[arg(short, long)]
    interface: Option<String>,
    // number of packets to capture
    #[arg(short, long, default_value_t = 100)]
    count: usize,
    // used to print available interfaces
    #[arg(long)]
    list: bool,

    #[arg(short, long)]
    filter: Option<String>,
}

fn main() {
    // [PARSING CLI ARGS]
    let cli_arguments: Args = Args::parse();

    if cli_arguments.list {
        let device_interface_list = match Device::list() {
            Ok(vector) => vector,
            Err(e) => {
                println!(
                    "The following error was arose trying to generate a custom device interface list: \n{}",
                    e
                );
                return;
            }
        };
        println!("List of custom device interfaces: ");
        for device_interface in &device_interface_list {
            println!("{}", device_interface.name);
        }
        println!(
            "Use one of the interfaces above with the --interface flag to capture packets on that interface."
        );
        return;
    } else {
        match &cli_arguments.interface {
            Some(val) => println!("Interface: {}", val),
            None => {
                println!("No flags utilized, please reference RUN.md for specifications");
                return;
            }
        }
    }

    // [STARTING PACKET CAPTURE]
    capture::start_capture(cli_arguments.interface, cli_arguments.count, cli_arguments.filter);
}
