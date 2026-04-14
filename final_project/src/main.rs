use clap::Parser;
use pcap::Device;
use chrono::{TimeZone, Local};


#[derive(Parser, Debug)]
struct Args {
    // network interface to capture on: ethernet, wifi card, etc.
    #[arg(short, long)]
    interface: Option<String>,
    // number of packets to capture
    #[arg(short, long, default_value_t = 100)]
    count: usize,
    // used to print available interface
    #[arg(long)]
    list: bool
}

fn main() {
    // [PARSING CLI ARGS]
    let cli_arguments: Args = Args::parse();
    // if --list flag is utilized
    if cli_arguments.list {
        let device_interface_list = match Device::list() {
            Ok(vector) => vector,
            Err(e) => {
                println!("The following error was arose trying to generate a custom device interface list: \n{}", e);
                return;
            }
        };
        println!("List of custom device interfaces: ");
        for device_interface in &device_interface_list {
            println!("{}", device_interface.name);
        }
        println!("Use one of the interfaces above with the --interface flag to capture packets on that interface.");
        return;
    } else {
        // if --list flag is NOT utilized
        match &cli_arguments.interface {
            Some(val) => println!("Interface: {}", val),
            None => {
                println!("No flags utilized, please reference RUN.md for specifications");
                return;
            }
        } 
    }

    // [STARTING PACKET CAPTURE]
    let dev = match cli_arguments.interface {
            Some(val) => val,
            None => {
                panic!("There was an issue with finding the specified interface");
            }
        };
    let inactive_capture = match pcap::Capture::from_device(dev.as_str()) {
        Ok(val) => val,
        Err(e) => {
            panic!("There was an issue with finding the specified interface: {}", e);
        }
    };
    let mut capture1 = match inactive_capture.promisc(true).snaplen(65535).timeout(100).open() {
        Ok(val) => val,
        Err(e) => {
            panic!("Failed to open capture handle: {}", e);
        }
    };
    println!("Capture handle opened, starting capture on {}...", dev);
    let mut packets_received = 0;
    while packets_received < cli_arguments.count {
        match capture1.next_packet() {
            Ok(packet) => {
                packets_received += 1;
                println!("\nReceived packet {} out of {}.", packets_received, cli_arguments.count);
                let tv = packet.header.ts;
                let dt = Local.timestamp_opt(tv.tv_sec, (tv.tv_usec as u32) * 1000).unwrap();
                println!("At {} ({} out of {} bytes captured)", dt.format("%Y-%m-%d %H:%M:%S%.3f"), packet.header.caplen, packet.header.len);
            }
            Err(e) => {
                if e != pcap::Error::TimeoutExpired {
                println!("The following error occurred while attempting to retrieve the next packet: {}", e);
                }
            }
        }
    }

}
