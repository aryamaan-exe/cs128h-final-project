use clap::Parser;
use pcap::Device;
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

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
    list: bool,

    #[arg(short, long)]
    filter: Option<String>,
}

fn main() {
    // [PARSING CLI ARGS]
    let cli_arguments: Args = Args::parse();
    // if --list flag is utilized
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
            panic!(
                "There was an issue with finding the specified interface: {}",
                e
            );
        }
    };

    let mut capture1 = match inactive_capture
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
    {
        Ok(val) => val,
        Err(e) => {
            panic!("Failed to open capture handle: {}", e);
        }
    };

    if let Some(f) = &cli_arguments.filter {
        if let Err(e) = capture1.filter(f, true) {
            eprintln!("Failed to apply filter '{}': {}", f, e);
            return;
        }
        println!("Filter applied: {}", f);
    }

    println!("Capture handle opened, starting capture on {}...", dev);

    let mut packets_received = 0;

    while packets_received < cli_arguments.count {
        match capture1.next_packet() {
            Ok(packet) => {
                packets_received += 1;

                // CLEAN WIRESHARK-STYLE OUTPUT
                if let Some(eth) = EthernetPacket::new(packet.data) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                match ip.get_next_level_protocol() {
                                    IpNextHeaderProtocols::Tcp => {
                                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                            println!(
                                                "[{}] TCP {}:{} -> {}:{}",
                                                packets_received,
                                                ip.get_source(),
                                                tcp.get_source(),
                                                ip.get_destination(),
                                                tcp.get_destination()
                                            );
                                        }
                                    }
                                    IpNextHeaderProtocols::Udp => {
                                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                                            println!(
                                                "[{}] UDP {}:{} -> {}:{}",
                                                packets_received,
                                                ip.get_source(),
                                                udp.get_source(),
                                                ip.get_destination(),
                                                udp.get_destination()
                                            );
                                        }
                                    }
                                    _ => {
                                        println!(
                                            "[{}] IPv4 {} -> {} (Other)",
                                            packets_received,
                                            ip.get_source(),
                                            ip.get_destination()
                                        );
                                    }
                                }
                            }
                        }

                        EtherTypes::Arp => {
                            println!("[{}] ARP packet", packets_received);
                        }

                        _ => {
                            println!("[{}] Other Ethernet frame", packets_received);
                        }
                    }
                }
            }

            Err(e) => {
                if e != pcap::Error::TimeoutExpired {
                    println!(
                        "The following error occurred while attempting to retrieve the next packet: {}",
                        e
                    );
                }
            }
        }
    }
}
