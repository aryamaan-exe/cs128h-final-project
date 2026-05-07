use pcap;
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

pub fn start_capture(interface: Option<String>, count: usize, filter: Option<String>) {
    let dev = match interface {
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

    if let Some(f) = &filter {
        if let Err(e) = capture1.filter(f, true) {
            eprintln!("Failed to apply filter '{}': {}", f, e);
            return;
        }
        println!("Filter applied: {}", f);
    }

    println!("Capture handle opened, starting capture on {}...", dev);

    let mut packets_received = 0;

    while packets_received < count {
        match capture1.next_packet() {
            Ok(packet) => {
                packets_received += 1;

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
