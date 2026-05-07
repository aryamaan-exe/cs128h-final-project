use std::sync::{Arc, Mutex};

use pcap;
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use crate::stats::Stats;

// Instead of printing each packet, we now receive a reference to the shared
// Stats object and silently update it. The dashboard thread reads Stats
// independently on its own timer.
pub fn start_capture(
    interface: Option<String>,
    count: usize,
    filter: Option<String>,
    stats: Arc<Mutex<Stats>>, // Arc = shared ownership across threads, Mutex = safe mutation
) {
    let dev = match interface {
        Some(val) => val,
        None => panic!("No interface specified"),
    };

    let inactive_capture = match pcap::Capture::from_device(dev.as_str()) {
        Ok(val) => val,
        Err(e) => panic!("Failed to open device: {}", e),
    };

    let mut cap = match inactive_capture
        .promisc(true)   // promiscuous mode: capture all packets, not just ours
        .snaplen(65535)  // max bytes to capture per packet
        .timeout(100)    // return from next_packet() after 100ms even if no packet arrived
        .open()
    {
        Ok(val) => val,
        Err(e) => panic!("Failed to open capture handle: {}", e),
    };

    if let Some(f) = &filter {
        if let Err(e) = cap.filter(f, true) {
            eprintln!("Failed to apply filter '{}': {}", f, e);
            return;
        }
    }

    let mut received = 0;

    while received < count {
        match cap.next_packet() {
            Ok(packet) => {
                received += 1;

                // Lock the mutex so we can safely write to Stats.
                // The lock is released automatically when `s` goes out of
                // scope at the end of this block — no manual unlock needed.
                let mut s = stats.lock().unwrap();
                s.total += 1;

                // Parse the Ethernet frame to get IP/protocol info
                if let Some(eth) = EthernetPacket::new(packet.data) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                // Record this source IP in the senders map.
                                // entry().or_insert(0) gives us the counter for this
                                // IP, creating it at 0 if it didn't exist yet.
                                let src = ip.get_source().to_string();
                                *s.senders.entry(src).or_insert(0) += 1;

                                match ip.get_next_level_protocol() {
                                    IpNextHeaderProtocols::Tcp => {
                                        let _ = TcpPacket::new(ip.payload()); // validate
                                        s.tcp += 1;
                                    }
                                    IpNextHeaderProtocols::Udp => {
                                        let _ = UdpPacket::new(ip.payload()); // validate
                                        s.udp += 1;
                                    }
                                    _ => s.other += 1,
                                }
                            }
                        }
                        EtherTypes::Arp => s.arp += 1,
                        _ => s.other += 1,
                    }
                }
                // `s` is dropped here → Mutex lock is released
            }

            Err(e) => {
                // TimeoutExpired just means no packet arrived in 100ms — that's normal.
                // Any other error is a real problem, but we can't print to stdout
                // while the TUI is running (it would corrupt the display), so we
                // silently ignore it here.
                if e != pcap::Error::TimeoutExpired {
                    let mut s = stats.lock().unwrap();
                    s.other += 0; // no-op, just a place to add error tracking later
                }
            }
        }
    }
}
