use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use chrono::Local;
use pnet_packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};


#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Arp,
    Other,
}

#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub time_str: String,
    pub number: usize,
    pub protocol: Protocol,
    pub src: String,
    pub dst: String,
    pub src_ip: Option<String>,
    pub size: usize,
}

pub fn parse_packet(data: &[u8], number: usize) -> PacketInfo {
    let timestamp = Instant::now();
    let time_str = Local::now().format("%H:%M:%S").to_string();
    let size = data.len();

    if let Some(eth) = EthernetPacket::new(data) {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                    let src_ip_str = ip.get_source().to_string();
                    let dst_ip_str = ip.get_destination().to_string();
                    let src_ip = Some(src_ip_str.clone());

                    match ip.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                return PacketInfo {
                                    timestamp, time_str, number, size,
                                    protocol: Protocol::Tcp,
                                    src: format!("{}:{}", src_ip_str, tcp.get_source()),
                                    dst: format!("{}:{}", dst_ip_str, tcp.get_destination()),
                                    src_ip,
                                };
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ip.payload()) {
                                return PacketInfo {
                                    timestamp, time_str, number, size,
                                    protocol: Protocol::Udp,
                                    src: format!("{}:{}", src_ip_str, udp.get_source()),
                                    dst: format!("{}:{}", dst_ip_str, udp.get_destination()),
                                    src_ip,
                                };
                            }
                        }
                        _ => {
                            return PacketInfo {
                                timestamp, time_str, number, size,
                                protocol: Protocol::Other,
                                src: src_ip_str,
                                dst: dst_ip_str,
                                src_ip,
                            };
                        }
                    }
                }
            }
            EtherTypes::Arp => {
                return PacketInfo {
                    timestamp, time_str, number, size,
                    protocol: Protocol::Arp,
                    src: "ARP".to_string(),
                    dst: "ARP".to_string(),
                    src_ip: None,
                };
            }
            _ => {}
        }
    }

    PacketInfo {
        timestamp, time_str, number, size,
        protocol: Protocol::Other,
        src: "N/A".to_string(),
        dst: "N/A".to_string(),
        src_ip: None,
    }
}

pub struct Analytics {
    pub feed: Vec<PacketInfo>,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub arp_count: u64,
    pub other_count: u64,
    pub top_talkers: HashMap<String, (u64, u64)>,
    recent: VecDeque<(Instant, usize)>,
    pub time_series: VecDeque<[f64; 2]>,
    last_tick: Instant,
}

impl Analytics {
    pub fn new() -> Self {
        Analytics {
            feed: Vec::new(),
            tcp_count: 0,
            udp_count: 0,
            arp_count: 0,
            other_count: 0,
            top_talkers: HashMap::new(),
            recent: VecDeque::new(),
            time_series: VecDeque::new(),
            last_tick: Instant::now(),
        }
    }

    pub fn add_packet(&mut self, info: PacketInfo) {
        match info.protocol {
            Protocol::Tcp => self.tcp_count += 1,
            Protocol::Udp => self.udp_count += 1,
            Protocol::Arp => self.arp_count += 1,
            Protocol::Other => self.other_count += 1,
        }

        if let Some(ip) = &info.src_ip {
            let entry = self.top_talkers.entry(ip.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += info.size as u64;
        }

        self.recent.push_back((info.timestamp, info.size));

        if self.feed.len() >= 10_000 {
            self.feed.remove(0);
        }
        self.feed.push(info);
    }

    pub fn tick_time_series(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_tick) < Duration::from_secs(1) {
            return;
        }

        let one_sec_ago = now - Duration::from_secs(1);
        let mut pps = 0u64;
        let mut bps = 0u64;
        for (t, sz) in &self.recent {
            if *t >= one_sec_ago {
                pps += 1;
                bps += *sz as u64;
            }
        }

        let cutoff = now - Duration::from_secs(65);
        while let Some((t, _)) = self.recent.front() {
            if *t < cutoff {
                self.recent.pop_front();
            } else {
                break;
            }
        }

        if self.time_series.len() >= 60 {
            self.time_series.pop_front();
        }
        self.time_series.push_back([pps as f64, bps as f64]);

        self.last_tick = now;
    }
}
