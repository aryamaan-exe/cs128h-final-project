use crate::output;

use pnet_packet::{
    Packet,
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
};

pub fn handle_packet(count: usize, data: &[u8]) {
    if let Some(ethernet) = EthernetPacket::new(data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => parse_ipv4(count, ethernet.payload()),

            EtherTypes::Arp => {
                output::print_arp(count);
            }

            _ => {
                output::print_other(count);
            }
        }
    }
}

fn parse_ipv4(count: usize, payload: &[u8]) {
    if let Some(ip) = Ipv4Packet::new(payload) {
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => parse_tcp(count, &ip),

            IpNextHeaderProtocols::Udp => parse_udp(count, &ip),

            _ => {
                output::print_ipv4_other(
                    count,
                    &ip.get_source().to_string(),
                    &ip.get_destination().to_string(),
                );
            }
        }
    }
}

fn parse_tcp(count: usize, ip: &Ipv4Packet) {
    if let Some(tcp) = TcpPacket::new(ip.payload()) {
        output::print_transport(
            count,
            "TCP",
            &ip.get_source().to_string(),
            tcp.get_source(),
            &ip.get_destination().to_string(),
            tcp.get_destination(),
        );
    }
}

fn parse_udp(count: usize, ip: &Ipv4Packet) {
    if let Some(udp) = UdpPacket::new(ip.payload()) {
        output::print_transport(
            count,
            "UDP",
            &ip.get_source().to_string(),
            udp.get_source(),
            &ip.get_destination().to_string(),
            udp.get_destination(),
        );
    }
}
