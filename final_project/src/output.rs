use chrono::Local;
use colored::*;

fn timestamp() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

pub fn print_transport(
    count: usize,
    protocol: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) {
    let proto_colored = match protocol {
        "TCP" => protocol.green(),
        "UDP" => protocol.blue(),
        _ => protocol.normal(),
    };

    println!(
        "[{}] [{:<4}] {:<21} -> {}:{}",
        timestamp(),
        proto_colored,
        format!("{}:{}", src_ip, src_port),
        dst_ip,
        dst_port
    );

    println!("       Packet #{}", count);
}

pub fn print_arp(count: usize) {
    println!("[{}] [{}] Packet #{}", timestamp(), "ARP".yellow(), count);
}

pub fn print_other(count: usize) {
    println!("[{}] [{}] Packet #{}", timestamp(), "OTHER".red(), count);
}

pub fn print_ipv4_other(count: usize, src_ip: &str, dst_ip: &str) {
    println!(
        "[{}] [{}] {} -> {} (Other IPv4)",
        timestamp(),
        "IPv4".cyan(),
        src_ip,
        dst_ip
    );

    println!("       Packet #{}", count);
}
