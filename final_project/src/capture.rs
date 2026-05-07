use std::sync::mpsc;

use crate::analytics;
use crate::cli::Args;
use crate::packet_parser;

use pcap::{Capture, Device};

pub fn start_capture(args: Args, tx: Option<mpsc::Sender<analytics::PacketInfo>>) -> Result<(), Box<dyn std::error::Error>> {
    if args.list {
        list_interfaces()?;
        return Ok(());
    }

    let interface = match args.interface {
        Some(i) => i,
        None => {
            eprintln!("No interface specified.");
            eprintln!("Use --list to see available interfaces.");
            return Ok(());
        }
    };

    println!("==================================");
    println!(" Rust Packet Sniffer");
    println!("==================================\n");

    println!("Interface    : {}", interface);
    println!("Packet Limit : {}", args.count);

    match &args.filter {
        Some(f) => println!("Filter       : {}", f),
        None => println!("Filter       : none"),
    }

    println!("Promiscuous  : enabled");
    println!("\nCapture started...\n");

    let mut capture = Capture::from_device(interface.as_str())?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()?;

    if let Some(filter) = args.filter {
        capture.filter(&filter, true)?;
    }

    let mut packets_received = 0;

    while packets_received < args.count {
        match capture.next_packet() {
            Ok(packet) => {
                packets_received += 1;

                if let Some(ref sender) = tx {
                    let info = analytics::parse_packet(packet.data, packets_received);
                    if sender.send(info).is_err() {
                        break;
                    }
                } else {
                    packet_parser::handle_packet(packets_received, packet.data);
                }
            }

            Err(pcap::Error::TimeoutExpired) => {}

            Err(e) => {
                eprintln!("Packet capture error: {}", e);
            }
        }
    }

    println!("\n==================================");
    println!(" Capture Complete");
    println!("==================================");
    println!("Packets Captured : {}", packets_received);

    Ok(())
}

fn list_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    let devices = Device::list()?;

    println!("Available Interfaces:\n");

    for device in devices {
        println!(" - {}", device.name);
    }

    println!("\nUse one with:");
    println!("  rustsniff -i <interface>");

    Ok(())
}
