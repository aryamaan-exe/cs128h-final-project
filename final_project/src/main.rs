mod capture;
mod dashboard;
mod stats;

use std::sync::{Arc, Mutex};

use clap::Parser;
use pcap::Device;
use stats::Stats;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short, long, default_value_t = 10_000_000)]
    count: usize,

    #[arg(long)]
    list: bool,

    #[arg(short, long)]
    filter: Option<String>,
}

fn main() {
    let args: Args = Args::parse();

    if args.list {
        match Device::list() {
            Ok(devices) => {
                for d in &devices {
                    println!("{}", d.name);
                }
            }
            Err(e) => println!("Error listing devices: {}", e),
        }
        return;
    }

    if args.interface.is_none() {
        println!("Specify an interface with --interface. Use --list to see options.");
        return;
    }

    let stats = Arc::new(Mutex::new(Stats::new()));

    let stats_for_capture = Arc::clone(&stats);

    std::thread::spawn(move || {
        capture::start_capture(
            args.interface,
            args.count,
            args.filter,
            stats_for_capture,
        );
    });

    if let Err(e) = dashboard::run_dashboard(stats) {
        eprintln!("Dashboard error: {}", e);
    }
}
