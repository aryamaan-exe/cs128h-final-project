mod capture;
mod cli;
mod output;
mod packet_parser;

use clap::Parser;
use cli::Args;

fn main() {
    let args = Args::parse();

    if let Err(e) = capture::start_capture(args) {
        eprintln!("Error: {}", e);
    }
}
