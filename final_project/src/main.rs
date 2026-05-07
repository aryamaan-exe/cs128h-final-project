mod analytics;
mod capture;
mod cli;
mod dashboard;
mod output;
mod packet_parser;

use clap::Parser;
use cli::Args;

fn main() {
    let args = Args::parse();

    if args.gui {
        dashboard::run(args);
    } else {
        if let Err(e) = capture::start_capture(args, None) {
            eprintln!("Error: {}", e);
        }
    }
}
