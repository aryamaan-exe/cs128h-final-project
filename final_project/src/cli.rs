use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustsniff",
    version,
    about = "A lightweight packet sniffer written in Rust",
    after_help = "\
Examples:
  rustsniff --list
  rustsniff -i en0
  rustsniff -i en0 --gui
  rustsniff -i wlan0 -c 50
  rustsniff -i eth0 -f \"tcp port 80\"
"
)]
pub struct Args {
    /// Network interface to capture on
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Number of packets to capture
    #[arg(short, long, default_value_t = 10_000_000)]
    pub count: usize,

    /// List available interfaces
    #[arg(long)]
    pub list: bool,

    /// BPF filter (example: "tcp port 80")
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Open the GUI dashboard instead of printing to the terminal
    #[arg(long)]
    pub gui: bool,
}
