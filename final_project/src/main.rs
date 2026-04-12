use clap::Parser;
use pcap::Device;
#[derive(Parser, Debug)]
struct Args {
    // network interface to capture on: ethernet, wifi card, etc.
    #[arg(short, long)]
    interface: Option<String>,
    // number of packets to capture
    #[arg(short, long, default_value_t = 100)]
    count: usize,
    // used to print available interface
    #[arg(long)]
    list: bool
}

fn main() {
    let cli_arguments: Args = Args::parse();
    // if --list flag is utilized
    if cli_arguments.list {
        let device_interface_list = match Device::list() {
            Ok(vector) => vector,
            Err(e) => {
                println!("The following error was arose trying to generate a custom device interface list: \n{}", e);
                return;
            }
        };
        println!("List of custom device interfaces: ");
        for device_interface in &device_interface_list {
            println!("{}", device_interface.name);
        }
        println!("Use one of the interfaces above with the --interface flag to capture packets on that interface.");
    } else {
        // if --list flag is NOT utilized
        match cli_arguments.interface {
            Some(val) => println!("Interface: {}", val),
            None => {
                println!("No flags utilized, please reference RUN.md for specifications");
            }
        } 
    }  
}


// This function should take in and out something
// fn encrypt() {
//     todo!()
// }

// This function should take in and out something
// fn decrypt() {
//     todo!()
// }