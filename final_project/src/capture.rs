use pcap;

pub fn start_capture(interface: Option<String>, count: usize) {
    let dev = match interface {
            Some(val) => val,
            None => {
                panic!("There was an issue with finding the specified interface");
            }
        };
    let inactive_capture = match pcap::Capture::from_device(dev.as_str()) {
        Ok(val) => val,
        Err(e) => {
            panic!("There was an issue with finding the specified interface: {}", e);
        }
    };
    let mut capture1 = match inactive_capture.promisc(true).snaplen(65535).timeout(100).open() {
        Ok(val) => val,
        Err(e) => {
            panic!("Failed to open capture handle: {}", e);
        }
    };
    println!("Capture handle opened, starting capture on {}...", dev);
    let mut packets_received = 0;
    while packets_received < count {
        match capture1.next_packet() {
            Ok(packet) => {
                packets_received += 1;
                println!("\nReceived packet {} out of {}. \n{:?}", packets_received, count, packet);
            }
            Err(e) => {
                if e != pcap::Error::TimeoutExpired {
                println!("The following error occurred while attempting to retrieve the next packet: {}", e);
                }
            }
        }
    }
}