use std::collections::HashMap;

// This struct holds every metric the dashboard displays.
// It lives inside an Arc<Mutex<Stats>> so two threads can safely share it:
//   - the capture thread writes to it on every packet
//   - the dashboard thread reads it ~5 times per second to refresh the screen
pub struct Stats {
    pub total: usize,

    // Protocol breakdown
    pub tcp: usize,
    pub udp: usize,
    pub arp: usize,
    pub other: usize,

    // Maps a source IP string (e.g. "192.168.1.5") to how many packets
    // we have seen from that address.
    pub senders: HashMap<String, usize>,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            total: 0,
            tcp: 0,
            udp: 0,
            arp: 0,
            other: 0,
            senders: HashMap::new(),
        }
    }
}
