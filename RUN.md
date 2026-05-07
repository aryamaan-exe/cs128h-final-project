# Simplified Wireshark

A live packet capture dashboard built with `pcap`, `clap`, and `ratatui`.

## Prerequisites

- Rust/Cargo installed
- Linux: `sudo apt install libpcap-dev`
- macOS: preinstalled
- Windows: install Npcap from https://npcap.com
- Root/admin privileges required for packet capture

## Running

```bash
git clone <repo-url>
cd cs128h-final-project/final_project
```

List available interfaces:

```bash
sudo cargo run -- --list
```

Launch the dashboard (use `lo0` on macOS, `lo` on Linux):

```bash
sudo cargo run -- -i lo0
```

The dashboard updates live and shows:
- Total packets received
- Protocol breakdown (TCP / UDP / ARP / Other)
- Top senders by packet count

Press **q** to quit.

### Optional flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--interface` | `-i` | Network interface to capture on | (required) |
| `--count` | `-c` | Stop after N packets | 10,000,000 |
| `--filter` | `-f` | BPF filter expression | (none) |

### Filter examples

```bash
# Only TCP traffic
sudo cargo run -- -i en0 -f "tcp"

# Only traffic to/from a specific host
sudo cargo run -- -i en0 -f "host 8.8.8.8"

# Only traffic on port 443 (HTTPS)
sudo cargo run -- -i en0 -f "tcp port 443"
```

### Generate test traffic (in a separate terminal)

```bash
ping -c 5 127.0.0.1
```

On Windows, run the terminal as Administrator instead of using `sudo`, and use `cargo run -- --list` to find your interface name.
