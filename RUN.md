# Simplified Wireshark

A CLI packet capture tool built with `pcap` and `clap`.

## Prerequisites

- Rust/Cargo installed
- `libpcap-dev` (Ubuntu: `sudo apt install libpcap-dev`)
- `sudo` privileges for packet capture

## Running

```bash
git clone <repo-url>
cd cs128h-final-project/final_project
```

List available interfaces:

```bash
sudo cargo run -- --list
```

Capture packets:

```bash
sudo cargo run -- -i lo -c 10
```
