# Simplified Wireshark

A CLI packet capture tool built with `pcap` and `clap`.

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

Capture 10 packets (use `lo0` on macOS, `lo` on Linux):

```bash
sudo cargo run -- -i lo0 -c 10
```

In a separate terminal, generate test traffic:

```bash
ping -c 5 127.0.0.1
```

On Windows, run the terminal as Administrator instead of using `sudo`, and use `cargo run -- --list` to find your desired interface name.