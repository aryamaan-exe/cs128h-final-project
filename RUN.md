# Rust Packet Sniffer

A packet capture tool with both a terminal output mode and a live GUI dashboard.
Built with `pcap`, `clap`, `ratatui`, and `egui` (`eframe`).

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

### Terminal mode (original)

Prints formatted, colored packet output to the terminal:

```bash
sudo cargo run -- -i en0
sudo cargo run -- -i en0 -c 50
sudo cargo run -- -i en0 -f "tcp port 443"
```

### GUI mode

Opens a native window with a live dashboard:

```bash
sudo cargo run -- -i en0 --gui
```

Terminal output still appears in the terminal while the window is open.
Close the window to stop the GUI; the capture thread exits automatically.

The dashboard has two tabs:

- **Live Feed** — scrolling packet log with timestamp, protocol, source→dest.
  Uncheck *Auto-scroll* to pause scrolling and read older entries.
- **Metrics** — packets/sec and bytes/sec line graphs (rolling 60 s window),
  protocol breakdown bar chart, and a top-talkers table (sorted by packet count).

### Optional flags

| Flag          | Short | Description                          | Default |
|---------------|-------|--------------------------------------|---------|
| `--interface` | `-i`  | Network interface to capture on      | (required) |
| `--count`     | `-c`  | Stop after N packets                 | 100 |
| `--filter`    | `-f`  | BPF filter expression                | (none) |
| `--gui`       |       | Open the GUI dashboard               | off |
| `--list`      |       | List available interfaces and exit   | — |

### Filter examples

```bash
sudo cargo run -- -i en0 -f "tcp"
sudo cargo run -- -i en0 -f "host 8.8.8.8"
sudo cargo run -- -i en0 -f "tcp port 443"
```

### Generate test traffic (in a separate terminal)

```bash
ping -c 5 127.0.0.1
```

On Windows, run as Administrator instead of using `sudo`, and use
`cargo run -- --list` to find your interface name.
