# Procsniff - Process Traffic Sniffer

Capture network traffic of individual processes using Linux network namespaces.

## Features

- Isolates processes in dedicated network namespaces
- Captures traffic to PCAP files or displays in real-time
- Provides internet access via NAT
- Automatic cleanup of network resources
- Configurable network parameters

## Usage

```bash
sudo ./procsniff.sh OUTPUT.pcap PROGRAM [ARGS...]
sudo ./procsniff.sh - PROGRAM [ARGS...]  # Real-time output
```

## Examples

```bash
# Capture curl traffic to file
sudo ./procsniff.sh curl.pcap curl -I https://example.com

# View real-time ping traffic
sudo ./procsniff.sh - ping 8.8.8.8

# Capture browser traffic (replace with actual browser command)
sudo ./procsniff.sh firefox.pcap firefox --new-instance https://example.com
```

## Configuration

Edit these variables in the script:

```bash
NS="procsniff"                  # Namespace name
VETH_HOST="veth0"               # Host-side interface
VETH_NS="veth1"                 # Namespace-side interface
HOST_IP="192.168.100.1"         # Host IP
NS_IP="192.168.100.2"           # Namespace IP
EXTRA_TCPDUMP_ARGS=( -n )       # Additional tcpdump flags
```

## Requirements

- Linux kernel 4.0+ (network namespace support)
- iproute2, iptables, tcpdump
- Bash 4.0+
- Root privileges

## Installation

```bash
git clone https://github.com/Mohammad-Saad-Acacus/procsniff.git
cd procsniff
chmod +x procsniff.sh
```
