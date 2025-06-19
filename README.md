# Procsniff - Process-Level Network Traffic Sniffer for Linux

Capture network traffic of individual processes using Linux network namespaces with isolation and internet access

## Features

- **Process Isolation**: Run applications in dedicated network namespaces
- **Flexible Capture**: Save PCAPs for analysis or view real-time traffic
- **Internet Access**: Full outbound connectivity via NAT
- **Automatic Cleanup**: Removes all network resources on exit
- **Configurable**: Customize IPs, interfaces, and tcpdump filters
- **DNS Support**: Pre-configured with Google/Cloudflare DNS

## Usage

```bash
sudo ./procsniff.sh OUTPUT.pcap PROGRAM [ARGS...]  # Capture to file
sudo ./procsniff.sh - PROGRAM [ARGS...]            # Real-time output
```


## Examples

### Basic Traffic Capture
```bash
# Capture curl traffic to file
sudo ./procsniff.sh curl.pcap curl -I https://example.com

# View real-time ping traffic
sudo ./procsniff.sh - ping 8.8.8.8
```

### Advanced Use Cases
```bash
# Capture DNS traffic only
# change in file EXTRA_TCPDUMP_ARGS="( -n port 53 )"
sudo ./procsniff.sh dns.pcap dig example.com
```

💡 **Pro Tip**: Use `bash -c` for complex commands with pipes/redirection:
```bash
sudo ./procsniff.sh output.pcap bash -c 'curl example.com | grep title > result.html'
```


## Configuration

Customize these variables at the top of the script:
```bash
NS="procsniff"                  # Namespace name
VETH_HOST="veth0"               # Host-side interface
VETH_NS="veth1"                 # Namespace-side interface
HOST_IP="192.168.100.1"         # Host IP
NS_IP="192.168.100.2"           # Namespace IP
EXTRA_TCPDUMP_ARGS=( -n )       # Additional tcpdump flags
```

## Requirements

- **Linux Kernel**: 4.0+ (with network namespace support)
- **Dependencies**: iproute2, iptables, tcpdump
- **Shell**: Bash 4.0+
- **Permissions**: Root access (for network operations)

## Installation

```bash
git clone https://github.com/Mohammad-Saad-Acacus/procsniff.git
cd procsniff
chmod +x procsniff.sh
```

