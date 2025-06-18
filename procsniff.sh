#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run as root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# CONFIGURABLE
NS="procsniff"                    # network namespace name
VETH_HOST="veth0"                 # host side veth interface
VETH_NS="veth1"                   # namespace side veth interface
HOST_IP="192.168.100.1"           # host veth IP
NS_IP="192.168.100.2"             # namespace veth IP
# Additional tcpdump arguments:
# Must be defined as a Bash array, e.g., to disable DNS and filter only IP packets:
# EXTRA_TCPDUMP_ARGS=( -n ip )
EXTRA_TCPDUMP_ARGS=( -n )         # leave empty for defaults

cleanup() {
    echo "[+] Cleaning up..."
    kill "${TCPDUMP_PID:-}" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST"   2>/dev/null || true
    
    # Cleanup NAT and forwarding rules if they exist
    iptables -t nat -D POSTROUTING -s 192.168.100.0/24 -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$VETH_HOST" -j ACCEPT 2>/dev/null || true
    
    echo "[+] Done."
}
trap cleanup EXIT

# Argument check
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 /path/to/output.pcap|- <program> [args...]" >&2
    exit 1
fi

PCAP_FILE="$1"
shift
PROGRAM=("$@")

# Remove leftovers
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_HOST"   2>/dev/null || true

echo "[+] Creating network namespace: $NS"
ip netns add "$NS"

echo "[+] Creating veth pair: $VETH_HOST <-> $VETH_NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"

echo "[+] Configuring host side ($VETH_HOST → $HOST_IP/24)"
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

echo "[+] Configuring namespace side ($VETH_NS → $NS_IP/24)"
ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$VETH_NS"
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$HOST_IP"

# Configure DNS for namespace
NS_RESOLV_DIR="/etc/netns/$NS"
mkdir -p "$NS_RESOLV_DIR"
{
    echo "nameserver 8.8.8.8"    # Google DNS
    echo "nameserver 1.1.1.1"    # Cloudflare DNS
} > "$NS_RESOLV_DIR/resolv.conf"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure NAT for internet access
iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j MASQUERADE
iptables -A FORWARD -i "$VETH_HOST" -j ACCEPT
iptables -A FORWARD -o "$VETH_HOST" -j ACCEPT

# Build tcpdump command with additional args
if [ "$PCAP_FILE" = "-" ]; then
    echo "[+] Starting tcpdump inside $NS, streaming human-readable output..."
    # -l: line-buffered for real-time
    TCPDUMP_CMD=( ip netns exec "$NS" tcpdump -i "$VETH_NS" "${EXTRA_TCPDUMP_ARGS[@]}" -l )
else
    echo "[+] Starting tcpdump inside $NS, saving pcap to $PCAP_FILE..."
    TCPDUMP_CMD=( ip netns exec "$NS" tcpdump -i "$VETH_NS" "${EXTRA_TCPDUMP_ARGS[@]}" -w "$PCAP_FILE" )
fi

# Create a temporary pipe for synchronization
PIPE=$(mktemp -u)
mkfifo -m 600 "$PIPE"

# Launch tcpdump, redirecting stderr to the pipe and preserving stdout
{
    "${TCPDUMP_CMD[@]}" 2>&1 1>&3 | tee "$PIPE" >&2
} 3>&1 &
TCPDUMP_PID=$!

# Wait for tcpdump's "listening" message to ensure it's ready
echo "[+] Waiting for tcpdump to start..."
grep -q -m1 "listening" "$PIPE"
rm -f "$PIPE"
echo "[+] Tcpdump is ready."

echo "[+] Launching program: ${PROGRAM[*]}"
ip netns exec "$NS" "${PROGRAM[@]}"