#!/bin/bash
# Test script for TLS VPN system
# This script demonstrates the testing procedure but requires root privileges to execute

set -e

echo "=== TLS VPN System Test Script ==="
echo "Note: This script requires root/sudo privileges"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run with sudo/root privileges"
    echo "Usage: sudo ./test.sh"
    exit 1
fi

# Build the application
echo "Step 1: Building application..."
go build -o vpn "TLS VPN 系统.go"
echo "✓ Build successful"
echo ""

# Start server in background
echo "Step 2: Starting VPN server..."
./vpn server > /tmp/vpn-server.log 2>&1 &
SERVER_PID=$!
sleep 3
echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ Server failed to start"
    cat /tmp/vpn-server.log
    exit 1
fi

# Check TUN device on server
echo "Step 3: Checking server TUN device..."
if ip addr show tun0 | grep -q "10.8.0.1"; then
    echo "✓ Server TUN device configured: 10.8.0.1/24"
else
    echo "✗ Server TUN device not configured properly"
    kill $SERVER_PID
    exit 1
fi
echo ""

# Start client in background
echo "Step 4: Starting VPN client..."
./vpn client > /tmp/vpn-client.log 2>&1 &
CLIENT_PID=$!
sleep 3
echo "✓ Client started (PID: $CLIENT_PID)"
echo ""

# Check if client is running
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo "✗ Client failed to start"
    cat /tmp/vpn-client.log
    kill $SERVER_PID
    exit 1
fi

# Check TUN device on client
echo "Step 5: Checking client TUN device..."
if ip addr show tun0 | grep -q "10.8.0.2"; then
    echo "✓ Client TUN device configured: 10.8.0.2/24"
else
    echo "✗ Client TUN device not configured properly"
    kill $CLIENT_PID
    kill $SERVER_PID
    exit 1
fi
echo ""

# Test connectivity: client to server
echo "Step 6: Testing connectivity (client -> server)..."
if ping -c 3 -W 2 10.8.0.1 > /dev/null 2>&1; then
    echo "✓ Client can ping server (10.8.0.1)"
else
    echo "✗ Client cannot ping server"
    kill $CLIENT_PID
    kill $SERVER_PID
    exit 1
fi
echo ""

# Test connectivity: server to client
echo "Step 7: Testing connectivity (server -> client)..."
if ping -c 3 -W 2 10.8.0.2 > /dev/null 2>&1; then
    echo "✓ Server can ping client (10.8.0.2)"
else
    echo "✗ Server cannot ping client"
    kill $CLIENT_PID
    kill $SERVER_PID
    exit 1
fi
echo ""

# Display statistics
echo "Step 8: Displaying statistics..."
echo ""
echo "=== Server TUN Interface ==="
ip -s link show tun0
echo ""
echo "=== Active Connections ==="
netstat -tn | grep :8080 | head -5
echo ""

# Cleanup
echo "Step 9: Cleaning up..."
kill $CLIENT_PID
kill $SERVER_PID
sleep 2
echo "✓ Processes terminated"
echo ""

echo "==================================="
echo "✓ All tests passed successfully!"
echo "==================================="
echo ""
echo "Server log:"
tail -20 /tmp/vpn-server.log
echo ""
echo "Client log:"
tail -20 /tmp/vpn-client.log
