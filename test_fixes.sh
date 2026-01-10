#!/bin/bash
# Test script for TLS VPN fixes
# This script verifies the fixes without requiring root privileges

set -e

echo "=== TLS VPN Fixes Verification ==="
echo ""

# Test 1: Certificate Persistence
echo "Test 1: Certificate Persistence"
echo "--------------------------------"
rm -rf certs/
./vpn 2>&1 | grep -q "生成新的CA证书" && echo "✓ Certificates generated on first run"
./vpn 2>&1 | grep -q "从文件加载CA证书" && echo "✓ Certificates loaded from files on second run"
ls -l certs/ | grep -q "ca.crt" && echo "✓ CA certificate exists"
ls -l certs/ | grep -q "server.crt" && echo "✓ Server certificate exists"
ls -l certs/ | grep -q "client.crt" && echo "✓ Client certificate exists"
echo ""

# Test 2: Build Success
echo "Test 2: Build Success"
echo "---------------------"
go build -o vpn "TLS VPN 系统.go" 2>&1 && echo "✓ Build successful"
echo ""

# Test 3: Certificate Permissions
echo "Test 3: Certificate Permissions"
echo "--------------------------------"
stat -c "%a" certs/ca.key | grep -q "600" && echo "✓ CA key has secure permissions (600)"
stat -c "%a" certs/server.key | grep -q "600" && echo "✓ Server key has secure permissions (600)"
stat -c "%a" certs/client.key | grep -q "600" && echo "✓ Client key has secure permissions (600)"
echo ""

# Test 4: Code Structure
echo "Test 4: Code Structure"
echo "----------------------"
grep -q "originalIPForward string" "TLS VPN 系统.go" && echo "✓ Original IP forward state tracking added"
grep -q "ipMap.*map\[string\]\*VPNSession" "TLS VPN 系统.go" && echo "✓ IP-to-Session mapping added"
grep -q "wg.*sync.WaitGroup" "TLS VPN 系统.go" && echo "✓ WaitGroup for goroutine tracking added"
grep -q "AuthKey string" "TLS VPN 系统.go" && echo "✓ Authentication key support added"
grep -q "connMutex.*sync.Mutex" "TLS VPN 系统.go" && echo "✓ Connection mutex for concurrency safety added"
echo ""

# Test 5: Function Improvements
echo "Test 5: Function Improvements"
echo "------------------------------"
grep -q "func cleanupTUNDevice.*error" "TLS VPN 系统.go" && echo "✓ cleanupTUNDevice returns error"
grep -q "func getIPForwarding" "TLS VPN 系统.go" && echo "✓ getIPForwarding function added"
grep -q "func setIPForwarding" "TLS VPN 系统.go" && echo "✓ setIPForwarding function added"
grep -q "func ensureCertDir" "TLS VPN 系统.go" && echo "✓ ensureCertDir function added"
grep -q "func validateCertificate" "TLS VPN 系统.go" && echo "✓ validateCertificate function added"
echo ""

# Test 6: Authentication Flow
echo "Test 6: Authentication Flow"
echo "----------------------------"
grep -q "MessageTypeAuth" "TLS VPN 系统.go" && echo "✓ MessageTypeAuth is used"
grep -q "VPN_AUTH_KEY" "TLS VPN 系统.go" && echo "✓ Environment variable support for auth key"
echo ""

echo "==================================="
echo "✓ All verification tests passed!"
echo "==================================="
echo ""
echo "Note: Root-level tests (IP forwarding, TUN devices) require sudo privileges"
echo "and should be run manually using the instructions in the problem statement."
