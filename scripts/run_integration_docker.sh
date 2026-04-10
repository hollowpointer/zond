#!/bin/bash
# Zond Phase 1: Topological Integration Test Runner
# 
# Verifies Multi-NIC discovery, DNS resolution, and Routed segment discovery.

set -e

# 1. Argument Parsing
CHAOS=0
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --chaos) CHAOS=1 ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# 2. Note: Build is now handled inside the scanner.Dockerfile multi-stage build.
echo ">>> (Build handled by Docker Compose)"

# 3. Start the environment
echo ">>> Bringing up Docker nodes..."
docker compose -f docker-compose.test.yml up --build -d

# Give containers a second to start
sleep 3

# 4. Setup Routes for Discovery
echo ">>> Extracting gateway IP..."
for i in {1..5}; do
    GATEWAY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' zond-gateway | tr ' ' '\n' | grep '172.20.' | head -n 1)
    if [ ! -z "$GATEWAY_IP" ]; then
        break
    fi
    echo "Wait for gateway IP... ($i/5)"
    sleep 2
done

if [ -z "$GATEWAY_IP" ]; then
    echo "Error: Could not find gateway IP on LAN network."
    docker compose -f docker-compose.test.yml down
    exit 1
fi

echo ">>> Setting up static route to isolated network via gateway at $GATEWAY_IP..."
docker exec zond-integration-scanner ip route add 172.30.0.0/24 via $GATEWAY_IP

# 5. Inject Chaos (Impairment) if requested
if [ "$CHAOS" -eq 1 ]; then
    echo ">>> [CHAOS] Injecting Network Impairment..."
    echo ">>> [CHAOS] target-lan: 10% Packet Loss"
    docker exec zond-target-lan tc qdisc add dev eth0 root netem loss 10%
    echo ">>> [CHAOS] target-isolated: 250ms Latency"
    docker exec zond-target-isolated tc qdisc add dev eth0 root netem delay 250ms
fi

# 6. Perform Phase 1 Tests
echo ">>> [Phase 1] Executing Topological Discovery Scan..."

# Scan all three target subnets
# - 172.20.0.0/24 (LAN 1)
# - 172.25.0.0/24 (LAN 2 - Extra NIC)
# - 172.30.0.0/24 (Routed Isolated)
EXIT_CODE=0
docker exec zond-integration-scanner ./zond -vvv discover 172.20.0.0/24 172.25.0.0/24 172.30.0.0/24 || EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ">>> Scan failed with exit code $EXIT_CODE. Container logs:"
    docker logs zond-integration-scanner
fi

# 7. Cleanup
echo ">>> Tearing down Docker nodes..."
if [ "$CHAOS" -eq 1 ]; then
    # Clear chaos rules (optional as containers are being destroyed, but good for local dev)
    docker exec zond-target-lan tc qdisc del dev eth0 root netem 2>/dev/null || true
    docker exec zond-target-isolated tc qdisc del dev eth0 root netem 2>/dev/null || true
fi
docker compose -f docker-compose.test.yml down

exit $EXIT_CODE
