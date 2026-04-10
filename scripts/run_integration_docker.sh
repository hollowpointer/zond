#!/bin/bash
# Zond Phase 1: Topological Integration Test Runner
# 
# Verifies Multi-NIC discovery, DNS resolution, and Routed segment discovery.

set -e

# 1. Note: Build is now handled inside the scanner.Dockerfile multi-stage build.
echo ">>> (Build handled by Docker Compose)"
# cargo build is no longer necessary on host

# 2. Start the environment
echo ">>> Bringing up Docker nodes..."
docker compose -f docker-compose.test.yml up --build -d

# Give containers a second to start
sleep 3

# 3. Setup Routes for Discovery
# We need to tell the scanner how to reach the isolated network (172.30.0.0/24) via the gateway
# We search all networks for the one in the 172.20.0.0/24 subnet
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

# 4. Perform Phase 1 Tests
echo ">>> [Phase 1] Executing Topological Discovery Scan..."

# Scan all three target subnets
# - 172.20.0.0/24 (LAN 1)
# - 172.25.0.0/24 (LAN 2 - Extra NIC)
# - 172.30.0.0/24 (Routed Isolated)
# We turn on trace logging to see what's happening
EXIT_CODE=0
docker exec zond-integration-scanner ./zond -vvv discover 172.20.0.0/24 172.25.0.0/24 172.30.0.0/24 || EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ">>> Scan failed with exit code $EXIT_CODE. Container logs:"
    docker logs zond-integration-scanner
fi

# 5. Cleanup
echo ">>> Tearing down Docker nodes..."
docker compose -f docker-compose.test.yml down

exit $EXIT_CODE
