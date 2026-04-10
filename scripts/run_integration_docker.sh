#!/bin/bash
# Zond Docker Integration Test Runner
# 
# This script builds the Zond binaries, brings up the Docker Compose environment,
# and executes the integration scanner to verify network-wide discovery.

set -e

# 1. Build the project to ensure we have fresh binaries
echo ">>> Building Zond binaries..."
cargo build

# 2. Build and start the Docker environment
echo ">>> Bringing up Docker nodes..."
docker-compose -f docker-compose.test.yml up --build -d

# Give containers a second to start listeners
sleep 2

# 3. Perform a discovery scan from the scanner node
echo ">>> Executing Zond discovery scan from scanner node..."
docker exec zond-integration-scanner ./target/debug/zond discover 172.20.0.0/24 172.30.0.0/24

# 4. Cleanup
echo ">>> Tearing down Docker nodes..."
docker-compose -f docker-compose.test.yml down

echo ">>> Docker Integration tests completed successfully."
