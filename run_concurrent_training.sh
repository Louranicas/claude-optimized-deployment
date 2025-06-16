#!/bin/bash
# Concurrent SYNTHEX Discovery and BASHGOD Training

echo "=========================================="
echo "SYNTHEX & BASHGOD CONCURRENT DEPLOYMENT"
echo "=========================================="
echo

# Function to handle cleanup on exit
cleanup() {
    echo
    echo "Stopping processes..."
    if [ ! -z "$BASHGOD_PID" ]; then
        kill $BASHGOD_PID 2>/dev/null
    fi
    exit 0
}

trap cleanup INT TERM

# Run SYNTHEX Discovery
echo "1. Launching SYNTHEX Discovery Fleet..."
echo "   Deploying 10 agents to find new bash commands..."
python3 synthex_bash_discovery.py &
SYNTHEX_PID=$!

# Wait a moment for SYNTHEX to start
sleep 2

# Start BASHGOD Training in standalone mode (visible)
echo
echo "2. Starting BASHGOD Continuous Training..."
echo "   Running in foreground mode for visibility..."
python3 bashgod_continuous_training.py run &
BASHGOD_PID=$!

# Wait for SYNTHEX to complete
echo
echo "Waiting for SYNTHEX discovery to complete..."
wait $SYNTHEX_PID
echo "✓ SYNTHEX discovery complete!"

echo
echo "BASHGOD continues training in the background."
echo "Press Ctrl+C to stop training..."
echo

# Keep script running while BASHGOD trains
wait $BASHGOD_PID