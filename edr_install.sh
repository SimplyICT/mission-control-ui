#!/bin/bash
# EDR Agent Installer — Foolproof single-command deploy
# Usage: curl -s http://SOC_SERVER:8095/api/edr/install | sudo bash
set -e

SOC_SERVER="${1:-208.87.135.84:8095}"
AGENT_SCRIPT="/usr/local/bin/edr_agent.py"
SERVICE_FILE="/etc/systemd/system/edr-agent.service"

echo "=== EDR Agent Installer ==="

# 1. Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi
echo "[OK] Python $(python3 --version)"

# 2. Install aiohttp (try pip3 first, fallback to pip, detect if already installed)
if python3 -c "import aiohttp" &>/dev/null; then
    echo "[OK] aiohttp already installed"
else
    echo "[..] Installing aiohttp..."
    # Try multiple methods to handle PEP 668 (Python 3.11+) and 3.10
    export PIP_REQUIRE_VIRTUALENV=0
    (pip3 install aiohttp -q --break-system-packages 2>/dev/null) ||     (pip3 install aiohttp -q 2>/dev/null) ||     (pip install aiohttp -q --break-system-packages 2>/dev/null) ||     (pip install aiohttp -q 2>/dev/null) ||     (python3 -m pip install aiohttp -q --user 2>/dev/null) ||     (python3 -m pip install aiohttp -q 2>/dev/null) || {
        echo "[WARN] pip install failed, trying apt..."
        apt-get install -y python3-aiohttp 2>/dev/null ||         dnf install -y python3-aiohttp 2>/dev/null ||         yum install -y python3-aiohttp 2>/dev/null || {
            echo "[WARN] Could not install aiohttp via pip or package manager"
        }
    }
    pip3 install websockets -q --break-system-packages 2>/dev/null || pip3 install websockets -q 2>/dev/null || true
fi

# 3. Download agent script
echo "[..] Downloading agent script..."
curl -sL "http://${SOC_SERVER}/api/agent/download/windows" -o "$AGENT_SCRIPT" 2>/dev/null
if [ ! -s "$AGENT_SCRIPT" ]; then
    echo "ERROR: Failed to download agent script"
    exit 1
fi
chmod +x "$AGENT_SCRIPT"
echo "[OK] Agent script saved to $AGENT_SCRIPT"

# 4. Create systemd service
echo "[..] Creating systemd service..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SOC Agent
After=network.target
Wants=network.target

[Service]
ExecStart=/usr/bin/python3 ${AGENT_SCRIPT} --server ${SOC_SERVER}
Restart=always
# Politeness: this runs on someone's working machine. Background scheduling, a small
# share of CPU and IO, an idle IO class, and a memory ceiling so a runaway scan cannot
# take the box down. The agent also lowers its own niceness and caps its log size.
Nice=10
CPUWeight=20
IOWeight=20
IOSchedulingClass=idle
MemoryMax=256M
LogRateLimitIntervalSec=30s
LogRateLimitBurst=500
RestartSec=10
StandardOutput=append:/var/log/soc-agent-boot.log
StandardError=append:/var/log/soc-agent-boot.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/dev/null || true

# 5. Start agent
echo "[..] Starting EDR agent..."
systemctl enable edr-agent 2>/dev/null || true
systemctl restart edr-agent 2>/dev/null || {
    # Fallback: run in background
    echo "[..] systemd not available, running in background"
    nohup python3 "$AGENT_SCRIPT" --server "$SOC_SERVER" > /var/log/soc-agent-boot.log 2>&1 &
    echo "[OK] Agent started in background (PID $!)"
}

echo ""
echo "=== EDR Agent Deployed ==="
echo "Status: $(systemctl is-active edr-agent 2>/dev/null || echo 'running')"
echo "Logs:   tail -f /var/log/soc-agent.log"
echo ""

# 6. Quick connectivity test
sleep 2
if grep -q "Connected" /var/log/soc-agent.log 2>/dev/null; then
    echo "[OK] Agent connected to SOC server"
else
    echo "[WARN] Agent may not have connected yet. Check logs:"
    echo "  tail -20 /var/log/soc-agent.log"
fi
