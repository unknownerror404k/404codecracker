#!/bin/bash
# ============================================================
#  404 CODE CRACKER - One-Line Installer
#  Usage:
#  curl -sSL https://raw.githubusercontent.com/unknownerror404k/404codecracker/main/install.sh | bash
# ============================================================

echo ""
echo "404 CODE CRACKER - INSTALLER"
echo "============================"
echo ""

# ── Step 1: Check Python ──
echo "[1/4] Checking Python ..."
if ! command -v python3 &> /dev/null; then
    echo "  Installing Python 3 ..."
    sudo apt install -y python3 python3-pip < /dev/null
fi
echo "✓ Python $(python3 --version 2>&1 | cut -d' ' -f2) found"

# ── Step 2: Install system dependencies ──
echo "[2/4] Installing system dependencies ..."
sudo apt install -y libzbar0 python3-tk < /dev/null 2>/dev/null
echo "✓ System packages installed"

# ── Step 3: Install 404 Code Cracker ──
echo "[3/4] Installing 404 Code Cracker ..."
REPO="https://github.com/unknownerror404k/404codecracker/archive/refs/heads/main.zip"

# Try normal pip install first
if pip3 install -q "$REPO" < /dev/null 2>/dev/null; then
    echo "✓ 404 Code Cracker installed"
else
    # Kali Linux / Debian 12+ / Ubuntu 23.04+ block system pip (PEP 668)
    # Retry with --break-system-packages flag
    echo "  Detected externally-managed environment (Kali/Debian 12+)"
    echo "  Using --break-system-packages flag ..."
    if pip3 install -q --break-system-packages "$REPO" < /dev/null; then
        echo "✓ 404 Code Cracker installed"
    else
        # Last resort: install as user with the flag
        echo "  Trying user install ..."
        if pip3 install -q --user --break-system-packages "$REPO" < /dev/null; then
            echo "✓ 404 Code Cracker installed (user mode)"
        else
            echo ""
            echo "✗ INSTALLATION FAILED"
            echo ""
            echo "  Try manually with this command:"
            echo "  pip3 install --break-system-packages $REPO"
            echo ""
            exit 1
        fi
    fi
fi

# ── Step 4: Verify and launch ──
echo "[4/4] Verifying installation ..."
if command -v 404codecracker &> /dev/null; then
    echo "✓ Command '404codecracker' is ready!"
    echo ""
    echo "══════════════════════════════════════════════"
    echo "  INSTALLATION COMPLETE!"
    echo "══════════════════════════════════════════════"
    echo ""
    echo "  To open the tool anytime, type:"
    echo "      404codecracker"
    echo ""
    echo "  Opening now ..."
    echo ""
    # Launch the GUI
    404codecracker &
else
    # Command not on PATH - try running the module directly
    echo "✓ Installed. Launching ..."
    python3 -m code404cracker &
fi
