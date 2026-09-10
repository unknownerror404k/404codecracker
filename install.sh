#!/bin/bash
# 404 CODE CRACKER - One-Line Installer
# Automatically installs system deps + Python deps + tool

set -e

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  404 CODE CRACKER - INSTALLER                ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# Step 1: Check Python
echo "  [1/4] Checking Python..."
if command -v python3 &>/dev/null; then
    PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "       ✓ Python $PYVER found"
else
    echo "       ✗ Python 3 not found. Please install Python 3.10+ first."
    echo "         On Kali/Debian: sudo apt install python3 python3-pip"
    exit 1
fi

# Step 2: Install system dependencies
echo "  [2/4] Installing system dependencies..."
if command -v apt &>/dev/null; then
    sudo apt update -qq && sudo apt install -y -qq libzbar0 python3-tk 2>/dev/null || {
        echo "       ! Could not install libzbar0/python3-tk via apt"
        echo "       ! Image features (QR/steganography) may not work"
    }
    echo "       ✓ System packages installed"
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm zbar tk 2>/dev/null || true
    echo "       ✓ System packages installed"
elif command -v dnf &>/dev/null; then
    sudo dnf install -y zbar python3-tkinter 2>/dev/null || true
    echo "       ✓ System packages installed"
else
    echo "       ! Unknown package manager. Please install manually:"
    echo "         libzbar0 and python3-tk"
fi

# Step 3: Install the tool from GitHub
echo "  [3/4] Installing 404 Code Cracker..."
pip3 install --user git+https://github.com/unknownerror404k/404codecracker.git 2>/dev/null || \
pip install --user git+https://github.com/unknownerror404k/404codecracker.git 2>/dev/null || \
pip3 install git+https://github.com/unknownerror404k/404codecracker.git 2>/dev/null || \
pip install git+https://github.com/unknownerror404k/404codecracker.git
echo "       ✓ 404 Code Cracker installed"

# Step 4: Verify
echo "  [4/4] Verifying..."
if command -v 404codecracker &>/dev/null; then
    echo "       ✓ Command '404codecracker' is ready"
else
    echo "       ! Command not found in PATH"
    echo "       ! Add ~/.local/bin to PATH:"
    echo "         export PATH=\$PATH:~/.local/bin"
    echo "       ! Or run with: python3 -m code404cracker"
fi

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  ✦ INSTALLATION COMPLETE!                    ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║                                              ║"
echo "  ║  Run the GUI:                                ║"
echo "  ║    404codecracker                            ║"
echo "  ║                                              ║"
echo "  ║  Run in terminal:                            ║"
echo "  ║    404codecracker --cli                      ║"
echo "  ║                                              ║"
echo "  ║  Decode a string directly:                   ║"
echo "  ║    404codecracker -t 'SGVsbG8gV29ybGQ='      ║"
echo "  ║                                              ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
