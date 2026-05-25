#!/bin/bash
# fpp-TuyaBridge install script.
# Called by FPP when the plugin is installed/updated.
# Compiles the C++ plugin .so against the installed FPP source.

set -e

PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_NAME="fpp-TuyaBridge"
SONAME="lib${PLUGIN_NAME}.so"

# Locate FPP source (prefer /opt/fpp/src, fall back to $FPPDIR/src)
if [ -d /opt/fpp/src ]; then
    FPP_SRC=/opt/fpp/src
elif [ -n "$FPPDIR" ] && [ -d "$FPPDIR/src" ]; then
    FPP_SRC="$FPPDIR/src"
else
    echo "ERROR: Cannot find FPP source directory. Set FPPDIR or install FPP to /opt/fpp."
    exit 1
fi

echo "fpp-TuyaBridge: Installing build dependencies..."
apt-get install -y --no-install-recommends \
    g++ \
    make \
    libssl-dev \
    zlib1g-dev \
    libjsoncpp-dev

echo "fpp-TuyaBridge: Building C++ plugin (FPP_SRC=${FPP_SRC})..."
cd "${PLUGIN_DIR}"
make FPP_SRC="${FPP_SRC}" clean
make FPP_SRC="${FPP_SRC}" -j"$(nproc)"

echo "fpp-TuyaBridge: Install complete."
echo "  The plugin loads automatically when fppd starts."
echo "  Configure devices: FPP web UI → Content Setup → Tuya Bridge."
