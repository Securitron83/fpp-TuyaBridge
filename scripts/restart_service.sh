#!/bin/bash
# Previously restarted the tuya-mqtt Node.js systemd service.
# The C++ plugin is loaded directly by fppd — no service restart is needed.
# Devices reload automatically when devices.conf is saved via the web UI.
echo "fpp-TuyaBridge: plugin is C++ and managed by fppd directly — no restart required."
