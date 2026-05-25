#!/bin/bash
# FPP plugin callback descriptor.
# When called with --list, output the plugin type.
# "c++" tells FPP to load lib<plugin-name>.so from this directory.
if [ "$1" = "--list" ]; then
    echo "c++"
fi
