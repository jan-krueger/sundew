#!/bin/sh
# Containers share the runner's kernel, so the modules must be loaded here.
set -eu
modules="ip_set ip_set_hash_ip ip_set_hash_net ip_set_bitmap_ip nf_tables"
if ! sudo modprobe -a $modules; then
    sudo apt-get update
    sudo apt-get install -y "linux-modules-extra-$(uname -r)"
    sudo modprobe -a $modules
fi
lsmod | grep -E "^(ip_set|nf_tables)"
