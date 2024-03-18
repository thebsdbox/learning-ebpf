#!/bin/bash

echo "Creating a qemu VM"
sudo qemu-system-x86_64 --enable-kvm -m 2048 \
  -nographic \
  -net nic,macaddr="52:54:12:11:3c:c0" -net bridge,br=virtbr0
