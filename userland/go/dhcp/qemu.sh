#!/bin/bash

echo "Creating a qemu VM"
sudo qemu-system-x86_64 --enable-kvm -m 2048 \
   -nographic \
   -device virtio-net-pci,netdev=network0,mac="52:54:12:11:3c:c0" \
   -netdev tap,id=network0,ifname=tap0,script=no,downscript=no
  
  #-net nic,macaddr="52:54:12:11:3c:c0" -net bridge,br=virtbr0
