#!/bin/bash

echo "Starting a network bridge"

sudo ip link add name virtbr0 type bridge
sudo ip addr add 192.168.1.20/24 dev virtbr0
sudo ip link set virtbr0 up
sudo ip tuntap add tap0 mode tap
sudo ip link set tap0 up
sudo ip link set tap0 master virtbr0
sudo ip link set dev tap0 promisc on
echo "tap0 mac address = $(ip link show dev tap0 | grep link | awk ' { print $2 }')"

