#!/bin/bash

echo "Deleting a network bridge"
sudo ip link del dev virtbr0
sudo ip link del dev tap0
