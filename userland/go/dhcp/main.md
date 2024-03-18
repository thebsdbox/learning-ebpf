# DHCP with eBPF

This example requires a little bit more infrastructure in order to understand what is transpiring under the covers! So i've tried to make this as simple as possible, with some simple networking!

## Start a network bridge

`./bridgeup.sh`

This will create `virtbr0` that is a layer2 network bridge that doesn't have any interfaces attached or anything, its comparable to a simple layer 2 switch at this point. We will use this bridge to connect to with eBPF and we will also connect a VM to this bridge so that we can capture and modify the behaviour of the DHCP responses!


We will create the directory for our bridge configuration `mkdir -p /etc/qemu/`.

Then we will allow qemu to be allowed to use this bridge (well all bridges, the acl is a pain) `echo "allow all" | sudo tee  /etc/qemu/bridge.conf`.

## Start the VM

`./qemu.sh`

Starting qemu will start the VM boot process, including the PXE boot process

```
iPXE 1.21.1+git-20220113.fbbdc3926-0ubuntu1 -- Open Source Network Boot Firmware
 -- https://ipxe.org
Features: DNS HTTP HTTPS iSCSI NFS TFTP VLAN AoE ELF MBOOT PXE bzImage Menu PXEX

net0: 52:54:12:11:3c:c0 using 82540em on 0000:00:03.0 (Ethernet) [open]
  [Link:up, TX:0 TXE:0 RX:0 RXE:0]
Configuring (net0 52:54:12:11:3c:c0)......
```

To exit from qemu press `ctrl a` and then press `x`

## Tidy up

`./bridgedown.sh`
