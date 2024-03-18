# DHCP with eBPF

This example requires a little bit more infrastructure in order to understand what is transpiring under the covers! So i've tried to make this as simple as possible, with some simple networking!

## Start a network bridge

`./bridgeup.sh`

This will create `virtbr0` that is a layer2 network bridge that doesn't have any interfaces attached or anything, its comparable to a simple layer 2 switch at this point. We will use this bridge to connect to with eBPF and we will also connect a VM to this bridge so that we can capture and modify the behaviour of the DHCP responses!


We will create the directory for our bridge configuration `mkdir -p /etc/qemu/`.

Then we will allow qemu to be allowed to use this bridge (well all bridges, the acl is a pain) `echo "allow all" | sudo tee  /etc/qemu/bridge.conf`.

## Start everything (requires `tmux`)

This will start a three panel tmux that has a VM on the bridge, a tcpdump on the bridge and our eBPF program on the bridge. 

```
tmux new-session \; send-keys '\''go generate; go build; sudo ./dhcp -interface virtbr0 -mac 52:54:12:11:3c:c0 -address 10.0.0.1'\'' C-m \; split-window -v\; send-keys '\''sudo tcpdump -i virtbr0'\''\; split-window -v\; select-layout even-vertical
```

## Exit from `qemu`

To exit from qemu press `ctrl a` and then press `x`

## Tidy up

`./bridgedown.sh`
