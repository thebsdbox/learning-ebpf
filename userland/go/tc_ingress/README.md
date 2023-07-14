## Setting up your environment

1. Install Ubuntu (22.04)
2. Update the package lists
3. Install our 6.1 kernel `sudo apt install -y linux-image-6.1.0-1006-oem linux-headers-6.1.0-1006-oem linux-tools-6.1.0-1006-oem libbpf-dev`
4. Reboot !

## Build out all the bits we need!

`bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../headers/vmlinux.h` - will generate the header with all the required functions in it!
`go generate` - will generate all the stub code required for our go program to speak C

### What is `go generate` doing?

If we actually look at the definition within `main.go`, we will find the following line: `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf <path to code> -- -I../header`. This line will invocate a go program that will compile the c code and then use the tool `bpf2go` to create all of the required stubs for our Go code to work as expected!

### Creating our program!

#### Generate the required code

Running the command `go generate` will create all the required go/eBPF code!

#### Create our userland code

Build our code with the command `go build -o lb`.

#### Running the program

`sudo lb <interface_name> port <ip1> <ip2> backendPort`, will create a bpf program that will capture incoming traffic on `port` and then forward it to one of the `<ipX>` listening on a `backendPort`.

