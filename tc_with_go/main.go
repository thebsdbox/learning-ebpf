// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/PraserX/ipconv"

	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../ebpf/tc_ingress/tc.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	be1, _ := ipconv.IPv4ToInt(net.ParseIP("172.17.0.3"))
	be2, _ := ipconv.IPv4ToInt(net.ParseIP("172.17.0.3"))
	err = objs.SvcMap.Put(uint16(9090), bpfBackends{
		Backend1: HostToNetLong(be1),
		Backend2: HostToNetLong(be2),
		DestPort: uint16(80),
	})

	if err != nil {
		log.Fatalf("add to map failed %w", err)
	}
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := rtnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", iface.Name, err)
		rtnl.Qdisc().Delete(&qdisc)
		return
	}
	log.Printf("Attaching eBPF program to iface %q (index %d)", iface.Name, iface.Index)

	// when deleting the qdisc, the applied filter will also be gone
	defer rtnl.Qdisc().Delete(&qdisc)

	fd := uint32(objs.TcIngress.FD())
	flags := uint32(0x1)
	name := objs.TcIngress.String()

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",

			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
				Name:  &name,
			},
		},
	}

	if err := rtnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}
	defer rtnl.Filter().Delete(&filter)

	//
	log.Printf("Press Ctrl-C to exit and remove the program")

	time.Sleep(time.Minute)
}

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func NetToHostLong(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.LittleEndian.Uint32(data)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

func Ip2Int(ip net.IP) uint32 {
	i := big.NewInt(0)

	return uint32(i.SetBytes(ip).Uint64())
}
