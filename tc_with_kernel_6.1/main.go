package main

import "C"

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

type forward_key struct {
	bindAddress uint32
	protocol    uint8
	padding     uint8
	bindPort    uint16
}

type forward_info struct {
	destAddress uint32
	destPort    uint16
	padding     uint16
}

func Ip2Int(ip net.IP) uint32 {
	i := big.NewInt(0)

	return uint32(i.SetBytes(ip).Uint64())
}

func main() {
	// if len(os.Args) < 3 {
	// 	log.Fatalf("Please specify a network interface")
	// }

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	//destinationAddress := os.Args[2]
	//sourceAddress := os.Args[3]

	// Broken
	_, _ := ebpf.LoadCollection("./egress.o")
	devID, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", ifaceName, err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	fd := uint32(prog1.GetFd())

	flags := uint32(0x1)

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return
	}
	// objs.XdpProgMain.FD()
	// // Attach the program.
	// l, err := link.AttachXDP(link.XDPOptions{
	// 	Program:   objs.XdpProgMain,
	// 	Interface: iface.Index,
	// })
	// if err != nil {
	// 	log.Fatalf("could not attach XDP program: %s", err)
	// }
	// defer l.Close()

	// log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	// netDestination := HostToNetLong(Ip2Int(net.ParseIP(destinationAddress)))
	// netSource := HostToNetLong(Ip2Int(net.ParseIP(sourceAddress)))
	// log.Printf("[%s]->[%d], [%s]->[%d]", destinationAddress, netDestination, sourceAddress, netSource)

	// // log.Printf("All traffic to [%s], will have it's source address changed to [%s]", destinationAddress, sourceAddress)
	// // log.Printf("All traffic to [%d], will have it's source address changed to [%d]", NetToHostLong(Ip2Int(net.ParseIP(destinationAddress))), Ip2Int(net.ParseIP(sourceAddress)))

	// fwMap := forward_key{
	// 	protocol:    syscall.IPPROTO_TCP,
	// 	bindPort:    HostToNetShort(2222),
	// 	bindAddress: netSource,
	// }
	// fw_info := forward_info{
	// 	destAddress: netDestination,
	// 	destPort:    HostToNetShort(22),
	// }

	// fmt.Printf("[% x] [% x] [% x]", fwMap.bindAddress, fwMap.protocol, fwMap.bindPort)

	// err = objs.ForwardMap.Put(fwMap, fw_info)
	// //objs.ForwardMap.Put()
	// // err = objs.XdpAddress.Put(Ip2Int(net.ParseIP(destinationAddress)), Ip2Int(net.ParseIP(sourceAddress)))
	// if err != nil {
	// 	log.Fatalf("could not apply data to eBPF map: %s", err)
	// }
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Blocking, press ctrl+c to continue...")
	<-done // Will block here until user hits ctrl+c
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	XdpProgMain *ebpf.ProgramSpec `ebpf:"tc_ingress"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	ForwardMap *ebpf.MapSpec `ebpf:"svc_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	ForwardMap *ebpf.Map `ebpf:"svc_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.ForwardMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	XdpProgMain *ebpf.Program `ebpf:"tc_ingress"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.XdpProgMain,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed egress.o
var _BpfBytes []byte

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
