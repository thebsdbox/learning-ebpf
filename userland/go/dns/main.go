package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/praserx/ipconv"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" dns ../../../ebpf/dns/dns.c -- -I../headers

func main() {

	ifaceName := flag.String("interface", "eth0", "The interface to watch network traffic on")
	findName := flag.String("findDomain", "", "The domain to watch for")
	replaceRecord := flag.String("replaceRecord", "", "The A record to replace for that particular domain")

	flag.Parse()

	log.Infof("Starting 🐝 the eBPF DNS watcher, on interface [%s]", *ifaceName)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Look up the network interface by name.
	devID, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", *ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := dnsObjects{}
	if err := loadDnsObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()
	// Parse the URL Path
	var dnsName [256]uint8
	var convertedName [256]uint8

	copy(dnsName[:], *findName)

	if *findName != "" || *replaceRecord != "" {

		address, _ := ipconv.IPv4ToInt(net.ParseIP(*replaceRecord))
		tempName := ConvertDomain(*findName)
		copy(convertedName[:], tempName)
		err = objs.DnsMap.Put(convertedName, dnsDnsReplace{dnsName, HostToNetLong(address)})
		if err != nil {
			log.Fatalf("add to map failed %v", err)
		}
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		log.Fatalf("could not get replace qdisc: %v", err)
	}
	log.Info("Loaded TC QDisc")

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcIngress.FD(),
		Name:         objs.TcIngress.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterIngress); err != nil {
		log.Fatalf("failed to replace tc filter: %v", err)
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.TcEgress.FD(),
		Name:         objs.TcEgress.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterEgress); err != nil {
		log.Fatalf("failed to replace tc filter: %v", err)
	}

	log.Printf("Press Ctrl-C to exit and remove the program")

	// Drop the logs
	go cat()
	<-ctx.Done() // We wait here
	log.Info("Removing eBPF programs")

	link, err := netlink.LinkByName(*ifaceName)
	if err != nil {
		log.Fatalf("could not find iface: %v", err)
	}

	f, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatalf("could not list filters: %v", err)
	}

	if len(f) == 0 {
		log.Error("Unable to clean any filters")
	}
	for x := range f {
		err = netlink.FilterDel(f[x])
		if err != nil {
			log.Fatalf("could not get remove filter: %v", err)
		}
	}

	f, err = netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		log.Fatalf("could not list filters: %v", err)
	}

	if len(f) == 0 {
		log.Error("Unable to clean any filters")
	}
	for x := range f {
		err = netlink.FilterDel(f[x])
		if err != nil {
			log.Fatalf("could not get remove filter: %v", err)
		}
	}
}

func readLines(r io.Reader) {
	rd := bufio.NewReader(r)
	for {
		line, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", line)

	}
}

func cat() {
	file, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	readLines(file)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

func ConvertDomain(name string) []byte {
	var convertedName []byte
	//var charCount uint8
	var charPointer int
	subDomains := strings.Split(name, ".")
	for x := range subDomains {
		convertedName = append(convertedName, uint8(len(subDomains[x])))
		convertedName = append(convertedName, subDomains[x]...)
		charPointer = charPointer + 1 + len(subDomains[x])
	}
	//convertedName = append(convertedName, uint8(0))
	return convertedName
}
