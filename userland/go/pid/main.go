package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

const (
	UID  = 0 // rooty mc tooty
	GUID = 0
)

const (
	_SYSLOG_ACTION_CLEAR = 5
)

const story = `
You purged the computers of the malware - and not a second too late. Congratula
tions! The location of the base remains a secret. Maybe not for long though, wh
ile everyone was focusing on the computers, Bajeroff Lake, the traitor, managed
 to escape from his cell and stole a shuttle to escape the base. On the radars,
you only see him jump into hyperspace. There's no doubt your paths will cross a
gain one day. Before that, you'll take a day or three off to enjoy a well-deser
ved rest. How about checking in on your giant bees, for a change?

Oh wait, they're just calling all hands on deck: a Rebel squadron fell into an 
ambush and is fighting their way out... You'll relax another week!

-------------------------------------------------------------------------------

Thanks for playing the eBPF Summit 2023 Capture the Flag, paste the below code 
in the CTF channel on the eBPF Slack!

`

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../../../ebpf/pid/pid.c -- -I../headers

func main() {
	_, demon := os.LookupEnv("DEMON")
	_, hard := os.LookupEnv("HARDMODE")

	if !demon {

		// We need to randomize some pids!!
		os.Setenv("DEMON", "TRUE")
		// The Credential fields are used to set UID, GID and attitional GIDS of the process
		// You need to run the program as  root to do this
		var cred = &syscall.Credential{
			Uid:         UID,
			Gid:         GUID,
			Groups:      []uint32{},
			NoSetGroups: false}
		// the Noctty flag is used to detach the process from parent tty
		var sysproc = &syscall.SysProcAttr{Credential: cred, Noctty: false}
		var attr = os.ProcAttr{
			Dir: ".",
			Env: os.Environ(),
			Files: []*os.File{
				os.Stdin,
				nil,
				nil,
			},
			Sys: sysproc,
		}
		process, err := os.StartProcess(os.Args[0], os.Args, &attr)
		if err == nil {

			// It is not clear from docs, but Realease actually detaches the process
			err = process.Release()
			if err != nil {
				panic(err.Error())
			}

		} else {
			panic(err.Error())
		}
		fmt.Println("🐝 inject")
	} else {
		exit := 1
		patch := 2

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Allow the current process to lock memory for eBPF resources.
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal(err)
		}

		pid := os.Getpid()
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
		now := time.Now()
		var duration time.Duration
		var mode string

		go func() {
			// Every 30 seconds we will read the passwd file (naughty)
			for {
				if hard {
					// Wipe the system logs (hides the pid)
					_, err = unix.Klogctl(_SYSLOG_ACTION_CLEAR, nil)
					if err != nil {
						log.Fatalf("syslog failed: %v", err)
					}
				}
				duration = time.Since(now)
				_, _ = os.ReadFile("/etc/passwd")
				data := []byte(fmt.Sprintf("I've been in your kernel for [%f seconds]\n", duration.Seconds()))
				_ = os.WriteFile("/ebpf.summit", data, 0)
				time.Sleep(1 * time.Second)
			}
		}()
		//str :=

		mode = "Mode [EASY]"
		if hard {
			mode = "Mode [HARD]"
			// Wipe the system logs (hides the pid)
			_, err = unix.Klogctl(_SYSLOG_ACTION_CLEAR, nil)
			if err != nil {
				log.Fatalf("syslog failed: %v", err)
			}

		}
		fmt.Println("🐝 2")

		<-ctx.Done() // We wait here

		// base64 our string
		rotString := base64.StdEncoding.EncodeToString([]byte((mode) + (fmt.Sprintf("\nI've was in your kernel for [%f seconds]\n", duration.Seconds()))))

		// Generate the full output and rotate the letters/numbers
		data := (story) + (rot13rot5(rotString)) + "\n"
		// Defer wont be called, so manually tidy eBPF objects
		objs.Close()
		kpEnter.Close()
		kpExit.Close()
		kpPatch.Close()

		_ = os.WriteFile("/ebpf.summit", []byte(data), 0)
	}
}

// rot13(alphabets) + rot5(numeric)
func rot13rot5(input string) string {

	var result []rune
	rot5map := map[rune]rune{'0': '5', '1': '6', '2': '7', '3': '8', '4': '9', '5': '0', '6': '1', '7': '2', '8': '3', '9': '4'}

	for _, i := range input {
		switch {
		case !unicode.IsLetter(i) && !unicode.IsNumber(i):
			result = append(result, i)
		case i >= 'A' && i <= 'Z':
			result = append(result, 'A'+(i-'A'+13)%26)
		case i >= 'a' && i <= 'z':
			result = append(result, 'a'+(i-'a'+13)%26)
		case i >= '0' && i <= '9':
			result = append(result, rot5map[i])
		case unicode.IsSpace(i):
			result = append(result, ' ')
		}
	}
	return fmt.Sprintf(string(result[:]))
}
