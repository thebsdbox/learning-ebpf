// +build ignore

#include <signal.h>
#include <unistd.h>
#include "tcSkeleton.h"
#include <bpf/libbpf.h>

#include <net/if.h>
#include <arpa/inet.h>
#include "../ebpf/tc_ingress/backends.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	switch (level) {

        case LIBBPF_WARN:
		        return vfprintf(stderr, format, args);
        case LIBBPF_INFO:
		        return vfprintf(stderr, format, args);
        case LIBBPF_DEBUG:
          break;
        }
	return 0;
}

int main(int argc, char **argv)
{
        int interface; // Specify the inteface to bind to
        uint16_t listenport; // Specify the port that we will listen on
        struct backends backend;

        if (argc < 5) {
                fprintf(stderr, "Usage: lb <interface_name> port <ip1> <ip2> backendPort\n");
                return 1;
        }

        interface = if_nametoindex(argv[1]);
        if (!interface) {
                fprintf(stderr, "Unknown interface %s\n", argv[1]);
                return 1;
        }

        listenport = atoi(argv[2]);
        inet_aton(argv[3], (struct in_addr *)&(backend.backend1));
        inet_aton(argv[4], (struct in_addr *)&(backend.backend2));

        if (backend.backend1 == 0  || backend.backend2 == 0) {
                fprintf(stderr, "Invalid backend IP values\n");
                return 1;
        }

        if (argc < 6)
            backend.destPort = 80;
        else
            backend.destPort = atoi(argv[5]);

    // Configure our eBPF program to connect to ingress on the interface if
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,.ifindex = interface, .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,.handle = 1, .priority = 1);
	
    // 
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	// Set logging function
	libbpf_set_print(libbpf_print_fn);

	struct tc *skel = tc__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    /* hack # of backends hard coded to 2 for initial demo */
    __u16   key = listenport;
	int err;
    err = bpf_map__update_elem(skel->maps.svc_map, &key, sizeof(key),
                                                       &backend, sizeof(backend),
                                                       BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update svc_map: %d\n", err);
		fprintf(stderr, "continuing with default backend mappings \n");
		goto cleanup;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
 	bool created = false;
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("started! use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (created)
		bpf_tc_hook_destroy(&tc_hook);
	tc__destroy(skel);
	return -err;
}
