// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "tc2.skel.h"
#include "def.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Please specify program type (1, 2 or 3).\n");
		return 1;
	}

	int ifindex;
	int attach_point;

	if (strcmp(argv[1], "1") == 0) {
		ifindex = IFINDEX_2_H;
		attach_point = BPF_TC_INGRESS;
	} else if (strcmp(argv[1], "2") == 0) {
		ifindex = IFINDEX_2_H;
		attach_point = BPF_TC_INGRESS;
	} else if (strcmp(argv[1], "3") == 0) {
		ifindex = IFINDEX_2_C;
		attach_point = BPF_TC_EGRESS;
	} else {
		fprintf(stderr, "Unsupported program type.\n");
		return 1;
	}
	
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
			    .attach_point = attach_point);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct tc2_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = tc2_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	if (strcmp(argv[1], "1") == 0) {
		tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress1);
	} else if (strcmp(argv[1], "2") == 0) {
		tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress2);
	} else if (strcmp(argv[1], "3") == 0) {
		tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress3);
	}
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

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

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
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc2_bpf__destroy(skel);
	return -err;
}
