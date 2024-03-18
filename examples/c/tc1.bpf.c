// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "def.h"

SEC("tc")
int tc_ingress1(struct __sk_buff *ctx)
{
	return bpf_redirect(IFINDEX_2_H, 0);
}

SEC("tc")
int tc_ingress2(struct __sk_buff *ctx)
{
	bpf_skb_change_type(ctx, PACKET_HOST);
	return bpf_redirect_peer(IFINDEX_2_H, 0);
}

SEC("tc")
int tc_ingress3(struct __sk_buff *ctx)
{
	bpf_skb_change_type(ctx, PACKET_HOST);
	return bpf_redirect(IFINDEX_2_H, BPF_F_C2C);
}


char __license[] SEC("license") = "GPL";
