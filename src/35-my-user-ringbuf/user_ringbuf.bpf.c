// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "user_ringbuf.h"
#include <errno.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");

int read = 0;

static long extract_port(struct bpf_dynptr *dynptr, int *context) {
	struct user_sample *sample;
	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample)
		return 0;

	*context = sample->port;
	bpf_printk("context is: %d", *context);
	return 0;
}

SEC("tc") int tc_egress(struct __sk_buff *ctx) {
	// receive data from userspace
	int context;
	long ret = bpf_user_ringbuf_drain(&user_ringbuf, extract_port, &context, 0);

	if (ret == EBUSY) {
		bpf_printk("ERROR: ring buffer is contended, and another calling context was concurrently draining the ring buffer.");
	}
	else if (ret == EINVAL) {
		bpf_printk("ERROR: user-space is not properly tracking the ring buffer due to the producer position not being aligned to 8 bytes, a sample not being aligned to 8 bytes, or the producer position not matching the advertised length of a sample.");
	}
	else if (ret == E2BIG) {
		bpf_printk("ERROR: user-space has tried to publish a sample which is larger than the size of the ring buffer, or which cannot fit within a struct bpf_dynptr.");
	}
	else if (ret > 0) {
		bpf_printk("Value outside is: %d", context);
	}
	else {
		bpf_printk("No data samples to process");
	}

	return 0;
}