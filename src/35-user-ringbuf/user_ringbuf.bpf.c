// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "user_ringbuf.h"
#include <errno.h>

char _license[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");

int read = 0;

static long
do_nothing_cb(struct bpf_dynptr *dynptr, int *context)
{
	struct user_sample *sample;
	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample)
		return 0;
	bpf_printk("sample->i is: %d", sample->i);
	int value = sample->i;
	bpf_printk("value is: %d", value);
	*context = sample->i;
	bpf_printk("context is: %d", *context);
	struct event *e;
	pid_t pid;
	//__builtin_memcpy(&context, &(sample->i), sizeof(sample->i));
	//bpf_printk("Context is: %d", context);
	//*context = sample->i;
	/* get PID and TID of exiting thread/process */
	pid = bpf_get_current_pid_tgid() >> 32;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	__sync_fetch_and_add(&read, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
	long ret;
	int err = 0;
	int context;
	// receive data from userspace
	ret = bpf_user_ringbuf_drain(&user_ringbuf, do_nothing_cb, &context, 0);


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