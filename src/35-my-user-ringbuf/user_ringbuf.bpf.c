// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "user_ringbuf.h"
#include "parse_helpers.h"
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

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

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
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;

	int eth_type;
	int ip_type;
	int tcp_type;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr; 

	nh.pos = data;

	/* Parse Ethernet and IP headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_TCP) {
			goto out;
		}
	} else {
		goto out;
	}

	tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
	if ((void*)(tcphdr + 1) > data_end) {
		goto out;
	}

	if (bpf_ntohs(tcphdr->source) == 8080) {
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
			bpf_printk("Port number is: %d", context);
			// We need to update the packet checksum when modifying the header.
			struct tcphdr tcphdr_old;
			__u32 csum = tcphdr->check;
			tcphdr_old = *tcphdr;
			tcphdr->dest = bpf_htons(context); // Change the destination port to 8080
			csum = bpf_csum_diff((__be32 *)&tcphdr_old, 4, (__be32 *)tcphdr, 4, ~csum);
			tcphdr->check = csum_fold_helper(csum);
		}
		else {
			bpf_printk("No data samples to process");
		}
	}

out:
	return TC_ACT_OK;
}

SEC("xdp") int xdp_ingress(struct xdp_md *ctx) {
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;

  struct hdr_cursor nh;
  nh.pos = data;

  struct ethhdr *eth = data;
  int eth_type;
  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type < 0) {
    goto out;
  }

  struct iphdr *ip;
  struct ipv6hdr *ipv6;
  int ip_type;
  if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &ip);
  }
  else if (eth_type == bpf_htons(ETH_P_IPV6)) {
    ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
  }
  else {
    // Default action, pass it up the GNU/Linux network stack to be handled
    goto out;
  }

  if (ip_type != IPPROTO_TCP) {
    // We only process TCP traffic, pass it up the GNU/Linux network stack to be handled
    goto out;
  }

  struct tcphdr *tcp = nh.pos;
  if ((void*)(tcp + 1) > data_end) {
    goto out;
  }

  int len = tcp->doff * 4;
  /* Sanity check packet field is valid */
  if(len < sizeof(*tcp)) {
    goto out;
  }

  /* Variable-length TCP header, need to use byte-based arithmetic */
  if (nh.pos + len > data_end) {
    goto out;
  }

  if (tcp->syn == 1 && bpf_ntohs(tcp->dest) == 8081) {
    __u32 dest_port = bpf_ntohs(tcp->dest);

		// We need to update the packet checksum when modifying the header.
		struct tcphdr tcphdr_old;
		__u32 csum = tcp->check;
		tcphdr_old = *tcp;
		tcp->dest = bpf_htons(8080); // Change the destination port to 8080
		csum = bpf_csum_diff((__be32 *)&tcphdr_old, 4, (__be32 *)tcp, 4, ~csum);
		tcp->check = csum_fold_helper(csum);
    
    // NOTE: No need for reserve/submit API - would be needed if we were worried about ring buffer getting full,
    // which could happen in case of high traffic or slow consumption of the data from it by the user space program
    int ret = bpf_ringbuf_output(&kernel_ringbuf, &dest_port, sizeof(dest_port), 0);
    // NOTE: Probably this shouldn't impact the program and one should just pass the packet with XDP_PASS
    if (ret != 0) {
      return XDP_ABORTED;
    } else {
      bpf_printk("XDP/BPF Succesfully NAT-ed port numbers %d -> %d!", dest_port, bpf_ntohs(tcp->dest));
    }
  }
    
out:
  return XDP_PASS;
}