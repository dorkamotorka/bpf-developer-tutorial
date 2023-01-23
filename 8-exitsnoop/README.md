# eBPF 入门开发实践指南八：在 eBPF 中使用 exitsnoop 监控 进程退出事件

## exitsnoop

eBPF (Extended Berkeley Packet Filter) 是 Linux 内核上的一个强大的网络和性能分析工具。它允许开发者在内核运行时动态加载、更新和运行用户定义的代码。

本文是 eBPF 入门开发实践指南的第八篇，在 eBPF 中使用 exitsnoop 监控进程退出事件。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
 struct task_struct *task;
 struct event *e;
 pid_t pid, tid;
 u64 id, ts, *start_ts, duration_ns = 0;
 
 /* get PID and TID of exiting thread/process */
 id = bpf_get_current_pid_tgid();
 pid = id >> 32;
 tid = (u32)id;

 /* ignore thread exits */
 if (pid != tid)
  return 0;

 /* reserve sample from BPF ringbuf */
 e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
 if (!e)
  return 0;

 /* fill out the sample with data */
 task = (struct task_struct *)bpf_get_current_task();

 e->duration_ns = duration_ns;
 e->pid = pid;
 e->ppid = BPF_CORE_READ(task, real_parent, tgid);
 e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
 bpf_get_current_comm(&e->comm, sizeof(e->comm));

 /* send data to user-space for post-processing */
 bpf_ringbuf_submit(e, 0);
 return 0;
}
```

这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件。BPF（Berkeley Packet Filter）是一种内核态程序设计语言，允许开发人员编写内核模块以捕获和处理内核事件。

该程序通过注册一个 tracepoint，来监控进程退出事件。Tracepoint 是一种内核特性，允许内核模块获取特定事件的通知。在本程序中，注册的 tracepoint 是“tp/sched/sched_process_exit”，表示该程序监控的是进程退出事件。

当系统中发生进程退出事件时，BPF 程序会捕获该事件，并调用“handle_exit”函数来处理它。该函数首先检查当前退出事件是否是进程退出事件（而不是线程退出事件），然后在 BPF 环形缓冲区（“rb”）中保留一个事件结构体，并填充该结构体中的其他信息，例如进程 ID、进程名称、退出代码和退出信号等信息。最后，该函数还会调用 BPF 的“perf_event_output”函数，将捕获的事件发送给用户空间程序。

总而言之，这段代码是一个 BPF 程序，用于监控 Linux 系统中的进程退出事件.

## Compile and Run

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Or

```console
$ ecc exitsnoop.bpf.c exitsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ./ecli run package.json 
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    
21:40:09  42050  42049   0          0            which
21:40:09  42049  3517    0          0            sh
21:40:09  42052  42051   0          0            ps
21:40:09  42051  3517    0          0            sh
21:40:09  42055  42054   0          0            sed
21:40:09  42056  42054   0          0            cat
21:40:09  42057  42054   0          0            cat
21:40:09  42058  42054   0          0            cat
21:40:09  42059  42054   0          0            cat
```

## 总结

更多的例子和详细的开发指南，请参考 eunomia-bpf 的官方文档：<https://github.com/eunomia-bpf/eunomia-bpf>

完整的教程和源代码已经全部开源，可以在 <https://github.com/eunomia-bpf/bpf-developer-tutorial> 中查看。