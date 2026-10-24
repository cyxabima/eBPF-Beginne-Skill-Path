//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int hello(struct trace_event_raw_sys_enter *ctx){



  bpf_printk("hello World");
  return 0;
}
