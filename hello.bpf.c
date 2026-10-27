//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#define MAX_PATH 256

char _license[] SEC("license") = "GPL";

// epf map

struct path_key {
  char path [MAX_PATH];
};


// i always get confuse there but remember exec_count is variable and we are placing that varible in section called map so that the usespace can use this section to build a map via sys_calls  
// the maps section is not executable memory—it is a purely descriptive metadata section
// therefore it canot have value therefore pointer of array is used in data type if you actually read this macro 
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(MAX_COUNT, 16554);
  __type(key, struct path_key);
  __type(value, int); 
} exec_count  SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handel_exceve_tp(struct trace_event_raw_sys_enter *ctx){



  bpf_printk("hello World");
  return 0;
}
