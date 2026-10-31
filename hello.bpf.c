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
  __uint(max_entries, 16554);
  __type(key, struct path_key);
  __type(value, __u64); 
} exec_count  SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handel_exceve_tp(struct trace_event_raw_sys_enter *ctx){

  // for the sys_calls execve sys_calls 
  // - args[0]  is the pointer to memory where pathname is stored in memory
  // - args[1]  is pointer to array of pointer of strings passed to the new program as its command-line arguments
  // - args[3]  is pointer to array of pounter of strings 
  const char *filename = (char *) ctx->args[0];

  struct path_key key = {};

  // why helper function as the userspace memory is not safe so eBpf verifier doesnot mark it safe
  // hazard that might occurs are :
  // - other userspace program modified that memory 
  // - data might not in Ram may be kernel put the data in harddrive 

  long n = bpf_probe_read_user_str(key.path, sizeof(key.path), filename);

  // Validate the copy operation was succesfull
  // means we are able to read
  // if error n will be negative
  if (n <= 0){
    return 0;
  }

  __u64 * val = bpf_map_lookup_elem(&exec_count,&key);
  if(val){
  
    // NOTE: this is not safe way to increment btw
    *val += 1;
  }else{
    __u64 init = 1;
    bpf_map_update_elem(&exec_count, &key ,&init, BPF_NOEXIST);
  }

  bpf_printk("execve: %s \n",key.path);
  return 0;
}
