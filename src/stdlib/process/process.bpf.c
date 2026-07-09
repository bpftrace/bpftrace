#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

long __signal_process(__u32 sig) {
    return bpf_send_signal(sig);
}

long __signal_thread(__u32 sig) {
    return bpf_send_signal_thread(sig);
}

unsigned long long __get_current_uid_gid() {
    return bpf_get_current_uid_gid();
}

unsigned long long __get_cgroup() {
    return bpf_get_current_cgroup_id();
}

unsigned long long __get_current_task() {
    return bpf_get_current_task();
}
