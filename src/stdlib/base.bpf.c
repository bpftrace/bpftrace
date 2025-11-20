#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

extern _Bool bpf_session_is_return(void) __ksym __weak;

// Try to limit the functions that get added in this file
// as these will always be imported/compiled by every script

_Bool __session_is_return() {
    if (bpf_session_is_return) {
        return bpf_session_is_return();
    }
    return 0;
}
