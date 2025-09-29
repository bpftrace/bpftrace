#define __KERNEL__
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>

extern _Bool bpf_session_is_return(void) __ksym __weak;

_Bool __session_is_return() {
    if (bpf_session_is_return) {
        return bpf_session_is_return();
    }
    return 0;
}
