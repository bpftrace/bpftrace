#!/bin/sh

# Report missing kernel features
#
# Usage: ./check_kernel_features.sh

set -e
set -u

err=0
config=''

# Find kernel config
for c in "/boot/config-$(uname -r)" "/boot/config" "/proc/config.gz"; do
    if [ -f "$c" ]; then
        config="$c"
        break
    fi
done

if [ -z "$config" ]; then
    echo "Could not find kernel config" >&2
    exit 1
fi

# Check feature
check_opt() {
    if ! zgrep -qE "^${1}[[:space:]]*=[[:space:]]*[y|Y]" "$config"; then
        err=1
        echo "Required option ${1} not set" >&2
    fi
}

check_opt 'CONFIG_BPF'
check_opt 'CONFIG_BPF_EVENTS'
check_opt 'CONFIG_BPF_JIT'
check_opt 'CONFIG_BPF_SYSCALL'
check_opt 'CONFIG_FTRACE_SYSCALLS'
check_opt 'CONFIG_HAVE_EBPF_JIT'
check_opt 'CONFIG_FUNCTION_TRACER'
check_opt 'CONFIG_HAVE_DYNAMIC_FTRACE'
check_opt 'CONFIG_DYNAMIC_FTRACE'
check_opt 'CONFIG_HAVE_KPROBES'
check_opt 'CONFIG_KPROBES'
check_opt 'CONFIG_KPROBE_EVENTS'
check_opt 'CONFIG_ARCH_SUPPORTS_UPROBES'
check_opt 'CONFIG_UPROBES'
check_opt 'CONFIG_UPROBE_EVENTS'
check_opt 'CONFIG_DEBUG_FS'

# Status report
if [ $err -eq 0 ]; then
    echo "All required features present!"
else
    echo "Missing required features"
fi

exit $err
