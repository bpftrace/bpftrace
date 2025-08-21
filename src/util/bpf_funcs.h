#pragma once

#include <bpf/bpf.h>
#include <iostream>

std::ostream &operator<<(std::ostream &out, const bpf_func_id &id);
