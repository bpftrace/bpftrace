#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Simple sentinel to prevent multiple applications.
class MapPrintAdded : public ast::State<"map-metadata"> {};

// The map print pass injects an exit probe which prints maps on exit.
//
// This is based on the `print_maps_on_exit` config setting. This emulates
// behavior that was formerly part of the runtime itself, but now this setting
// runtimes is a simple program transformation (and is therefore encoded into
// anything that is built, as long as it's run in the same way).
Pass CreateMapPrintPass();

} // namespace bpftrace::ast
