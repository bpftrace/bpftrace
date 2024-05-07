#include <iostream>

#include "ast/attachpoint_parser.h"
#include "driver.h"
#include "log.h"
#include "parser.tab.hh"

extern void *yy_scan_string(const char *yy_str, yyscan_t yyscanner);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy(yyscan_t yyscanner);
extern bpftrace::location loc;

namespace bpftrace {

namespace {
std::string_view parse_license()
{
  std::string_view program = Log::get().get_source();
  constexpr std::string_view spdx_id_marker = "SPDX-License-Identifier: ";
  auto spdx_id_pos = program.find(spdx_id_marker);
  if (spdx_id_pos == program.npos)
    return {};

  auto license_pos = spdx_id_pos + spdx_id_marker.size();
  auto eol_pos = program.find("\n", spdx_id_pos + 1);
  if (eol_pos == program.npos)
    return {};

  auto license = program.substr(license_pos, eol_pos - license_pos);

  // Try to translate some known GPL-v2-compatible licenses into a format
  // understood by the Linux kernel
  if (license.find("GPL-2.0") == 0)
    return "GPL";

  return license;
}
} // namespace

Driver::Driver(BPFtrace &bpftrace, std::ostream &o)
    : bpftrace_(bpftrace), out_(o)
{
}

void Driver::source(std::string_view filename, std::string_view script)
{
  Log::get().set_source(filename, script);
}

// Kept for the test suite
int Driver::parse_str(std::string_view script)
{
  source("stdin", script);
  return parse();
}

int Driver::parse()
{
  if (auto license = parse_license(); !license.empty()) {
    LOG(V1) << "Found license from SPDX ID: " << license;
    ConfigSetter config_setter(bpftrace_.config_, ConfigSource::default_);
    config_setter.set(ConfigKeyString::license, std::string{ license });
  }

  // Reset previous state if we parse more than once
  root.reset();

  // Reset source location info on every pass
  loc.initialize();

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  if (debug_) {
    parser.set_debug_level(1);
  }
  yy_scan_string(Log::get().get_source().c_str(), scanner);
  parser.parse();
  yylex_destroy(scanner);

  if (!failed_) {
    ast::AttachPointParser ap_parser(root.get(), bpftrace_, out_, listing_);
    if (ap_parser.parse())
      failed_ = true;
  }

  if (failed_) {
    root.reset();
  }

  // Keep track of errors thrown ourselves, since the result of
  // parser_->parse() doesn't take scanner errors into account,
  // only parser errors.
  return failed_;
}

void Driver::error(const location &l, const std::string &m)
{
  LOG(ERROR, l, out_) << m;
  failed_ = true;
}

void Driver::error(const std::string &m)
{
  LOG(ERROR, out_) << m;
  failed_ = true;
}

// Retrieves the list of kernel modules for all attachpoints. Will be used to
// identify modules whose BTF we need to parse.
// Currently, this is useful for k(ret)func, k(ret)probe, and tracepoint probes.
std::set<std::string> Driver::list_modules() const
{
  std::set<std::string> modules;
  for (auto &probe : *root->probes) {
    for (auto &ap : *probe->attach_points) {
      auto probe_type = probetype(ap->provider);
      if (probe_type == ProbeType::kfunc || probe_type == ProbeType::kretfunc ||
          ((probe_type == ProbeType::kprobe ||
            probe_type == ProbeType::kretprobe) &&
           !ap->target.empty())) {
        if (ap->need_expansion) {
          for (auto &match :
               bpftrace_.probe_matcher_->get_matches_for_ap(*ap)) {
            std::string func = match;
            erase_prefix(func);
            auto match_modules = bpftrace_.get_func_modules(func);
            modules.insert(match_modules.begin(), match_modules.end());
          }
        } else
          modules.insert(ap->target);
      } else if (probe_type == ProbeType::tracepoint) {
        // For now, we support this for a single target only since tracepoints
        // need dumping of C definitions BTF and that is not available for
        // multiple modules at once.
        modules.insert(ap->target);
      }
    }
  }
  return modules;
}

} // namespace bpftrace
