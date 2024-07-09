#include "bpfbytecode.h"

#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "utils.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>
#include <stdexcept>

namespace bpftrace {

BpfBytecode::BpfBytecode(const void *elf, size_t elf_size, BPFtrace &bpftrace)
    : log_size_(bpftrace.config_.get(ConfigKeyInt::log_size))
{
  int log_level = 0;
  // In debug mode, show full verifier log.
  // In verbose mode, only show verifier log for failures.
  if (bt_debug.find(DebugStage::Verifier) != bt_debug.end())
    log_level = 15;
  else if (bt_verbose)
    log_level = 1;

  BPFTRACE_LIBBPF_OPTS(bpf_object_open_opts,
                       opts,
                       .kernel_log_level = static_cast<__u32>(log_level));

  bpf_object_ = std::unique_ptr<struct bpf_object, bpf_object_deleter>(
      bpf_object__open_mem(elf, elf_size, &opts));
  if (!bpf_object_)
    LOG(BUG) << "The produced ELF is not a valid BPF object";

  struct bpf_map *global_vars_map = nullptr;
  bool needs_global_vars = !bpftrace.resources.needed_global_vars.empty();

  // Discover maps
  struct bpf_map *m;
  bpf_map__for_each (m, bpf_object_.get()) {
    if (needs_global_vars) {
      std::string_view name = bpf_map__name(m);
      // there are some random chars in the beginning of the map name
      if (name.npos != name.find(globalvars::SECTION_NAME)) {
        global_vars_map = m;
        continue;
      }
    }
    maps_.emplace(bpftrace_map_name(bpf_map__name(m)), m);
  }

  if (needs_global_vars) {
    if (!global_vars_map) {
      LOG(BUG) << "No map found for " << globalvars::SECTION_NAME
               << " which is needed to set global variables";
    }
    globalvars::update_global_vars(bpf_object_.get(),
                                   global_vars_map,
                                   bpftrace);
  }

  // Discover programs
  struct bpf_program *p;
  bpf_object__for_each_program (p, bpf_object_.get()) {
    auto prog = programs_.emplace(bpf_program__name(p),
                                  BpfProgram(p, log_size_));
    bpf_program__set_log_buf(p, prog.first->second.log_buf(), log_size_);
  }
}

const BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe) const
{
  auto usdt_location_idx = (probe.type == ProbeType::usdt)
                               ? std::make_optional<int>(
                                     probe.usdt_location_idx)
                               : std::nullopt;

  auto prog = programs_.find(
      get_function_name_for_probe(probe.name, probe.index, usdt_location_idx));
  if (prog == programs_.end()) {
    prog = programs_.find(get_function_name_for_probe(probe.orig_name,
                                                      probe.index,
                                                      usdt_location_idx));
  }

  if (prog == programs_.end()) {
    std::stringstream msg;
    if (probe.name != probe.orig_name)
      msg << "Code not generated for probe: " << probe.name
          << " from: " << probe.orig_name;
    else
      msg << "Code not generated for probe: " << probe.name;
    throw std::runtime_error(msg.str());
  }

  return prog->second;
}

BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe)
{
  return const_cast<BpfProgram &>(
      const_cast<const BpfBytecode *>(this)->getProgramForProbe(probe));
}

namespace {
/*
 * Searches the verifier's log for err_pattern. If a match is found, extracts
 * the name and ID of the problematic helper and throws a HelperVerifierError.
 *
 * Example verfier log extract:
 *     [...]
 *     36: (b7) r3 = 64                      ; R3_w=64
 *     37: (85) call bpf_d_path#147
 *     helper call is not allowed in probe
 *     [...]
 *
 *  In the above log, "bpf_d_path" is the helper's name and "147" is the ID.
 */
void maybe_throw_helper_verifier_error(std::string_view log,
                                       std::string_view err_pattern,
                                       const std::string &exception_msg_suffix)
{
  auto err_pos = log.find(err_pattern);
  if (err_pos == log.npos)
    return;

  std::string_view call_pattern = " call ";
  auto call_pos = log.rfind(call_pattern, err_pos);
  if (call_pos == log.npos)
    return;

  auto helper_begin = call_pos + call_pattern.size();
  auto hash_pos = log.find("#", helper_begin);
  if (hash_pos == log.npos)
    return;

  auto eol = log.find("\n", hash_pos + 1);
  if (eol == log.npos)
    return;

  auto helper_name = std::string{ log.substr(helper_begin,
                                             hash_pos - helper_begin) };
  auto func_id = std::stoi(
      std::string{ log.substr(hash_pos + 1, eol - hash_pos - 1) });

  std::string msg = std::string{ "helper " } + helper_name +
                    exception_msg_suffix;
  throw HelperVerifierError(msg, static_cast<libbpf::bpf_func_id>(func_id));
}

// The log should end with line:
//     processed N insns (limit 1000000) ...
// so we try to find it. If it's not there, it's very likely that the log has
// been trimmed due to insufficient log limit. This function checks if that
// happened.
bool is_log_trimmed(std::string_view log)
{
  static const std::vector<std::string> tokens = { "processed", "insns" };
  return !wildcard_match(log, tokens, true, true);
}
} // namespace

void BpfBytecode::load_progs(const RequiredResources &resources,
                             const BTF &btf,
                             BPFfeature &feature,
                             const Config &config)
{
  prepare_progs(resources.probes, btf, feature, config);
  prepare_progs(resources.special_probes, btf, feature, config);
  prepare_progs(resources.watchpoint_probes, btf, feature, config);

  int res = bpf_object__load(bpf_object_.get());

  // If requested, print the entire verifier logs, even if loading succeeded.
  for (const auto &[name, prog] : programs_) {
    if (bt_debug.find(DebugStage::Verifier) != bt_debug.end()) {
      std::cout << "BPF verifier log for " << name << ":\n";
      std::cout << "--------------------------------------\n";
      std::cout << prog.log_buf() << std::endl;
    }
  }

  if (res == 0)
    return;

  // If loading of bpf_object failed, we try to give user some hints of what
  // could've gone wrong.
  std::ostringstream err;
  for (const auto &[name, prog] : programs_) {
    if (res == 0 || prog.fd() >= 0)
      continue;

    // Unfortunately, a negative fd does not mean that this specific program
    // caused the failure. It can mean that libbpf didn't even try to load it
    // b/c some other program failed to load. So, we only log program load
    // failures when the verifier log is non-empty.
    std::string_view log(prog.log_buf());
    if (!log.empty()) {
      // This should be the only error that may occur here and does not imply
      // a bpftrace bug so throw immediately with a proper error message.
      maybe_throw_helper_verifier_error(log,
                                        "helper call is not allowed in probe",
                                        " not allowed in probe");

      std::stringstream errmsg;
      errmsg << "Error loading BPF program for " << name << ".";
      if (bt_verbose) {
        errmsg << std::endl
               << "Kernel error log: " << std::endl
               << log << std::endl;
        if (is_log_trimmed(log)) {
          LOG(WARNING, errmsg)
              << "Kernel log seems to be trimmed. This may be due to buffer "
                 "not being big enough, try increasing the BPFTRACE_LOG_SIZE "
                 "environment variable beyond the current value of "
              << log_size_ << " bytes";
        }
      } else {
        errmsg << " Use -v for full kernel error log.";
      }
      LOG(ERROR, err) << errmsg.str();
    }
  }

  if (err.str().empty()) {
    // The problem does not seem to be in program loading. It may be something
    // else (e.g. maps failing to load) but we're not able to figure out what
    // it is so advise user to check libbf output which should contain more
    // information.
    LOG(ERROR, err)
        << "Unknown BPF object load failure. Try using the \"-d libbpf\" "
           "option to see the full loading log.";
  }

  std::cerr << err.str();
  throw FatalUserException("Loading BPF object(s) failed.");
}

void BpfBytecode::prepare_progs(const std::vector<Probe> &probes,
                                const BTF &btf,
                                BPFfeature &feature,
                                const Config &config)
{
  for (auto &probe : probes) {
    auto &program = getProgramForProbe(probe);
    program.set_prog_type(probe, feature);
    program.set_expected_attach_type(probe, feature);
    program.set_attach_target(probe, btf, config);
    program.set_no_autoattach();
  }
}

bool BpfBytecode::all_progs_loaded()
{
  for (const auto &prog : programs_) {
    if (prog.second.fd() < 0)
      return false;
  }
  return true;
}

bool BpfBytecode::hasMap(MapType internal_type) const
{
  return maps_.find(to_string(internal_type)) != maps_.end();
}

bool BpfBytecode::hasMap(const StackType &stack_type) const
{
  return maps_.find(stack_type.name()) != maps_.end();
}

const BpfMap &BpfBytecode::getMap(const std::string &name) const
{
  auto map = maps_.find(name);
  if (map == maps_.end()) {
    LOG(BUG) << "Unknown map: " << name;
  }
  return map->second;
}

const BpfMap &BpfBytecode::getMap(MapType internal_type) const
{
  return getMap(to_string(internal_type));
}

const BpfMap &BpfBytecode::getMap(int map_id) const
{
  auto map = maps_by_id_.find(map_id);
  if (map == maps_by_id_.end()) {
    LOG(BUG) << "Unknown map id: " << std::to_string(map_id);
  }
  return *map->second;
}

const std::map<std::string, BpfMap> &BpfBytecode::maps() const
{
  return maps_;
}

int BpfBytecode::countStackMaps() const
{
  int n = 0;
  for (auto &map : maps_) {
    if (map.second.is_stack_map())
      n++;
  }
  return n;
}

void BpfBytecode::set_map_ids(RequiredResources &resources)
{
  for (auto &map : maps_) {
    auto map_info = resources.maps_info.find(map.first);
    if (map_info != resources.maps_info.end() && map_info->second.id != -1)
      maps_by_id_.emplace(map_info->second.id, &map.second);
  }
}

} // namespace bpftrace
