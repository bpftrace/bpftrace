#include "bpfbytecode.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "ast/passes/named_param.h"
#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "util/bpf_names.h"
#include "util/exceptions.h"
#include "util/wildcard.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>

namespace bpftrace {

char BpfLoadError::ID;

void BpfLoadError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

char HelperVerifierError::ID;

void HelperVerifierError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

BpfBytecode::BpfBytecode(std::span<uint8_t> elf)
    : BpfBytecode(std::as_bytes(elf))
{
}

BpfBytecode::BpfBytecode(std::span<char> elf) : BpfBytecode(std::as_bytes(elf))
{
}

static std::optional<std::string> get_global_var_section_name(
    std::string_view map_name,
    const std::unordered_set<std::string> &section_names)
{
  for (const auto &section_name : section_names) {
    // there are some random chars in the beginning of the map name
    if (std::string_view::npos != map_name.find(section_name))
      return section_name;
  }
  return std::nullopt;
}

BpfBytecode::BpfBytecode(std::span<const std::byte> elf)
{
  int log_level = 0;
  // In debug mode, show full verifier log.
  // In verbose mode, only show verifier log for failures.
  if (bt_debug.contains(DebugStage::Verifier))
    log_level = 15;
  else if (bt_verbose)
    log_level = 1;

  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
  opts.kernel_log_level = static_cast<__u32>(log_level);

  bpf_object_ = std::unique_ptr<struct bpf_object, bpf_object_deleter>(
      bpf_object__open_mem(elf.data(), elf.size(), &opts));
  if (!bpf_object_)
    LOG(BUG) << "The produced ELF is not a valid BPF object: "
             << std::strerror(errno);

  const auto section_names = globalvars::get_section_names();

  // Discover maps
  struct bpf_map *m;
  bpf_map__for_each (m, bpf_object_.get()) {
    std::string_view name = bpf_map__name(m);
    if (auto global_var_section_name_opt = get_global_var_section_name(
            name, section_names)) {
      section_names_to_global_vars_map_[std::move(
          *global_var_section_name_opt)] = m;
      continue;
    }
    maps_.emplace(bpftrace_map_name(bpf_map__name(m)), m);
  }

  // Discover programs
  struct bpf_program *p;
  bpf_object__for_each_program (p, bpf_object_.get()) {
    programs_.emplace(bpf_program__name(p), BpfProgram(p));
  }
}

const BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe) const
{
  auto prog = programs_.find(
      util::get_function_name_for_probe(probe.name, probe.index));
  if (prog == programs_.end()) {
    throw std::runtime_error("Code not generated for probe: " + probe.name);
  }

  return prog->second;
}

BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe)
{
  return const_cast<BpfProgram &>(
      const_cast<const BpfBytecode *>(this)->getProgramForProbe(probe));
}

void BpfBytecode::update_global_vars(BPFtrace &bpftrace,
                                     globalvars::GlobalVarMap &&global_var_vals)
{
  bpftrace.resources.global_vars.update_global_vars(
      bpf_object_.get(),
      section_names_to_global_vars_map_,
      std::move(global_var_vals),
      bpftrace.ncpus_,
      bpftrace.max_cpu_id_,
      bpftrace.child_ ? std::make_optional<pid_t>(bpftrace.child_->pid())
                      : std::nullopt);
}

uint64_t BpfBytecode::get_event_loss_counter(BPFtrace &bpftrace, int max_cpu_id)
{
  auto *current_values = bpftrace.resources.global_vars.get_global_var(
      bpf_object_.get(),
      globalvars::EVENT_LOSS_COUNTER_SECTION_NAME,
      section_names_to_global_vars_map_);
  uint64_t current_value = 0;
  for (int i = 0; i < max_cpu_id; ++i) {
    current_value += *current_values;
    current_values++;
  }

  return current_value;
}

// Searches the verifier's log for err_pattern. If a match is found, extracts
// the name and ID of the problematic helper and throws a HelperVerifierError.
//
// Example verfier log extract:
//     [...]
//     36: (b7) r3 = 64                      ; R3_w=64
//     37: (85) call bpf_d_path#147
//     helper call is not allowed in probe
//     [...]
//
//  In the above log, "bpf_d_path" is the helper's name and "147" is the ID.
static Result<> check_helper_verifier_error(
    const std::string &log,
    const std::string &err_pattern,
    const std::string &exception_msg_suffix)
{
  auto err_pos = log.find(err_pattern);
  if (err_pos == std::string_view::npos)
    return OK();

  std::string_view call_pattern = " call ";
  auto call_pos = log.rfind(call_pattern, err_pos);
  if (call_pos == std::string_view::npos)
    return OK();

  auto helper_begin = call_pos + call_pattern.size();
  auto hash_pos = log.find("#", helper_begin);
  if (hash_pos == std::string_view::npos)
    return OK();

  auto eol = log.find("\n", hash_pos + 1);
  if (eol == std::string_view::npos)
    return OK();

  auto helper_name = std::string{ log.substr(helper_begin,
                                             hash_pos - helper_begin) };
  auto func_id = std::stoi(
      std::string{ log.substr(hash_pos + 1, eol - hash_pos - 1) });

  std::string msg = std::string{ "helper " } + helper_name +
                    exception_msg_suffix;
  return make_error<HelperVerifierError>(msg,
                                         static_cast<bpf_func_id>(func_id));
}

// The log should end with line:
//     processed N insns (limit 1000000) ...
// so we try to find it. If it's not there, it's very likely that the log has
// been trimmed due to insufficient log limit. This function checks if that
// happened.
static bool is_log_trimmed(std::string_view log)
{
  static const std::vector<std::string> tokens = { "processed", "insns" };
  return !util::wildcard_match(log, tokens, true, true);
}

Result<> BpfBytecode::load_progs(const RequiredResources &resources,
                                 const BTF &btf,
                                 BPFfeature &feature,
                                 const Config &config)
{
  std::unordered_map<std::string_view, std::vector<char>> log_bufs;
  for (auto &[name, prog] : programs_) {
    log_bufs[name] = std::vector<char>(config.log_size, '\0');
    auto &log_buf = log_bufs[name];
    bpf_program__set_log_buf(prog.bpf_prog(), log_buf.data(), log_buf.size());
  }

  prepare_progs(resources.begin_probes, btf, feature, config);
  prepare_progs(resources.end_probes, btf, feature, config);
  prepare_progs(resources.test_probes, btf, feature, config);
  prepare_progs(resources.benchmark_probes, btf, feature, config);
  prepare_progs(resources.signal_probes, btf, feature, config);
  prepare_progs(resources.probes, btf, feature, config);
  prepare_progs(resources.watchpoint_probes, btf, feature, config);

  int res = bpf_object__load(bpf_object_.get());

  // If requested, print the entire verifier logs, even if loading succeeded.
  for (const auto &[name, prog] : programs_) {
    if (bt_debug.contains(DebugStage::Verifier)) {
      std::cout << "BPF verifier log for " << name << ":\n";
      std::cout << "--------------------------------------\n";
      std::cout << log_bufs[name].data() << std::endl;
    }
  }

  if (res == 0)
    return OK();

  // If loading of bpf_object failed, we try to give user some hints of what
  // could've gone wrong.
  for (const auto &[name, prog] : programs_) {
    if (res == 0 || prog.fd() >= 0)
      continue;

    // Unfortunately, a negative fd does not mean that this specific program
    // caused the failure. It can mean that libbpf didn't even try to load it
    // b/c some other program failed to load. So, we only log program load
    // failures when the verifier log is non-empty.
    std::string log(log_bufs[name].data());
    if (!log.empty()) {
      // These should be the only errors that may occur here which do not imply
      // a bpftrace bug so throw immediately with a proper error message.
      auto ok = check_helper_verifier_error(
          log, "helper call is not allowed in probe", " not allowed in probe");
      if (!ok) {
        return ok.takeError();
      }
      ok = check_helper_verifier_error(log,
                                       "program of this type cannot use helper",
                                       " not allowed in probe");
      if (!ok) {
        return ok.takeError();
      }
      ok = check_helper_verifier_error(
          log,
          "pointer arithmetic on ptr_or_null_ prohibited, null-check it first",
          ": result needs to be null-checked before accessing fields");
      if (!ok) {
        return ok.takeError();
      }

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
              << log_bufs[name].size() << " bytes";
        }
      } else {
        errmsg << " Use -v for full kernel error log.";
      }
      return make_error<BpfLoadError>(errmsg.str());
    }
  }

  // The problem does not seem to be in program loading. It may be something
  // else (e.g. maps failing to load) but we're not able to figure out what
  // it is so advise user to check libbf output which should contain more
  // information.
  return make_error<BpfLoadError>(
      "Unknown BPF object load failure. Try using the \"-d libbpf\" "
      "option to see the full loading log.");
}

void BpfBytecode::prepare_progs(const std::vector<Probe> &probes,
                                const BTF &btf,
                                BPFfeature &feature,
                                const Config &config)
{
  for (const auto &probe : probes) {
    auto &program = getProgramForProbe(probe);
    program.set_prog_type(probe);
    program.set_expected_attach_type(probe, feature);
    program.set_attach_target(probe, btf, config);
    program.set_no_autoattach();
  }
}

void BpfBytecode::attach_external()
{
  for (const auto &prog : programs_) {
    auto *p = prog.second.bpf_prog();
    if (bpf_program__autoattach(p)) {
      bpf_program__attach(p);
    }
  }
}

bool BpfBytecode::all_progs_loaded()
{
  return std::ranges::all_of(programs_, [](const auto &prog) {
    return prog.second.fd() >= 0;
  });
}

bool BpfBytecode::hasMap(MapType internal_type) const
{
  return maps_.contains(to_string(internal_type));
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
  for (const auto &map : maps_) {
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
