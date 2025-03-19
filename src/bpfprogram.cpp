#include <bpf/bpf.h>
#include <elf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "attached_probe.h"
#include "bpfprogram.h"
#include "log.h"
#include "util/exceptions.h"

namespace bpftrace {

BpfProgram::BpfProgram(struct bpf_program *bpf_prog) : bpf_prog_(bpf_prog)
{
}

int BpfProgram::fd() const
{
  return bpf_program__fd(bpf_prog_);
}

void BpfProgram::set_prog_type(const Probe &probe)
{
  auto prog_type = progtype(probe.type);
  bpf_program__set_type(bpf_prog_, static_cast<::bpf_prog_type>(prog_type));
}

void BpfProgram::set_expected_attach_type(const Probe &probe,
                                          BPFfeature &feature)
{
  auto attach_type = static_cast<libbpf::bpf_attach_type>(0);
  if (probe.type == ProbeType::fentry)
    attach_type = libbpf::BPF_TRACE_FENTRY;
  else if (probe.type == ProbeType::fexit)
    attach_type = libbpf::BPF_TRACE_FEXIT;
  else if (probe.type == ProbeType::iter)
    attach_type = libbpf::BPF_TRACE_ITER;
  else if (probe.type == ProbeType::rawtracepoint)
    attach_type = libbpf::BPF_TRACE_RAW_TP;

  // We want to avoid kprobe_multi when a module is specified
  // because the BPF_TRACE_KPROBE_MULTI link type does not
  // currently support the `module:function` syntax.
  if ((probe.type == ProbeType::kprobe || probe.type == ProbeType::kretprobe) &&
      !probe.funcs.empty() && probe.path.empty()) {
    if (probe.is_session && feature.has_kprobe_session())
      attach_type = libbpf::BPF_TRACE_KPROBE_SESSION;
    else if (feature.has_kprobe_multi())
      attach_type = libbpf::BPF_TRACE_KPROBE_MULTI;
  }

  if ((probe.type == ProbeType::uprobe || probe.type == ProbeType::uretprobe) &&
      feature.has_uprobe_multi() && !probe.funcs.empty())
    attach_type = libbpf::BPF_TRACE_UPROBE_MULTI;

  bpf_program__set_expected_attach_type(
      bpf_prog_, static_cast<::bpf_attach_type>(attach_type));
}

void BpfProgram::set_attach_target(const Probe &probe,
                                   const BTF &btf,
                                   const Config &config)
{
  if (probe.type != ProbeType::fentry && probe.type != ProbeType::fexit &&
      probe.type != ProbeType::iter && probe.type != ProbeType::rawtracepoint)
    return;

  const std::string &mod = probe.path;
  const std::string &fun = probe.attach_point;
  const std::string attach_target = !mod.empty() ? mod + ":" + fun : fun;

  std::string btf_fun;
  __u32 kind = BTF_KIND_FUNC;

  if (probe.type == ProbeType::iter) {
    btf_fun = "bpf_iter_" + fun;
  } else if (probe.type == ProbeType::rawtracepoint) {
    btf_fun = "btf_trace_" + fun;
    kind = BTF_KIND_TYPEDEF;
  } else {
    btf_fun = fun;
  }

  if (btf.get_btf_id(btf_fun, mod, kind) < 0) {
    const std::string msg = "No BTF found for " + attach_target;
    if (probe.orig_name != probe.name &&
        config.get(ConfigKeyMissingProbes::default_) !=
            ConfigMissingProbes::error) {
      // One attach point in a multi-attachpoint probe failed and the user
      // requested not to error out. Show a warning (if requested) and continue
      // but disable auto-loading of the program as it would make the entire BPF
      // object loading fail.
      if (config.get(ConfigKeyMissingProbes::default_) ==
          ConfigMissingProbes::warn)
        LOG(WARNING) << msg << ", skipping.";
      bpf_program__set_autoload(bpf_prog_, false);
    } else {
      // explicit match failed, fail hard
      throw util::FatalUserException(msg);
    }
  }

  bpf_program__set_attach_target(bpf_prog_, 0, attach_target.c_str());
}

void BpfProgram::set_no_autoattach()
{
  bpf_program__set_autoattach(bpf_prog_, false);
}

struct bpf_program *BpfProgram::bpf_prog() const
{
  return bpf_prog_;
}

} // namespace bpftrace
