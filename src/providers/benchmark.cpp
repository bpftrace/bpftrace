#include "providers/benchmark.h"
#include "bpfprogram.h"
#include "util/result.h"

namespace bpftrace::providers {

class BenchmarkAttachPoint : public SimpleAttachPoint {
public:
  BenchmarkAttachPoint(const std::string &name) : SimpleAttachPoint(name) {};

  Action action() const override
  {
    return Action::Once;
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_XDP;
  }
};

Result<AttachPointList> BenchmarkProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_list<BenchmarkAttachPoint>(str);
}

Result<> BenchmarkProvider::run_single(
    std::unique_ptr<AttachPoint> &attach_point,
    const BpfProgram &prog) const
{
  // Note: on newer kernels you must provide a data_in buffer at least
  // ETH_HLEN bytes long to make sure input validation works for
  // opts. Otherwise, bpf_prog_test_run_opts will return -EINVAL for
  // BPF_PROG_TYPE_XDP.
  //
  // https://github.com/torvalds/linux/commit/6b3d638ca897e099fa99bd6d02189d3176f80a47
  constexpr size_t ETH_HLEN = 14;
  char data_in[ETH_HLEN];
  struct bpf_test_run_opts opts = {};
  opts.sz = sizeof(opts);
  opts.data_in = data_in;
  opts.data_size_in = ETH_HLEN;
  opts.repeat = 1'000'000;

  auto name = attach_point->name();
  if (bpf_prog_test_run_opts(prog.fd(), &opts) < 0) {
    return make_error<SystemError>("failed to run benchmark");
  }

  return OK();
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::BenchmarkAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::SimpleAttachPoint,
                                     bpftrace::providers::BenchmarkAttachPoint)
