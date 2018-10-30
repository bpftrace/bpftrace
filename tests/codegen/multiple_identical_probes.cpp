#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, multiple_identical_probes)
{
  test("kprobe:f { 1; } kprobe:f { 1; }",

R"EXPECTED(; Function Attrs: norecurse nounwind readnone
define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr #0 section "s_kprobe:f_1" {
entry:
  ret i64 0
}

; Function Attrs: norecurse nounwind readnone
define i64 @"kprobe:f.1"(i8* nocapture readnone) local_unnamed_addr #0 section "s_kprobe:f_2" {
entry:
  ret i64 0
}

attributes #0 = { norecurse nounwind readnone }
)EXPECTED");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
