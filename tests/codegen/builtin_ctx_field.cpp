#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_ctx_field)
{
  std::string prog = R"END(
struct c {
  char c;
};

struct x {
  long a;
  short b[4];
  struct c c;
  struct c *d;
  char e[4]
};

kprobe:f {
  $x = (struct x*)ctx;
  @a = $x->a;
  @b = $x->b[0];
  @c = $x->c.c;
  @d = $x->d->c;
  @e = $x->e;
}
)END";

  test(prog, NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
