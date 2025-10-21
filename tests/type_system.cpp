#include <gtest/gtest.h>

#include "ast/ast.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/type_system.h"
#include "data/data_source_btf.h"

namespace bpftrace::test::type_system {

TEST(TypeSystemTest, basic)
{
  ast::ASTContext ast;

  // Use our synthetic BTF as the object.
  ast::BitcodeModules bm;
  bm.modules.emplace_back(ast::BitcodeModules::Result{
      .module = nullptr,
      .object = std::string(reinterpret_cast<const char *>(btf_data),
                            sizeof(btf_data)),
      .loc = nullptr,
  });

  // Run the pass and extract the types.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bm)
                .add(ast::CreateTypeSystemPass())
                .run();
  ASSERT_TRUE(bool(ok));
  auto types = ok->get<ast::TypeMetadata>();

  // This is a bit of a change detector test, but simply print all the types and
  // ensure that they are contained within the set. If this ends up being a
  // pain, then in the future we could limit this to some smaller set of types
  // that are interesting. Note that there are some duplicated names due to the
  // partial types (e.g. `union (anon)`), so we just skip those cases.
  std::unordered_set<std::string> removed;
  std::unordered_set<std::string> expected = {
    "unsigned char",
    "short int",
    "short unsigned int",
    "long int",
    "long unsigned int",
    "long long int",
    "long long unsigned int",
    "size_t",
    "void",
    "struct Foo1",
    "int",
    "char",
    "long int",
    "struct (anon)",
    "union (anon)",
    "struct Foo2",
    "const struct Foo2",
    "volatile const struct Foo2",
    "struct Foo3",
    "struct Foo1*",
    "volatile const struct Foo2*",
    "restrict volatile const struct Foo2*",
    "struct Foo4",
    "unsigned int",
    "enum FooEnum",
    "struct FirstFieldsAreAnonUnion",
    "struct Arrays",
    "int[4]",
    "long unsigned int",
    "char[8]",
    "char[16]",
    "void*[2]",
    "void*",
    "int[6]",
    "int[0]",
    "struct ArrayWithCompoundData",
    "struct Foo3*[2]",
    "struct Foo3*",
    "struct task_struct",
    "struct file",
    "struct vm_area_struct",
    "struct bpf_iter__task",
    "struct task_struct*",
    "struct bpf_iter__task_file",
    "struct file*",
    "struct bpf_iter__task_vma",
    "struct vm_area_struct*",
    "struct bpf_map",
    "const struct bpf_map",
    "struct sock",
    "struct sock*",
    "const struct bpf_map*",
    "struct ArrayWithCompoundData*",
    "struct Arrays*",
    "int*",
    "struct Foo2*",
    "struct Foo4*",
    "long unsigned int process_counts",
    "long int (*)(void* __data, long int first_real_arg)",
    "long int __probestub_event_rt(void* __data, long int first_real_arg)",
    "int (*)()",
    "int bpf_iter_task()",
    "int bpf_iter_task_file()",
    "int bpf_iter_task_vma()",
    "long int (*)(const struct bpf_map* map)",
    "long int bpf_map_sum_elem_count(const struct bpf_map* map)",
    "struct Foo3* (*)(int a, struct Foo1* foo1, struct Foo2* foo2, struct "
    "Foo3* foo3, struct Foo4* foo4)",
    "struct Foo3* func_1(int a, struct Foo1* foo1, struct Foo2* foo2, struct "
    "Foo3* foo3, struct Foo4* foo4)",
    "struct Foo3* (*)(int a, int* b, struct Foo1* foo1)",
    "struct Foo3* func_2(int a, int* b, struct Foo1* foo1)",
    "struct Foo3* func_3(int a, int* b, struct Foo1* foo1)",
    "void (*)(struct ArrayWithCompoundData* arr)",
    "void func_array_with_compound_data(struct ArrayWithCompoundData* arr)",
    "struct Arrays* (*)(struct Arrays* arr)",
    "struct Arrays* func_arrays(struct Arrays* arr)",
    "int main()",
    "void (*)(struct sock* sk, int how)",
    "void tcp_shutdown(struct sock* sk, int how)",
    ".data..percpu",
  };
  for (const auto &v : types.global) {
    std::stringstream ss;
    ss << v;
    const auto s = ss.str();
    if (removed.contains(s)) {
      continue; // Already checked.
    }
    EXPECT_TRUE(expected.erase(s)) << s;
    removed.insert(s);
  }
  EXPECT_TRUE(expected.empty());
}

} // namespace bpftrace::test::type_system
