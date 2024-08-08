#include "container/ref.h"
#include "gtest/gtest.h"

#include <type_traits>

namespace bpftrace::test::ref {

using bpftrace::ref;

class Base {};

class ClassA : public Base {};

class ClassB : public Base {};

TEST(ref, construct)
{
  // From exact type
  EXPECT_TRUE((std::is_constructible_v<ref<ClassA>, ClassA &>));
  EXPECT_TRUE((std::is_constructible_v<ref<ClassA>, ref<ClassA>>));

  // From derived type
  EXPECT_TRUE((std::is_constructible_v<ref<Base>, ClassA &>));
  EXPECT_TRUE((std::is_constructible_v<ref<Base>, ref<ClassA>>));

  // From non-derived type
  EXPECT_FALSE((std::is_constructible_v<ref<ClassB>, ClassA &>));
  EXPECT_FALSE((std::is_constructible_v<ref<ClassB>, ref<ClassA>>));
}

TEST(ref, operator_get)
{
  int n = 123;
  ref<int> n_ref{ n };

  EXPECT_EQ(123, n_ref());
}

TEST(ref, const_operator_get)
{
  int n = 123;
  const ref<int> n_ref{ n };

  EXPECT_EQ(123, n_ref());
}

TEST(ref, ptr)
{
  int n = 123;
  ref<int> n_ref{ n };

  EXPECT_EQ(&n, n_ref.ptr());
}

TEST(ref, const_ptr)
{
  int n = 123;
  const ref<int> n_ref{ n };

  EXPECT_EQ(&n, n_ref.ptr());
}

TEST(ref, eq_ref_ref)
{
  int n = 123;
  int m = 456;

  ref<int> a{ n };
  ref<int> b{ n };
  ref<int> c{ m };

  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_EQ(b, a);
  EXPECT_NE(b, c);
  EXPECT_NE(c, a);
  EXPECT_NE(c, b);
}

} // namespace bpftrace::test::ref
