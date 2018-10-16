#pragma once

// Annoying C type helpers.
//
// C headers sometimes contain struct ending with a flexible array
// member, which is not supported in C++. An example of such a type is
// file_handle from fcntl.h (man name_to_handle_at)
//
// Here are some helper macros helping to ensure if the C++
// counterpart has members of the same type and offset.

#include <cstddef>
#include <type_traits>

namespace act_helpers
{

template <typename T, typename M> M get_member_type(M T:: *);

}

#define ACTH_SAME_SIZE(cxxtype, ctype, extra_type) \
  (sizeof(cxxtype) == sizeof(ctype) + sizeof(extra_type))
#define ACTH_GET_TYPE_OF(mem) \
  decltype(act_helpers::get_member_type(&mem))
#define ACTH_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem) \
  (std::is_standard_layout<cxxtype>::value && \
   std::is_standard_layout<ctype>::value && \
   (offsetof(cxxtype, cxxmem) == offsetof(ctype, cmem)))
#define ACTH_SAME_TYPE(cxxtype, cxxmem, ctype, cmem) \
  std::is_same<ACTH_GET_TYPE_OF(cxxtype :: cxxmem), ACTH_GET_TYPE_OF(ctype :: cmem)>::value

#define ACTH_ASSERT_SAME_SIZE(cxxtype, ctype, extra_type) \
  static_assert(ACTH_SAME_SIZE(cxxtype, ctype, extra_type), \
                "assumption that is broken: " #cxxtype " == " #ctype " + " # extra_type)
#define ACTH_ASSERT_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem) \
  static_assert(ACTH_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem), \
                "assumption that is broken: " #cxxtype "::" #cxxmem " is at the same offset as " #ctype "::" #cmem)
#define ACTH_ASSERT_SAME_TYPE(cxxtype, cxxmem, ctype, cmem) \
  static_assert(ACTH_SAME_TYPE(cxxtype, cxxmem, ctype, cmem), \
                "assumption that is broken: " #cxxtype "::" #cxxmem " has the same type as " #ctype "::" #cmem)
#define ACTH_ASSERT_SAME_MEMBER(cxxtype, cxxmem, ctype, cmem) \
  ACTH_ASSERT_SAME_TYPE(cxxtype, cxxmem, ctype, cmem); \
  ACTH_ASSERT_SAME_OFFSET(cxxtype, cxxmem, ctype, cmem)
