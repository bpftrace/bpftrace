#pragma once

typedef char m_str[64];

// m_arg is used to hide the passed argument behind an unrepresentable union,
// so that semantic analysis accepts the string pointer. This should be fixed
// with unified types in the future, but is a temporary workaround.
typedef union {
  m_str data;
} m_arg;
