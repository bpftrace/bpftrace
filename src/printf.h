#pragma once

#include <sstream>

#include "ast.h"
#include "types.h"

namespace bpftrace {

struct Field;

std::string verify_format_string(const std::string &fmt, std::vector<Field> args);

class IPrintable
{
public:
  virtual ~IPrintable() { };
  virtual uint64_t value() = 0;
};

class PrintableString : public virtual IPrintable
{
public:
  PrintableString(std::string value) : _value(value) { }
  uint64_t value();
private:
  std::string _value;
};

class PrintableInt : public virtual IPrintable
{
public:
  PrintableInt(uint64_t value) : _value(value) { }
  uint64_t value();
private:
  uint64_t _value;
};


} // namespace bpftrace
