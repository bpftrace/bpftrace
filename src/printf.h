#pragma once

#include <sstream>

#include "ast.h"
#include "types.h"

namespace bpftrace {

class Field;

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
  PrintableString(std::string value) : value_(std::move(value)) { }
  uint64_t value();
private:
  std::string value_;
};

class PrintableCString : public virtual IPrintable
{
public:
  PrintableCString(char* value) : value_(value) { }
  uint64_t value();
private:
  char* value_;
};

class PrintableInt : public virtual IPrintable
{
public:
  PrintableInt(uint64_t value) : value_(value) { }
  uint64_t value();
private:
  uint64_t value_;
};


} // namespace bpftrace
