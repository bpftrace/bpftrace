#include "output/output.h"
#include "output/text.h"

namespace bpftrace::output {

std::partial_ordering Primitive::Array::operator<=>(const Array &other) const
{
  return values <=> other.values;
}

bool Primitive::Array::operator==(const Array &other) const
{
  return values == other.values;
}

std::partial_ordering Primitive::Tuple::operator<=>(const Tuple &other) const
{
  return fields <=> other.fields;
}

bool Primitive::Tuple::operator==(const Tuple &other) const
{
  return fields == other.fields;
}

std::partial_ordering Primitive::Record::operator<=>(const Record &other) const
{
  return fields <=> other.fields;
}

bool Primitive::Record::operator==(const Record &other) const
{
  return fields == other.fields;
}

std::ostream &operator<<(std::ostream &out, const Primitive &p)
{
  TextOutput output(out);
  output.primitive(p);
  return out;
}

} // namespace bpftrace::output
