#pragma once

#include <istream>

namespace bpftrace {

namespace ast { class Program; }

class TracepointFormatParser
{
public:
  static void parse(ast::Program *program);
  static std::string get_struct_name(const std::string &category, const std::string &event_name);

private:
  static std::string parse_field(const std::string &line);
  static std::string adjust_integer_types(const std::string &field_type, int size);

protected:
  static std::string get_tracepoint_struct(std::istream &format_file, const std::string &category, const std::string &event_name);
};

} // namespace bpftrace
