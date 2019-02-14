#include <fstream>
#include <iostream>
#include <string.h>

#include "ast.h"
#include "struct.h"
#include "tracepoint_format_parser.h"
#include "bpftrace.h"

namespace bpftrace {

std::set<std::string> TracepointFormatParser::struct_list;

bool TracepointFormatParser::parse(ast::Program *program)
{
  bool has_tracepoint_probes = false;
  for (ast::Probe *probe : *program->probes)
    for (ast::AttachPoint *ap : *probe->attach_points)
      if (ap->provider == "tracepoint")
        has_tracepoint_probes = true;

  if (!has_tracepoint_probes)
    return true;

  program->c_definitions += "#include <linux/types.h>\n";
  for (ast::Probe *probe : *program->probes)
  {
    for (ast::AttachPoint *ap : *probe->attach_points)
    {
      if (ap->provider == "tracepoint")
      {
        std::string &category = ap->target;
        std::string &event_name = ap->func;
        if (has_wildcard(event_name))
        {
          // args not supported with wildcards yet: #132
          return true;
        }

        std::string format_file_path = "/sys/kernel/debug/tracing/events/" + category + "/" + event_name + "/format";
        std::ifstream format_file(format_file_path.c_str());

        if (format_file.fail())
        {
          std::cerr << "ERROR: tracepoint not found: " << category << ":" << event_name << std::endl;
          // helper message:
          if (category == "syscall")
            std::cerr << "Did you mean syscalls:" << event_name << "?" << std::endl;
          if (bt_verbose) {
              std::cerr << strerror(errno) << ": " << format_file_path << std::endl;
          }
          return false;
        }

        // Check to avoid adding the same struct more than once to definitions
        std::string struct_name = get_struct_name(category, event_name);
        if (!TracepointFormatParser::struct_list.count(struct_name))
        {
          program->c_definitions += get_tracepoint_struct(format_file, category, event_name);
          TracepointFormatParser::struct_list.insert(struct_name);
        }
      }
    }
  }
  return true;
}

std::string TracepointFormatParser::get_struct_name(const std::string &category, const std::string &event_name)
{
  return "_tracepoint_" + category + "_" + event_name;
}

std::string TracepointFormatParser::parse_field(const std::string &line)
{
  auto field_pos = line.find("field:");
  if (field_pos == std::string::npos)
    return "";

  auto field_semi_pos = line.find(';', field_pos);
  if (field_semi_pos == std::string::npos)
    return "";

  auto offset_pos = line.find("offset:", field_semi_pos);
  if (offset_pos == std::string::npos)
    return "";

  auto offset_semi_pos = line.find(';', offset_pos);
  if (offset_semi_pos == std::string::npos)
    return "";

  auto size_pos = line.find("size:", offset_semi_pos);
  if (size_pos == std::string::npos)
    return "";

  auto size_semi_pos = line.find(';', size_pos);
  if (size_semi_pos == std::string::npos)
    return "";

  int size = std::stoi(line.substr(size_pos + 5, size_semi_pos - size_pos - 5));
  std::string field = line.substr(field_pos + 6, field_semi_pos - field_pos - 6);
  auto field_type_end_pos = field.find_last_of("\t ");
  if (field_type_end_pos == std::string::npos)
    return "";
  std::string field_type = field.substr(0, field_type_end_pos);
  std::string field_name = field.substr(field_type_end_pos+1);

  if (field_type.find("__data_loc") != std::string::npos)
  {
    field_type = "int";
    field_name = "data_loc_" + field_name;
  }

  // Only adjust field types for non-arrays
  if (field_name.find("[") == std::string::npos)
    field_type = adjust_integer_types(field_type, size);

  return "  " + field_type + " " + field_name + ";\n";
}

std::string TracepointFormatParser::adjust_integer_types(const std::string &field_type, int size)
{
  std::string new_type = field_type;
  // Adjust integer fields to correctly sized types
  if (size == 8)
  {
    if (field_type == "int")
      new_type = "s64";
    if (field_type == "unsigned int" || field_type == "unsigned" ||
        field_type == "u32" || field_type == "pid_t" ||
        field_type == "uid_t" || field_type == "gid_t")
      new_type = "u64";
  }

  return new_type;
}

std::string TracepointFormatParser::get_tracepoint_struct(std::istream &format_file, const std::string &category, const std::string &event_name)
{
  std::string format_struct = "struct " + get_struct_name(category, event_name) + "\n{\n";

  for (std::string line; getline(format_file, line); )
  {
    format_struct += parse_field(line);
  }

  format_struct += "};\n";
  return format_struct;
}

} // namespace bpftrace
