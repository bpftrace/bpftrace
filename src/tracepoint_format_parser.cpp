#include <cstring>
#include <fstream>
#include <glob.h>
#include <iostream>

#include "ast/ast.h"
#include "bpftrace.h"
#include "log.h"
#include "struct.h"
#include "tracepoint_format_parser.h"

namespace bpftrace {

std::set<std::string> TracepointFormatParser::struct_list;

bool TracepointFormatParser::parse(ast::Program *program, BPFtrace &bpftrace)
{
  std::vector<ast::Probe*> probes_with_tracepoint;
  for (ast::Probe *probe : *program->probes)
    for (ast::AttachPoint *ap : *probe->attach_points)
      if (ap->provider == "tracepoint") {
        probes_with_tracepoint.push_back(probe);
        continue;
      }

  if (probes_with_tracepoint.empty())
    return true;

  ast::TracepointArgsVisitor n{};
  if (!bpftrace.btf_.has_data())
    program->c_definitions += "#include <linux/types.h>\n";
  for (ast::Probe *probe : probes_with_tracepoint)
  {
    n.visit(*probe);

    for (ast::AttachPoint *ap : *probe->attach_points)
    {
      if (ap->provider == "tracepoint")
      {
        std::string &category = ap->target;
        std::string &event_name = ap->func;
        std::string format_file_path = "/sys/kernel/debug/tracing/events/" + category + "/" + event_name + "/format";
        glob_t glob_result;

        if (has_wildcard(category) || has_wildcard(event_name))
        {
          // tracepoint wildcard expansion, part 1 of 3. struct definitions.
          memset(&glob_result, 0, sizeof(glob_result));
          int ret = glob(format_file_path.c_str(), 0, NULL, &glob_result);
          if (ret != 0)
          {
            if (ret == GLOB_NOMATCH)
            {
              LOG(ERROR, ap->loc, std::cerr)
                  << "tracepoints not found: " << category << ":" << event_name;
              // helper message:
              if (category == "syscall")
                LOG(ERROR, ap->loc, std::cerr)
                    << "Did you mean syscalls:" << event_name << "?";
              if (bt_verbose) {
                LOG(ERROR) << strerror(errno) << ": " << format_file_path;
              }
              return false;
            }
            else
            {
              // unexpected error
              LOG(ERROR, ap->loc, std::cerr) << std::string(strerror(errno));
              return false;
            }
          }

          if (probe->tp_args_structs_level <= 0)
          {
            globfree(&glob_result);
            continue;
          }

          for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
            std::string filename(glob_result.gl_pathv[i]);
            std::ifstream format_file(filename);
            std::string prefix("/sys/kernel/debug/tracing/events/");
            size_t pos = prefix.length();
            std::string real_category = filename.substr(
                pos, filename.find('/', pos) - pos);
            pos = prefix.length() + real_category.length() + 1;
            std::string real_event = filename.substr(
                pos, filename.length() - std::string("/format").length() - pos);

            // Check to avoid adding the same struct more than once to definitions
            std::string struct_name = get_struct_name(real_category,
                                                      real_event);
            if (!TracepointFormatParser::struct_list.count(struct_name))
            {
              program->c_definitions += get_tracepoint_struct(
                  format_file, real_category, real_event, bpftrace);
              TracepointFormatParser::struct_list.insert(struct_name);
            }
          }
          globfree(&glob_result);
        }
        else
        {
          // single tracepoint
          std::ifstream format_file(format_file_path.c_str());
          if (format_file.fail())
          {
            // Errno might get clobbered by LOG().
            int saved_errno = errno;

            LOG(ERROR, ap->loc, std::cerr)
                << "tracepoint not found: " << category << ":" << event_name;
            // helper message:
            if (category == "syscall")
              LOG(WARNING, ap->loc, std::cerr)
                  << "Did you mean syscalls:" << event_name << "?";
            if (bt_verbose) {
              // Having the location info isn't really useful here, so no
              // bpftrace.error
              LOG(ERROR) << strerror(saved_errno) << ": " << format_file_path;
            }
            return false;
          }

          if (probe->tp_args_structs_level <= 0)
            continue;

          // Check to avoid adding the same struct more than once to definitions
          std::string struct_name = get_struct_name(category, event_name);
          if (TracepointFormatParser::struct_list.insert(struct_name).second)
            program->c_definitions += get_tracepoint_struct(
                format_file, category, event_name, bpftrace);
        }
      }
    }
  }
  return true;
}

std::string TracepointFormatParser::get_struct_name(const std::string &category, const std::string &event_name)
{
  return "struct _tracepoint_" + category + "_" + event_name;
}

std::string TracepointFormatParser::get_struct_name(const std::string &probe_id)
{
  // probe_id has format category:event
  std::string event_name = probe_id;
  std::string category = erase_prefix(event_name);
  return get_struct_name(category, event_name);
}

std::string TracepointFormatParser::parse_field(const std::string &line,
                                                int *last_offset,
                                                BPFtrace &bpftrace)
{
  std::string extra = "";

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
  int offset = std::stoi(
      line.substr(offset_pos + 7, offset_semi_pos - offset_pos - 7));

  // If there'a gap between last field and this one,
  // generate padding fields
  if (offset && *last_offset)
  {
    int i, gap = offset - *last_offset;

    for (i = 0; i < gap; i++)
    {
      extra += "  char __pad_" + std::to_string(offset - gap + i) + ";\n";
    }
  }

  *last_offset = offset + size;

  std::string field = line.substr(field_pos + 6, field_semi_pos - field_pos - 6);
  auto field_type_end_pos = field.find_last_of("\t ");
  if (field_type_end_pos == std::string::npos)
    return "";
  std::string field_type = field.substr(0, field_type_end_pos);
  std::string field_name = field.substr(field_type_end_pos+1);

  if (field_type.find("__data_loc") != std::string::npos)
  {
    // Note that the type here (ie `int`) does not matter. Later during parse
    // time the parser will rewrite this field type to a u64 so that it can
    // hold the pointer to the actual location of the data.
    field_type = R"_(__attribute__((annotate("tp_data_loc"))) int)_";
  }

  // Only adjust field types for non-arrays
  if (field_name.find("[") == std::string::npos)
    field_type = adjust_integer_types(field_type, size);

  // If BTF is available, we try not to use any header files, including
  // <linux/types.h> and request all the types we need from BTF.
  bpftrace.btf_set_.emplace(field_type);

  return extra + "  " + field_type + " " + field_name + ";\n";
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

std::string TracepointFormatParser::get_tracepoint_struct(
    std::istream &format_file,
    const std::string &category,
    const std::string &event_name,
    BPFtrace &bpftrace)
{
  std::string format_struct = get_struct_name(category, event_name) + "\n{\n";
  int last_offset = 0;

  for (std::string line; getline(format_file, line); )
  {
    format_struct += parse_field(line, &last_offset, bpftrace);
  }

  format_struct += "};\n";
  return format_struct;
}

} // namespace bpftrace
