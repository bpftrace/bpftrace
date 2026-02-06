#include <cstring>
#include <fstream>
#include <glob.h>
#include <unordered_set>

#include "ast/ast.h"
#include "ast/passes/args_resolver.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "log.h"
#include "tracefs/tracefs.h"
#include "tracepoint_format_parser.h"

namespace bpftrace::ast {

char TracepointFormatFileError::ID;

void TracepointFormatFileError::log(llvm::raw_ostream &OS) const
{
  OS << err();
}

std::string TracepointFormatFileError::err() const
{
  std::stringstream msg;
  msg << "Tracepoint not found: " << category_ << ":" << event_;
  if (bt_verbose) {
    msg << "(" << strerror(errno) << ": " << file_path_ << ")";
  }
  return msg.str();
}

std::string TracepointFormatFileError::hint() const
{
  if (category_ == "syscall")
    return "Did you mean syscalls:" + event_ + "?";
  return "";
}

Result<> TracepointFormatParser::parse_format_file()
{
  std::string format_file_path = tracefs::event_format_file(category_, event_);

  std::ifstream format_file(format_file_path.c_str());
  if (format_file.fail()) {
    return make_error<TracepointFormatFileError>(category_,
                                                 event_,
                                                 format_file_path);
  }
  format_file_ = std::move(format_file);
  return OK();
}

std::string adjust_integer_types(const std::string &field_type, int size)
{
  std::string new_type = field_type;
  // Adjust integer fields to correctly sized types
  if (size == 8) {
    if (field_type == "int")
      new_type = "s64";
    if (field_type == "unsigned int" || field_type == "unsigned" ||
        field_type == "u32" || field_type == "pid_t" || field_type == "uid_t" ||
        field_type == "gid_t")
      new_type = "u64";
  }

  return new_type;
}

Result<std::string> parse_section(const std::string &line,
                                  const std::string &title,
                                  const std::string &tracepoint,
                                  const std::string &field_name)
{
  auto start = line.find(title);
  if (start == std::string::npos) {
    return make_error<ArgParseError>(tracepoint,
                                     field_name,
                                     "could not parse \"" + title + "\"");
  }

  auto end = line.find(';', start);
  if (end == std::string::npos) {
    return make_error<ArgParseError>(tracepoint,
                                     field_name,
                                     "could not parse \"" + title + "\"");
  }

  return line.substr(start + title.length(), end - start - title.length());
}

// Parse one line from the tracepoint format file which has the format:
//     field:unsigned short common_type; offset:0; size:2; signed:0;
Result<Field> TracepointFormatParser::parse_field(const std::string &line,
                                                  const std::string &tracepoint)
{
  auto field_str = parse_section(line, "field:", tracepoint, "");
  if (!field_str)
    return field_str.takeError();

  // Split field type from the name
  auto field_type_end_pos = field_str->find_last_of("\t ");
  if (field_type_end_pos == std::string::npos) {
    return make_error<ArgParseError>(*field_str, "could not parse type");
  }
  std::string field_type = field_str->substr(0, field_type_end_pos);
  std::string field_name = field_str->substr(field_type_end_pos + 1);

  // Check if the field is an array
  auto arr_size_pos = field_name.find('[');
  bool is_array = arr_size_pos != std::string::npos;
  std::optional<int> array_size = std::nullopt;
  if (is_array) {
    auto arr_size_end_pos = field_name.find(']');
    auto array_size_str = field_name.substr(arr_size_pos + 1,
                                            arr_size_end_pos - arr_size_pos -
                                                1);
    if (array_size_str.empty()) {
      array_size = 0;
    } else {
      try {
        array_size = std::stoi(array_size_str);
      } catch (std::exception &) {
        return make_error<ArgParseError>(tracepoint,
                                         field_name,
                                         "could not parse array size");
      }
    }
    field_name = field_name.substr(0, arr_size_pos);
  }

  auto offset_str = parse_section(line, "offset:", tracepoint, field_name);
  if (!offset_str)
    return offset_str.takeError();

  auto size_str = parse_section(line, "size:", tracepoint, field_name);
  if (!size_str)
    return size_str.takeError();

  auto signed_str = parse_section(line, "signed:", tracepoint, field_name);
  if (!signed_str)
    return signed_str.takeError();
  bool is_signed = *signed_str == "1";

  Field field;
  field.name = field_name;
  field.offset = std::stoi(*offset_str);
  field.is_data_loc = field_type.find("__data_loc") != std::string::npos;

  if (field.is_data_loc) {
    field.type = CreateInt64();
    field.type.SetAS(AddrSpace::kernel);
  } else {
    auto type = bpftrace_.btf_->get_stype(field_type);
    // There may be fields that are parsed that have the __user type
    // tag, which indicates an user address space. Otherwise, no explicit
    // type is attached. However, we know that tracepoint fields generally
    // refer to kernel space, so we attach this explicitly if it present.
    if (type.GetAS() == AddrSpace::none) {
      type.SetAS(AddrSpace::kernel);
    }
    if (is_array) {
      if (field_type == "char") {
        // See src/btf.cpp for why this is converted to a string
        field.type = CreateString(*array_size);
      } else {
        field.type = CreateArray(*array_size, type);
      }
    } else {
      field.type = type;
      field.type.SetSize(std::stoi(*size_str));
      field.type.SetSign(is_signed);
    }
  }

  return field;
}

Result<std::shared_ptr<Struct>> TracepointFormatParser::get_tracepoint_struct(
    std::istream &format_file)
{
  auto result = std::make_shared<Struct>(0, false);

  for (std::string line; getline(format_file, line);) {
    if (line.find("field:") == std::string::npos)
      continue;

    auto field = parse_field(line, category_ + ":" + event_);
    if (!field)
      return field.takeError();

    result->fields.push_back(std::move(*field));
  }
  result->is_tracepoint_args = true;
  result->size = result->fields.back().offset +
                 result->fields.back().type.GetSize();

  return result;
}

Result<std::shared_ptr<Struct>> TracepointFormatParser::get_tracepoint_struct()
{
  return get_tracepoint_struct(format_file_);
}

} // namespace bpftrace::ast
