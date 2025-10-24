#include <cstring>
#include <fstream>
#include <glob.h>
#include <unordered_set>

#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "tracefs/tracefs.h"
#include "tracepoint_format_parser.h"

namespace bpftrace::ast {

constexpr std::string_view TRACEPOINT_STRUCT_PREFIX = "struct _tracepoint_";

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

namespace {

class TracepointArgsResolver : public Visitor<TracepointArgsResolver> {
public:
  explicit TracepointArgsResolver(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<TracepointArgsResolver>::visit;
  void visit(AttachPoint &ap);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  std::unordered_set<std::string> visited_tps_;
};

} // namespace

void TracepointArgsResolver::visit(AttachPoint &ap)
{
  if (probetype(ap.provider) != ProbeType::tracepoint)
    return;

  if (visited_tps_.empty() && !bpftrace_.has_btf_data()) {
    ast_.root->c_statements.emplace_back(
        ast_.make_node<ast::CStatement>(ast::Location(),
                                        "#include <linux/types.h>"));
  }

  if (!visited_tps_.insert(ap.target + ":" + ap.func).second)
    return;

  TracepointFormatParser parser(ap.target, ap.func, bpftrace_);
  auto ok = parser.parse_format_file();
  if (!ok) {
    auto missing_config = bpftrace_.config_->missing_probes;
    auto ok_err = handleErrors(
        std::move(ok), [&](const TracepointFormatFileError &e) {
          auto err_msg = e.err();
          auto hint_msg = e.hint();
          if (missing_config == ConfigMissingProbes::error) {
            auto &err = ap.addError();
            err << err_msg;
            hint_msg += "If this is expected, set the 'missing_probes' config "
                        "variable to 'warn' or 'ignore'.";
            err.addHint() << hint_msg;
          } else if (missing_config == ConfigMissingProbes::warn) {
            auto &warn = ap.addWarning();
            warn << err_msg;
            if (!hint_msg.empty())
              warn.addHint() << hint_msg;
          }
        });
    return;
  }

  ast_.root->c_statements.emplace_back(
      ast_.make_node<ast::CStatement>(ast::Location(),
                                      parser.get_tracepoint_struct()));
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

std::string TracepointFormatParser::get_struct_name(
    const std::string &category,
    const std::string &event_name)
{
  return std::string(TRACEPOINT_STRUCT_PREFIX) + category + "_" + event_name;
}

bool TracepointFormatParser::is_tracepoint_struct(const std::string &name)
{
  return name.starts_with(TRACEPOINT_STRUCT_PREFIX);
}

std::string TracepointFormatParser::get_struct_name(const ast::AttachPoint &ap)
{
  return get_struct_name(ap.target, ap.func);
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

std::string TracepointFormatParser::parse_field(const std::string &line,
                                                int *last_offset)
{
  std::string extra;

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
  if (offset && *last_offset) {
    int i, gap = offset - *last_offset;

    for (i = 0; i < gap; i++) {
      extra += "  char __pad_" + std::to_string(offset - gap + i) + ";\n";
    }
  }

  *last_offset = offset + size;

  std::string field = line.substr(field_pos + 6,
                                  field_semi_pos - field_pos - 6);
  auto field_type_end_pos = field.find_last_of("\t ");
  if (field_type_end_pos == std::string::npos)
    return "";
  std::string field_type = field.substr(0, field_type_end_pos);
  std::string field_name = field.substr(field_type_end_pos + 1);

  if (field_type.find("__data_loc") != std::string::npos) {
    // Note that the type here (ie `int`) does not matter. Later during parse
    // time the parser will rewrite this field type to a u64 so that it can
    // hold the pointer to the actual location of the data.
    field_type = R"_(__attribute__((annotate("tp_data_loc"))) int)_";
  }

  auto arr_size_pos = field_name.find('[');
  auto arr_size_end_pos = field_name.find(']');
  // Only adjust field types for non-arrays
  if (arr_size_pos == std::string::npos)
    field_type = adjust_integer_types(field_type, size);

  // If BTF is available, we try not to use any header files, including
  // <linux/types.h> and request all the types we need from BTF.
  bpftrace_.btf_set_.emplace(field_type);

  if (arr_size_pos != std::string::npos) {
    auto arr_size = field_name.substr(arr_size_pos + 1,
                                      arr_size_end_pos - arr_size_pos - 1);
    if (arr_size.find_first_not_of("0123456789") != std::string::npos)
      bpftrace_.btf_set_.emplace(arr_size);
  }

  return extra + "  " + field_type + " " + field_name + ";\n";
}

std::string TracepointFormatParser::get_tracepoint_struct(
    std::istream &format_file)
{
  std::string format_struct = get_struct_name(category_, event_) + "\n{\n";
  int last_offset = 0;

  for (std::string line; getline(format_file, line);) {
    format_struct += parse_field(line, &last_offset);
  }

  format_struct += "};\n";
  return format_struct;
}

std::string TracepointFormatParser::get_tracepoint_struct()
{
  return get_tracepoint_struct(format_file_);
}

ast::Pass CreateParseTracepointFormatPass()
{
  return ast::Pass::create("tracepoint", [](ast::ASTContext &ast, BPFtrace &b) {
    TracepointArgsResolver resolver(ast, b);
    resolver.visit(ast.root);
  });
}

} // namespace bpftrace::ast
