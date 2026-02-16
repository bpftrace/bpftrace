#pragma once

#include <fstream>
#include <string>

#include "bpftrace.h"

namespace bpftrace::ast {

// ArgParseError may be surfaced when some probe attempts to use an `args.`
// builtin that cannot be parsed or does not resolve correctly.
class ArgParseError : public ErrorInfo<ArgParseError> {
public:
  static char ID;
  ArgParseError(std::string probe_name, std::string &&detail)
      : probe_name_(std::move(probe_name)), detail_(std::move(detail)) {};
  ArgParseError(std::string_view probe_name, std::string &&detail)
      : ArgParseError(std::string(probe_name), std::move(detail)) {};
  ArgParseError(std::string probe_name,
                std::string arg_name,
                std::string &&detail)
      : probe_name_(std::move(probe_name)),
        arg_name_(std::move(arg_name)),
        detail_(std::move(detail)) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string probe_name_;
  std::string arg_name_;
  std::string detail_;
};

class TracepointFormatFileError : public ErrorInfo<TracepointFormatFileError> {
public:
  static char ID;
  TracepointFormatFileError(std::string category,
                            std::string event,
                            std::string file_path)
      : category_(std::move(category)),
        event_(std::move(event)),
        file_path_(std::move(file_path)) {};
  void log(llvm::raw_ostream &OS) const override;
  std::string err() const;
  std::string hint() const;

private:
  std::string category_;
  std::string event_;
  std::string file_path_;
};

class TracepointFormatParser {
public:
  TracepointFormatParser(std::string category,
                         std::string event,
                         BPFtrace &bpftrace)
      : category_(std::move(category)),
        event_(std::move(event)),
        bpftrace_(bpftrace) {};

  Result<> parse_format_file();
  Result<std::shared_ptr<Struct>> get_tracepoint_struct();

protected:
  Result<std::shared_ptr<Struct>> get_tracepoint_struct(
      std::istream &format_file);

private:
  Result<Field> parse_field(const std::string &line,
                            const std::string &tracepoint);

  const std::string category_;
  const std::string event_;
  std::ifstream format_file_;
  BPFtrace &bpftrace_;
};

} // namespace bpftrace::ast
