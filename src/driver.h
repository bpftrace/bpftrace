#pragma once

#include <fstream>
#include <memory>

#include "ast/ast.h"
#include "bpftrace.h"

typedef void *yyscan_t;

namespace bpftrace {

class Driver {
public:
  explicit Driver(BPFtrace &bpftrace, std::ostream &o = std::cerr);

  int parse();
  int parse_str(std::string script);
  void source(std::string, std::string);
  void error(std::ostream &, const location &, const std::string &);
  void error(const location &l, const std::string &m);
  void error(const std::string &m);
  std::unique_ptr<ast::Program> root;

  void debug()
  {
    debug_ = true;
  };

  std::set<std::string> list_modules() const;

  BPFtrace &bpftrace_;

  bool listing_ = false;

private:
  std::ostream &out_;
  bool failed_ = false;
  bool debug_ = false;
};

} // namespace bpftrace
