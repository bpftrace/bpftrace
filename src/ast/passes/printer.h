#pragma once

#include <memory>
#include <ostream>

#include "ast/visitor.h"

namespace bpftrace::ast {

// BufferState is an internal type.
struct BufferState;

// Buffer is an internal type for output construction.
class Buffer {
public:
  Buffer();
  ~Buffer();
  Buffer(Buffer &&) = default;
  Buffer &operator=(Buffer &&) = default;
  Buffer(const Buffer &) = delete;
  Buffer &operator=(const Buffer &) = delete;

  [[nodiscard]] Buffer &&append(Buffer &&other, size_t indent = 0);
  [[nodiscard]] Buffer &&text(std::string str);
  [[nodiscard]] Buffer &&metadata(
      MetadataIndex metadata,
      std::optional<size_t> min_vspace = std::nullopt);
  [[nodiscard]] Buffer &&comment(std::string str);
  [[nodiscard]] Buffer &&line_break();

  size_t width() const;
  size_t lines() const;

private:
  std::unique_ptr<BufferState> state;
  friend std::ostream &operator<<(std::ostream &out, const Buffer &buffer);
};

// Buffer is directly printable, used below.
std::ostream &operator<<(std::ostream &out, const Buffer &buffer);

// Control how types should be formatted.
enum FormatMode {
  Minimal, // Only probes, no comments or spacing.
  Full,    // Print with full comments and spacing.
  Debug,   // Print with no comments, spacing but full types.
};

// Generic class for printing AST nodes.
class Formatter : public Visitor<Formatter, Buffer> {
public:
  Formatter(FormatMode mode,
            MetadataIndex &metadata,
            size_t max_width,
            bool bare = false)
      : mode(mode), metadata(metadata), max_width(max_width), bare(bare) {};

  using Visitor<Formatter, Buffer>::visit;
  Buffer visit(Integer &integer);
  Buffer visit(NegativeInteger &integer);
  Buffer visit(Boolean &boolean);
  Buffer visit(PositionalParameter &param);
  Buffer visit(PositionalParameterCount &param);
  Buffer visit(String &string);
  Buffer visit(None &none);
  Buffer visit(Builtin &builtin);
  Buffer visit(Identifier &identifier);
  Buffer visit(Variable &var);
  Buffer visit(VariableAddr &var_addr);
  Buffer visit(SubprogArg &subprog_arg);
  Buffer visit(AttachPoint &ap);
  Buffer visit(Call &call);
  Buffer visit(Sizeof &szof);
  Buffer visit(Offsetof &ofof);
  Buffer visit(Typeof &typeof);
  Buffer visit(Typeinfo &typeinfo);
  Buffer visit(Comptime &comptime);
  Buffer visit(MapDeclStatement &decl);
  Buffer visit(Map &map);
  Buffer visit(MapAddr &map_addr);
  Buffer visit(Binop &binop);
  Buffer visit(Unop &unop);
  Buffer visit(IfExpr &if_expr);
  Buffer visit(FieldAccess &acc);
  Buffer visit(ArrayAccess &arr);
  Buffer visit(TupleAccess &acc);
  Buffer visit(MapAccess &acc);
  Buffer visit(Cast &cast);
  Buffer visit(Tuple &tuple);
  Buffer visit(Record &record);
  Buffer visit(ExprStatement &expr);
  Buffer visit(AssignScalarMapStatement &assignment);
  Buffer visit(AssignMapStatement &assignment);
  Buffer visit(AssignVarStatement &assignment);
  Buffer visit(AssignConfigVarStatement &assignment);
  Buffer visit(VarDeclStatement &decl);
  Buffer visit(Jump &jump);
  Buffer visit(Unroll &unroll);
  Buffer visit(DiscardExpr &discard);
  Buffer visit(While &while_block);
  Buffer visit(Range &range);
  Buffer visit(For &for_loop);
  Buffer visit(Probe &probe);
  Buffer visit(Config &config);
  Buffer visit(BlockExpr &block);
  Buffer visit(Macro &macro);
  Buffer visit(Subprog &subprog);
  Buffer visit(RootImport &imp);
  Buffer visit(StatementImport &imp);
  Buffer visit(Program &program);
  Buffer visit(Expression &expr);
  Buffer visit(Statement &stmt);
  Buffer visit(RootStatement &root);
  Buffer visit(CStatement &cstmt);
  Buffer visit(NamedArgument& named_arg);
  Buffer visit(const SizedType &type);

private:
  template <typename U>
  Buffer format(U &value,
                MetadataIndex &metadata,
                size_t max_width,
                bool bare = false)
  {
    return Formatter(mode, metadata, max_width, bare).visit(value);
  }

  template <typename U>
  Buffer format_list(std::vector<U> &exprs,
                     const std::string &sep,
                     MetadataIndex &metadata,
                     size_t max_width,
                     bool bare = false);

  FormatMode mode;
  MetadataIndex &metadata;
  size_t max_width;
  bool bare;
};

// Printer is a class to format AST nodes of type T.
class Printer : Visitor<Printer> {
public:
  constexpr static size_t kDefaultWidth = 90;
  Printer(const ASTContext &ast,
          std::ostream &out,
          FormatMode mode = FormatMode::Minimal,
          size_t max_width = kDefaultWidth)
      : ast_(ast), out_(out), mode_(mode), max_width_(max_width) {};

  template <typename T>
  void visit(T &value)
  {
    MetadataIndex metadata = ast_.metadata();
    out_ << Formatter(mode_, metadata, max_width_, true).visit(value);
  }

private:
  const ASTContext &ast_;
  std::ostream &out_;
  FormatMode mode_;
  size_t max_width_;
};

} // namespace bpftrace::ast
