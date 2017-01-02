#include "codegen_bcc.h"
#include "ast.h"
#include "parser.tab.hh"

namespace ebpf {
namespace bpftrace {
namespace ast {

void CodegenBCC::visit(Integer &integer)
{
}

void CodegenBCC::visit(Builtin &builtin)
{
}

void CodegenBCC::visit(Call &call)
{
}

void CodegenBCC::visit(Map &map)
{
}

void CodegenBCC::visit(Binop &binop)
{
}

void CodegenBCC::visit(Unop &unop)
{
}

void CodegenBCC::visit(ExprStatement &expr)
{
}

void CodegenBCC::visit(AssignMapStatement &assignment)
{
}

void CodegenBCC::visit(AssignMapCallStatement &assignment)
{
}

void CodegenBCC::visit(Predicate &pred)
{
}

void CodegenBCC::visit(Probe &probe)
{
}

void CodegenBCC::visit(Program &program)
{
}

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
