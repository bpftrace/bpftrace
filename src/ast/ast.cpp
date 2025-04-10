#include <algorithm>
#include <utility>

#include "ast/ast.h"
#include "ast/context.h"
#include "log.h"
#include "util/format.h"

namespace bpftrace::ast {

Diagnostic &Node::addError() const
{
  return ctx_.diagnostics_->addError(loc);
}

Diagnostic &Node::addWarning() const
{
  return ctx_.diagnostics_->addWarning(loc);
}

const SizedType &Expression::type() const
{
  return std::visit(
      [](const auto *expr) -> const SizedType & { return expr->type(); },
      value);
}

static constexpr std::string_view ENUM = "enum ";

std::string opstr(const Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      return "return";
    case JumpType::BREAK:
      return "break";
    case JumpType::CONTINUE:
      return "continue";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Binop &binop)
{
  switch (binop.op) {
    case Operator::EQ:
      return "==";
    case Operator::NE:
      return "!=";
    case Operator::LE:
      return "<=";
    case Operator::GE:
      return ">=";
    case Operator::LT:
      return "<";
    case Operator::GT:
      return ">";
    case Operator::LAND:
      return "&&";
    case Operator::LOR:
      return "||";
    case Operator::LEFT:
      return "<<";
    case Operator::RIGHT:
      return ">>";
    case Operator::PLUS:
      return "+";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "*";
    case Operator::DIV:
      return "/";
    case Operator::MOD:
      return "%";
    case Operator::BAND:
      return "&";
    case Operator::BOR:
      return "|";
    case Operator::BXOR:
      return "^";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      return "!";
    case Operator::BNOT:
      return "~";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "dereference";
    case Operator::INCREMENT:
      if (unop.is_post_op)
        return "++ (post)";
      return "++ (pre)";
    case Operator::DECREMENT:
      if (unop.is_post_op)
        return "-- (post)";
      return "-- (pre)";
    default:
      return {};
  }

  return {}; // unreached
}

AttachPoint &AttachPoint::create_expansion_copy(ASTContext &ctx,
                                                const std::string &match) const
{
  // Create a new node with the same raw tracepoint. We initialize all the
  // information about the attach point, and then override/reset values
  // depending on the specific probe type.
  auto &ap = *ctx.make_node<AttachPoint>(raw_input,
                                         ignore_invalid,
                                         Location(loc));
  ap.index_ = index_;
  ap.provider = provider;
  ap.target = target;
  ap.lang = lang;
  ap.ns = ns;
  ap.func = func;
  ap.pin = pin;
  ap.usdt = usdt;
  ap.freq = freq;
  ap.len = len;
  ap.mode = mode;
  ap.async = async;
  ap.expansion = expansion;
  ap.address = address;
  ap.func_offset = func_offset;

  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      ap.func = match;
      if (match.find(":") != std::string::npos)
        ap.target = util::erase_prefix(ap.func);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
      // Tracepoint, raw tracepoint, uprobe, and fentry/fexit probes specify
      // both a target (category for tracepoints, binary for uprobes, and
      // kernel module for fentry/fexit and a function name.
      ap.func = match;
      ap.target = util::erase_prefix(ap.func);
      break;
    case ProbeType::usdt:
      // USDT probes specify a target binary path, a provider, and a function
      // name.
      ap.func = match;
      ap.target = util::erase_prefix(ap.func);
      ap.ns = util::erase_prefix(ap.func);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Watchpoint probes come with target prefix. Strip the target to get the
      // function
      ap.func = match;
      util::erase_prefix(ap.func);
      break;
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::interval:
    case ProbeType::profile:
    case ProbeType::special:
    case ProbeType::iter:
    case ProbeType::invalid:
      break;
    default:
      LOG(BUG) << "Unknown probe type";
  }
  return ap;
}

std::string AttachPoint::name() const
{
  std::string n = provider;
  if (!target.empty())
    n += ":" + target;
  if (!lang.empty())
    n += ":" + lang;
  if (!ns.empty())
    n += ":" + ns;
  if (!func.empty()) {
    n += ":" + func;
    if (func_offset != 0)
      n += "+" + std::to_string(func_offset);
  }
  if (address != 0)
    n += ":" + std::to_string(address);
  if (freq != 0)
    n += ":" + std::to_string(freq);
  if (len != 0)
    n += ":" + std::to_string(len);
  if (!mode.empty())
    n += ":" + mode;
  return n;
}

int AttachPoint::index() const
{
  return index_;
}

void AttachPoint::set_index(int index)
{
  index_ = index;
}

std::string Probe::name() const
{
  std::vector<std::string> ap_names;
  std::ranges::transform(attach_points,

                         std::back_inserter(ap_names),
                         [](const AttachPoint *ap) { return ap->name(); });
  return util::str_join(ap_names, ",");
}

std::string Probe::args_typename() const
{
  return "struct " + name() + "_args";
}

int Probe::index() const
{
  return index_;
}

void Probe::set_index(int index)
{
  index_ = index;
}

bool Probe::has_ap_of_probetype(ProbeType probe_type)
{
  return std::ranges::any_of(attach_points, [probe_type](auto *ap) {
    return probetype(ap->provider) == probe_type;
  });
}

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident);
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

SizedType ident_to_sized_type(const std::string &ident)
{
  if (ident.starts_with(ENUM)) {
    auto enum_name = ident.substr(ENUM.size());
    // This is an automatic promotion to a uint64
    // even though it's possible that highest variant value of that enum
    // fits into a smaller int. This will also affect casts from a smaller
    // int and cause an ERROR: Integer size mismatch.
    // This could potentially be revisited or the cast relaxed
    // if we check the variant values during semantic analysis.
    return CreateEnum(64, enum_name);
  }
  return ident_to_record(ident);
}

} // namespace bpftrace::ast
