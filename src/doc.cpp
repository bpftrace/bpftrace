#include "doc.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <ranges>
#include <string_view>
#include <variant>

#include "ast/ast.h"

namespace bpftrace::doc {
namespace {

struct Block {
  std::vector<std::string> lines;
};

using Variant = ast::MetadataIndex::Variant;

bool is_blank(std::string_view str)
{
  return std::ranges::all_of(str, [](unsigned char c) {
    return std::isspace(c) != 0;
  });
}

void trim_blank_lines(std::vector<std::string> &lines)
{
  while (!lines.empty() && is_blank(lines.front())) {
    lines.erase(lines.begin());
  }
  while (!lines.empty() && is_blank(lines.back())) {
    lines.pop_back();
  }
}

std::vector<Block> split_blocks(const std::vector<Variant> &metadata)
{
  std::vector<Block> blocks;
  Block current;

  auto flush = [&]() {
    if (!current.lines.empty()) {
      blocks.push_back(std::move(current));
      current = {};
    }
  };

  for (const auto &segment : metadata) {
    if (const auto *comment = std::get_if<std::string>(&segment)) {
      current.lines.push_back(*comment);
    } else {
      flush();
    }
  }

  flush();
  return blocks;
}

std::optional<Kind> kind_for_node(const ast::Node *node)
{
  if (dynamic_cast<const ast::Macro *>(node) != nullptr) {
    return Kind::Macro;
  }
  if (dynamic_cast<const ast::Subprog *>(node) != nullptr) {
    return Kind::Function;
  }
  if (dynamic_cast<const ast::Probe *>(node) != nullptr) {
    return Kind::Probe;
  }
  return std::nullopt;
}

std::optional<std::string> name_for_node(const ast::Node *node)
{
  if (const auto *macro = dynamic_cast<const ast::Macro *>(node)) {
    return macro->name;
  }
  if (const auto *function = dynamic_cast<const ast::Subprog *>(node)) {
    return function->name;
  }
  if (const auto *probe = dynamic_cast<const ast::Probe *>(node)) {
    if (probe->attach_points.empty()) {
      return std::nullopt;
    }

    std::string name;
    for (size_t i = 0; i < probe->attach_points.size(); ++i) {
      if (i != 0) {
        name += ",";
      }
      name += probe->attach_points.at(i)->name();
    }
    return name;
  }
  return std::nullopt;
}

std::optional<Entry> parse_block(const Block &block, const ast::Node *node)
{
  Entry entry;
  std::vector<std::string> description_lines;
  bool has_explicit_name = false;

  for (const auto &line : block.lines) {
    if (line.starts_with(":function ")) {
      entry.name = line.substr(sizeof(":function ") - 1);
      entry.kind = Kind::Function;
      has_explicit_name = true;
    } else if (line.starts_with(":variant ")) {
      auto variant = line.substr(sizeof(":variant ") - 1);
      entry.variants.push_back(variant);
      if (variant.find("()") != std::string::npos) {
        auto no_args_variant = variant;
        no_args_variant.replace(no_args_variant.find("()"), 2, "");
        entry.variants.push_back(std::move(no_args_variant));
      }
    } else if (line.starts_with(":deprecated_variant ")) {
      entry.deprecated_variants.push_back(
          line.substr(sizeof(":deprecated_variant ") - 1));
    } else {
      description_lines.push_back(line);
    }
  }

  trim_blank_lines(description_lines);
  if (!description_lines.empty()) {
    for (size_t i = 0; i < description_lines.size(); ++i) {
      if (i != 0) {
        entry.description += "\n";
      }
      entry.description += description_lines.at(i);
    }
  }

  if (!has_explicit_name) {
    auto kind = kind_for_node(node);
    auto name = name_for_node(node);
    if (!kind || !name) {
      return std::nullopt;
    }
    entry.kind = *kind;
    entry.name = *name;
  }

  if (entry.name.empty()) {
    return std::nullopt;
  }

  if (node != nullptr) {
    entry.source_file = node->loc->filename();
    entry.line = node->loc->line();
  }

  return entry;
}

std::vector<const ast::Node *> root_nodes(const ast::Program &program)
{
  std::vector<const ast::Node *> nodes;

  for (const auto *node : program.c_statements) {
    nodes.push_back(node);
  }
  if (program.config != nullptr) {
    nodes.push_back(program.config);
  }
  for (const auto *node : program.imports) {
    nodes.push_back(node);
  }
  for (const auto *node : program.map_decls) {
    nodes.push_back(node);
  }
  for (const auto *node : program.macros) {
    nodes.push_back(node);
  }
  for (const auto *node : program.functions) {
    nodes.push_back(node);
  }
  for (const auto *node : program.probes) {
    nodes.push_back(node);
  }

  std::ranges::sort(nodes, [](const ast::Node *lhs, const ast::Node *rhs) {
    return lhs->loc->current < rhs->loc->current;
  });

  return nodes;
}

void append_entries(std::vector<Entry> &entries,
                    const std::vector<Block> &blocks,
                    const ast::Node *node)
{
  for (size_t i = 0; i < blocks.size(); ++i) {
    const auto *associated_node = (i + 1 == blocks.size()) ? node : nullptr;
    auto entry = parse_block(blocks.at(i), associated_node);
    if (entry) {
      entries.push_back(std::move(*entry));
    }
  }
}

} // namespace

std::vector<Entry> extract(const ast::ASTContext &ast)
{
  std::vector<Entry> entries;
  auto metadata = ast.metadata();
  auto *program = ast.root;
  if (program == nullptr) {
    return entries;
  }

  for (const auto *node : root_nodes(*program)) {
    auto blocks = split_blocks(metadata.before(node->loc->current.begin).all());
    append_entries(entries, blocks, node);
  }

  append_entries(entries, split_blocks(metadata.all()), nullptr);

  std::ranges::sort(entries, less_than);

  return entries;
}

bool less_than(const Entry &lhs, const Entry &rhs)
{
  if (lhs.name != rhs.name) {
    return lhs.name < rhs.name;
  }
  if (lhs.source_file != rhs.source_file) {
    return lhs.source_file < rhs.source_file;
  }
  return lhs.line < rhs.line;
}

void write_markdown(std::ostream &out, const std::vector<Entry> &entries)
{
  for (size_t i = 0; i < entries.size(); ++i) {
    const auto &entry = entries.at(i);
    out << "### " << entry.name << "\n";

    if (!entry.variants.empty() || !entry.deprecated_variants.empty()) {
      for (const auto &variant : entry.variants) {
        out << "- `" << variant << "`\n";
      }
      for (const auto &variant : entry.deprecated_variants) {
        out << "- deprecated `" << variant << "`\n";
      }
      out << "\n";
    } else {
      out << "\n";
    }

    if (!entry.description.empty()) {
      out << entry.description << "\n";
    }

    if (i + 1 != entries.size()) {
      out << "\n";
    }
    out << "\n";
  }
}

} // namespace bpftrace::doc
