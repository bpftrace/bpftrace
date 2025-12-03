#include <cstring>
#include <fstream>
#include <glob.h>
#include <utility>

#include "bpfprogram.h"
#include "btf/btf.h"
#include "providers/provider.h"
#include "providers/tracepoint.h"
#include "tracefs/tracefs.h"
#include "util/result.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

// Create BTF type for tracepoint context.
static Result<btf::AnyType> create_tracepoint_type(
    const btf::Types &kernel_types,
    const std::string &category,
    const std::string &event_name)
{
  btf::Types overlay(kernel_types);
  std::string format_file_path = tracefs::event_format_file(category,
                                                            event_name);

  std::ifstream format_file(format_file_path.c_str());
  if (format_file.fail()) {
    return make_error<SystemError>("Unable to open format file: " +
                                   format_file_path);
  }

  // Parse fields to build BTF struct.
  std::vector<std::pair<std::string, btf::ValueType>> fields;
  int last_offset = 0;

  for (std::string line; getline(format_file, line);) {
    auto field_pos = line.find("field:");
    if (field_pos == std::string::npos)
      continue;

    auto field_semi_pos = line.find(';', field_pos);
    if (field_semi_pos == std::string::npos)
      continue;

    auto offset_pos = line.find("offset:", field_semi_pos);
    if (offset_pos == std::string::npos)
      continue;

    auto offset_semi_pos = line.find(';', offset_pos);
    if (offset_semi_pos == std::string::npos)
      continue;

    auto size_pos = line.find("size:", offset_semi_pos);
    if (size_pos == std::string::npos)
      continue;

    auto size_semi_pos = line.find(';', size_pos);
    if (size_semi_pos == std::string::npos)
      continue;

    int size = std::stoi(
        line.substr(size_pos + 5, size_semi_pos - size_pos - 5));
    int offset = std::stoi(
        line.substr(offset_pos + 7, offset_semi_pos - offset_pos - 7));

    // Add padding fields for gaps.
    if (offset && last_offset) {
      int gap = offset - last_offset;
      for (int i = 0; i < gap; i++) {
        std::string pad_name = "__pad_" + std::to_string(offset - gap + i);
        auto char_type = kernel_types.lookup<btf::Integer>("char");
        if (!char_type) {
          return char_type.takeError();
        }
        fields.emplace_back(pad_name, *char_type);
      }
    }

    last_offset = offset + size;
    std::string field = line.substr(field_pos + 6,
                                    field_semi_pos - field_pos - 6);
    auto field_type_end_pos = field.find_last_of(" ");
    if (field_type_end_pos == std::string::npos)
      continue;

    std::string field_type = field.substr(0, field_type_end_pos);
    std::string field_name = field.substr(field_type_end_pos + 1);

    // We need to parse `field_type` as a basic C type, looking up the
    // primitive name in the kernel_types object. We then need to see if
    // it's a pointer, lookup at the associated pointer etc. We need check
    // if it's an array, look at the associate array, etc. If the field is
    // marked as __data_loc, this is effectively an extra pointers.
    bool is_data_loc = false;
    if (field_type.starts_with("__data_loc")) {
      is_data_loc = true;
      field_type = field_type.substr(11); // Remove "__data_loc " prefix.
    }

    // Parse type name, removing any pointer/array decorations.
    int pointer_count = 0;
    int array_size = 0;
    while (!field_type.empty() && field_type.back() == '*') {
      pointer_count++;
      field_type.pop_back();
      while (!field_type.empty() && std::isspace(field_type.back())) {
        field_type.pop_back();
      }
    }
    auto bracket_pos = field_name.find('[');
    if (bracket_pos != std::string::npos) {
      auto close_bracket = field_name.find(']', bracket_pos);
      if (close_bracket != std::string::npos) {
        std::string size_str = field_name.substr(bracket_pos + 1,
                                                 close_bracket - bracket_pos -
                                                     1);
        if (!size_str.empty()) {
          array_size = std::stoi(size_str);
        }
        field_name = field_name.substr(0, bracket_pos);
        while (!field_name.empty() && std::isspace(field_name.back())) {
          field_name.pop_back();
        }
      }
    }

    std::optional<btf::ValueType> type;
    if (field_type.starts_with("struct ")) {
      std::string struct_name = field_type.substr(7);
      auto struct_type = kernel_types.lookup<btf::Struct>(struct_name);
      if (!struct_type) {
        return struct_type.takeError();
      } else {
        type = *struct_type;
      }
    } else if (field_type.starts_with("union ")) {
      std::string union_name = field_type.substr(6);
      auto union_type = kernel_types.lookup<btf::Union>(union_name);
      if (!union_type) {
        return union_type.takeError();
      } else {
        type = *union_type;
      }
    } else if (field_type.starts_with("enum ")) {
      std::string enum_name = field_type.substr(5);
      auto enum_type = kernel_types.lookup<btf::Enum>(enum_name);
      if (!enum_type) {
        auto enum64_type = kernel_types.lookup<btf::Enum64>(enum_name);
        if (!enum64_type) {
          return enum64_type.takeError();
        } else {
          type = *enum64_type;
        }
      } else {
        type = *enum_type;
      }
    } else {
      auto typedef_type = kernel_types.lookup<btf::Typedef>(field_type);
      if (!typedef_type) {
        auto int_type = kernel_types.lookup<btf::Integer>(field_type);
        if (!int_type) {
          return int_type.takeError();
        } else {
          type = *int_type;
        }
      } else {
        type = *typedef_type;
      }
    }

    // Wrap in pointers if needed.
    for (int i = 0; i < pointer_count; i++) {
      auto ptr_type = overlay.add<btf::Pointer>(*type);
      if (!ptr_type) {
        return ptr_type.takeError();
      } else {
        type = *ptr_type;
      }
    }

    // Wrap in array if needed.
    if (array_size > 0) {
      // Need an index type for the array.
      auto index_type = kernel_types.lookup<btf::Integer>("int");
      if (!index_type) {
        return index_type.takeError();
      }
      auto array_type = overlay.add<btf::Array>(*index_type, *type, array_size);
      if (!array_type) {
        return array_type.takeError();
      }
      type = *array_type;
    }

    // If __data_loc, wrap in an extra pointer.
    if (is_data_loc) {
      auto ptr_type = overlay.add<btf::Pointer>(*type);
      if (!ptr_type) {
        return ptr_type.takeError();
      }
      type = *ptr_type;
    }

    // Add it to our list of fields.
    fields.emplace_back(field_name, *type);
  }

  // Create a new struct from these fields.
  auto s = overlay.add<btf::Struct>("struct __tracepoint", fields);
  if (!s) {
    return s.takeError();
  }
  auto ptr = overlay.add<btf::Pointer>(*s);
  if (!ptr) {
    return ptr.takeError();
  }
  return *ptr;
}

class TracepointAttachPoint : public AttachPoint {
public:
  TracepointAttachPoint(std::string category, std::string tp_name)
      : category(std::move(category)), tp_name(std::move(tp_name)) {};

  std::string name() const override
  {
    if (category.empty()) {
      return tp_name;
    }
    return category + ":" + tp_name;
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_TRACEPOINT;
  }

  Result<btf::AnyType> context_type(
      const btf::Types &kernel_types) const override
  {
    return create_tracepoint_type(kernel_types, category, tp_name);
  }

  const std::string category;
  const std::string tp_name;
};

static Result<std::set<std::string>> available_tracepoints()
{
  // Check if this has been cached.
  static std::set<std::string> tracepoints;
  if (!tracepoints.empty()) {
    return tracepoints;
  }

  std::string events_file = tracefs::available_events();
  std::ifstream file(events_file);
  if (!file.is_open()) {
    return make_error<SystemError>("Unable to open tracefs events file");
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty()) {
      continue;
    }
    tracepoints.emplace(line);
  }

  return tracepoints;
}

Result<AttachPointList> TracepointProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  AttachPointList results;

  // Get all available tracepoints.
  auto all_tracepoints = available_tracepoints();
  if (!all_tracepoints) {
    return all_tracepoints.takeError();
  }

  // Match the string against the provider set.
  bool start_wildcard, end_wildcard;
  auto tokens = util::get_wildcard_tokens(str, start_wildcard, end_wildcard);
  for (const auto &tracepoint : *all_tracepoints) {
    if (util::wildcard_match(
            tracepoint, tokens, start_wildcard, end_wildcard)) {
      auto colon_pos = tracepoint.find(':');
      if (colon_pos != std::string::npos) {
        std::string match_category = tracepoint.substr(0, colon_pos);
        std::string match_name = tracepoint.substr(colon_pos + 1);
        results.emplace_back(
            std::make_unique<TracepointAttachPoint>(match_category,
                                                    match_name));
      } else {
        return make_error<ParseError>(this, str, "invalid tracepoint format");
      }
    }
  }
  if (!util::has_wildcard(str) && results.empty()) {
    return make_error<ParseError>(this, str, "function not found");
  }

  return results;
}

Result<AttachedProbeList> TracepointProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  const auto &tp_attach_point = attach_point->as<TracepointAttachPoint>();

  // Use libbpf to attach the tracepoint.
  auto *link = bpf_program__attach_tracepoint(prog.bpf_prog(),
                                              tp_attach_point.category.c_str(),
                                              tp_attach_point.tp_name.c_str());

  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach tracepoint");
  }
  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
