#include "dwarf_parser.h"
#include "mocks.h"
#include "util/symbols.h"
#include <elf.h>
#include <optional>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

#ifdef HAVE_LIBDW
namespace bpftrace::test {

TEST(dwarf_parser, inherited_parameter_names)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(), DWARF_ORIGIN_BINARY, "");
  ASSERT_NE(dwarf, nullptr);
  EXPECT_EQ(dwarf->get_function_params("add_named"),
            (std::vector<std::string>{ "int left", "int right" }));

  auto args = dwarf->resolve_args("add_named");
  ASSERT_NE(args, nullptr);
  ASSERT_EQ(args->fields.size(), 2);
  EXPECT_TRUE(args->HasField("left"));
  EXPECT_TRUE(args->HasField("right"));
}

#ifdef HAVE_SOURCE_LOCATION_FIXTURES
TEST(dwarf_parser, source_location_prefers_statement)
{
  auto bpftrace = create_bpftrace();
  auto dwarf = Dwarf::GetFromBinary(bpftrace.get(),
                                    DWARF_LINE_SELECTION_BINARY,
                                    "");
  ASSERT_NE(dwarf, nullptr);

  auto symbols = util::resolve_symbols(DWARF_LINE_SELECTION_BINARY,
                                       { "line_selection_preferred" },
                                       false);
  if (!symbols)
    FAIL() << llvm::toString(symbols.takeError());
  ASSERT_EQ(symbols->size(), 1);

  auto location = dwarf->line_to_addr("dwarf_line_selection.c", 10, 1, "");
  if (!location)
    FAIL() << llvm::toString(location.takeError());
  EXPECT_EQ(location->address, symbols->front().v_addr);
  EXPECT_EQ(location->function, "line_selection_preferred");
}
#endif

TEST(dwarf_parser, build_id_note_parser)
{
  std::string notes;
  const char name[] = "GNU";
  const unsigned char desc[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };
  const uint32_t name_size = sizeof(name);
  const uint32_t desc_size = sizeof(desc);
  const uint32_t type = NT_GNU_BUILD_ID;

  notes.append(reinterpret_cast<const char *>(&name_size), sizeof(name_size));
  notes.append(reinterpret_cast<const char *>(&desc_size), sizeof(desc_size));
  notes.append(reinterpret_cast<const char *>(&type), sizeof(type));
  notes.append(name, name_size);
  notes.append((4 - (name_size % 4)) % 4, '\0');
  notes.append(reinterpret_cast<const char *>(desc), desc_size);
  notes.append((4 - (desc_size % 4)) % 4, '\0');

  std::istringstream input(notes, std::ios::binary);
  auto id = parse_build_id_notes(input);
  EXPECT_EQ(id, std::optional<std::string>("0123456789ab"));
}

TEST(dwarf_parser, build_id_note_skips_other_notes)
{
  std::string notes;
  const char other[] = "OTHER";
  const uint32_t other_name_size = sizeof(other);
  const uint32_t other_desc_size = 0;
  const uint32_t other_type = NT_VERSION;
  notes.append(reinterpret_cast<const char *>(&other_name_size),
               sizeof(other_name_size));
  notes.append(reinterpret_cast<const char *>(&other_desc_size),
               sizeof(other_desc_size));
  notes.append(reinterpret_cast<const char *>(&other_type), sizeof(other_type));
  notes.append(other, other_name_size);
  notes.append((4 - (other_name_size % 4)) % 4, '\0');

  const char gnu[] = "GNU";
  const unsigned char desc[] = { 0xde, 0xad, 0xbe, 0xef };
  const uint32_t gnu_name_size = sizeof(gnu);
  const uint32_t gnu_desc_size = sizeof(desc);
  const uint32_t gnu_type = NT_GNU_BUILD_ID;
  notes.append(reinterpret_cast<const char *>(&gnu_name_size),
               sizeof(gnu_name_size));
  notes.append(reinterpret_cast<const char *>(&gnu_desc_size),
               sizeof(gnu_desc_size));
  notes.append(reinterpret_cast<const char *>(&gnu_type), sizeof(gnu_type));
  notes.append(gnu, gnu_name_size);
  notes.append((4 - (gnu_name_size % 4)) % 4, '\0');
  notes.append(reinterpret_cast<const char *>(desc), gnu_desc_size);
  notes.append((4 - (gnu_desc_size % 4)) % 4, '\0');

  std::istringstream input(notes, std::ios::binary);
  auto id = parse_build_id_notes(input);
  EXPECT_EQ(id, std::optional<std::string>("deadbeef"));
}

TEST(dwarf_parser, build_id_note_malformed)
{
  std::istringstream empty("", std::ios::binary);
  EXPECT_FALSE(parse_build_id_notes(empty));

  const uint32_t bad_name_size = 4;
  const uint32_t bad_desc_size = 16;
  const uint32_t bad_type = NT_GNU_BUILD_ID;
  std::string notes;
  notes.append(reinterpret_cast<const char *>(&bad_name_size),
               sizeof(bad_name_size));
  notes.append(reinterpret_cast<const char *>(&bad_desc_size),
               sizeof(bad_desc_size));
  notes.append(reinterpret_cast<const char *>(&bad_type), sizeof(bad_type));
  notes.append("GNU\0", 4);
  std::istringstream truncated(notes, std::ios::binary);
  EXPECT_FALSE(parse_build_id_notes(truncated));
}

} // namespace bpftrace::test
#endif
