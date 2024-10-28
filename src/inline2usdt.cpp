#include "log.h"
#include <fstream>
#include <iostream>
#include <lldb/API/SBAddress.h>
#include <lldb/API/SBBreakpointLocation.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/API/SBError.h>

extern "C" {
#include <getopt.h>
}

struct Args {
  std::string input_file;            /* Binary to modify */
  std::string output_file;           /* Name of the patched binary */
  std::string function_regex = ".*"; /* Take all functions by default*/
};

void usage(std::ostream& out)
{
  out << "USAGE: inline2usdt [OPTIONS] <file> [<output-file>]\n";
  out << "OPTIONS:\n";
  out << "  -h, --help     Print this help message\n";
  out << "  -r, --regex    Filter functions to add as usdt\n";
}

Args parse_args(int argc, char* argv[])
{
  Args args;

  const char* const short_options = "hr:";
  struct option long_options[] = {
    { "help", no_argument, nullptr, 'h' },
    { "regex", required_argument, nullptr, 'r' },
  };

  int c = -1;
  while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) !=
         -1) {
    switch (c) {
      case 'h': // --help
        usage(std::cout);
        exit(0);
      case 'r': // --regex
        args.function_regex = optarg;
        break;
      default:
        usage(std::cerr);
        exit(1);
    }
  }

  if (optind < argc) {
    args.input_file = argv[optind++];
  } else {
    LOG(ERROR) << "Missing binary file";
    usage(std::cerr);
    exit(1);
  }

  if (optind < argc) {
    args.output_file = argv[optind];
  } else {
    args.output_file = args.input_file + "-patched";
  }

  return args;
}

struct USDT {
  uintptr_t addr;
  uintptr_t base_addr;
  uintptr_t semaphore_addr;
  std::string_view provider;
  std::string_view name;
  std::string_view arg_types;

  uint32_t length() const
  {
    return 8 + 8 + 8 + provider.size() + 1 + name.size() + 1 +
           arg_types.size() + 1;
  }

  static USDT from_addr(lldb::SBAddress addr)
  {
    std::string_view provider;
    std::string_view name;
    // Map the address to the corresponding function name:
    // 1. Using the block
    auto block = addr.GetBlock();
    if (block) {
      // Find the first block that has an inlined name:
      while (block && block.GetInlinedName() == nullptr)
        block = block.GetParent();

      if (block && block.GetInlinedName()) {
        provider = "inline";
        name = block.GetInlinedName();
      }
    }

    // 2. Otherwise, using the function name
    if (name.empty()) {
      auto fn = addr.GetFunction();
      if (fn && fn.GetName()) {
        provider = "symbol";
        name = fn.GetName();
      }
    }

    // 3. Otherwise, using the symbol name
    if (name.empty()) {
      provider = "symbol";
      name = addr.GetSymbol().GetName();
    }

    // Construct the USDT
    return USDT{
      .addr = addr.GetFileAddress(),
      .base_addr = 0,      // Not implemented
      .semaphore_addr = 0, // Not implemented
      .provider = provider,
      .name = name,
      .arg_types = "", // Not implemented
    };
  }

  static constexpr std::string_view kNoteName = "stapsdt";
  static constexpr uint32_t kNoteType = 0x3;

  friend std::ostream& operator<<(std::ostream& out, const USDT& usdt)
  {
    // See https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation

    // Write the note header
    uint32_t note_name_length = kNoteName.size() + 1;
    out.write(reinterpret_cast<const char*>(&note_name_length),
              sizeof(note_name_length));

    uint32_t note_length = usdt.length();
    out.write(reinterpret_cast<const char*>(&note_length), sizeof(note_length));

    out.write(reinterpret_cast<const char*>(&kNoteType), sizeof(kNoteType));

    char terminator = '\0';
    out.write(kNoteName.data(), kNoteName.size());
    out.write(&terminator, sizeof(terminator));

    // Write the USDT
    out.write(reinterpret_cast<const char*>(&usdt.addr), sizeof(usdt.addr));
    out.write(reinterpret_cast<const char*>(&usdt.base_addr),
              sizeof(usdt.base_addr));
    out.write(reinterpret_cast<const char*>(&usdt.semaphore_addr),
              sizeof(usdt.semaphore_addr));

    out.write(usdt.provider.data(), usdt.provider.size());
    out.write(&terminator, sizeof(terminator));

    out.write(usdt.name.data(), usdt.name.size());
    out.write(&terminator, sizeof(terminator));

    out.write(usdt.arg_types.data(), usdt.arg_types.size());
    out.write(&terminator, sizeof(terminator));

    size_t padding = 4 - (note_length % 4);
    if (padding < 4)
      out.write("\0\0\0\0", padding);

    return out;
  }
};

int main(int argc, char* argv[])
{
  auto args = parse_args(argc, argv);

  lldb::SBDebugger::Initialize();

  // Init the debugger and open the input file
  auto debugger = lldb::SBDebugger::Create(/* source_init_file = */ false);
  if (!debugger)
    LOG(BUG) << "Failed to create debugger";
  debugger.SetScriptLanguage(lldb::ScriptLanguage::eScriptLanguageNone);

  lldb::SBError error;
  auto target = debugger.CreateTarget(
      args.input_file.c_str(), nullptr, nullptr, true, error);
  if (!error.Success() || !target.IsValid()) {
    LOG(BUG) << "Failed to create target: " << error.GetCString();
  }

  // Open the temporary note file
  std::ofstream out("note.stapsdt.bin", std::ios::binary);
  if (!out)
    LOG(BUG) << "Failed to open output file: note.stapsdt.bin";

  // Write each breakpoint location as a USDT to the note file
  auto breakpoints = target.BreakpointCreateByRegex(
      args.function_regex.c_str());
  if (!breakpoints)
    LOG(BUG) << "Failed to create breakpoints";

  LOG(DEBUG) << "Found " << breakpoints.GetNumLocations() << " locations";
  std::vector<USDT> usdts(breakpoints.GetNumLocations());
  for (uint32_t i = 0; i < breakpoints.GetNumLocations(); ++i) {
    usdts[i] = USDT::from_addr(breakpoints.GetLocationAtIndex(i).GetAddress());
  }

  std::sort(usdts.begin(), usdts.end(), [](auto& a, auto& b) {
    return a.name < b.name;
  });

  for (auto& usdt : usdts)
    out << usdt;

  // Cleanup
  out.close();

  debugger.DeleteTarget(target);
  debugger.Clear();

  lldb::SBDebugger::Terminate();

  // Patch the binary with the note file
  auto cmd = "llvm-objcopy "
             "--add-section .note.stapsdt=note.stapsdt.bin "
             "--set-section-alignment .note.stapsdt=4 "
             "--set-section-type .note.stapsdt=7 "
             "--no-verify-note-sections \"" +
             args.input_file + "\" \"" + args.output_file + '"';
  std::system(cmd.c_str());
}
