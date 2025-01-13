#include "lib_parser.h"

#include <fstream>
#include <vector>

#include "bpfbytecode.h"
#include "functions.h"
#include "struct.h"

namespace fs = std::filesystem;

namespace bpftrace {

namespace {
std::vector<char> openFile(fs::path path)
{
  auto length = fs::file_size(path);
  std::vector<char> buf(length);
  std::ifstream inputFile{ path, std::ios_base::binary };
  inputFile.read(buf.data(), length);
  inputFile.close();
  return buf;
}
} // namespace

bool LibParser::parse(std::string_view libName,
                      fs::path libPath,
                      FunctionRegistry &functions,
                      StructManager &structs)
{
  auto elf = openFile(libPath);
  BpfBytecode bytecode{ elf };
  auto btf = bytecode.btf();

  for (const auto &func : btf.functions()) {
    std::vector<Param> params;
    params.reserve(func.parameters().size());
    for (const auto &param : func.parameters()) {
      params.emplace_back(std::string{ param.name() }, param.type(structs));
    }

    //    std::string funcName = std::string{libName} + "_" +
    //    std::string{func.name()};
    functions.add(Function::Origin::External,
                  libName,
                  func.name(),
                  func.returnType(structs),
                  std::move(params));
  }

  for (const auto &func : btf.functions()) {
    std::cout << func.name() << "(" << func.parameters().size() << ")\n";
    for (const auto &param : func.parameters()) {
      std::cout << param.name() << ": " << param.type(structs) << "\n";
    }
    std::cout << "\n";
  }
}

} // namespace bpftrace
