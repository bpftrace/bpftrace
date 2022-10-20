#include "dibuilderbpf.h"
#include "utils.h"

#include <llvm/IR/Function.h>

namespace bpftrace {
namespace ast {

DIBuilderBPF::DIBuilderBPF(Module &module) : DIBuilder(module)
{
  file = createFile("bpftrace.bpf.o", ".");
}

void DIBuilderBPF::createFunctionDebugInfo(Function &func)
{
  // BPF probe function has:
  // - int return type
  // - single parameter (ctx) of a pointer type
  SmallVector<Metadata *, 2> types = { getInt64Ty(), getInt8PtrTy() };

  DISubroutineType *ditype = createSubroutineType(getOrCreateTypeArray(types));

  std::string sanitised_name = sanitise_bpf_program_name(func.getName().str());

  DISubprogram::DISPFlags flags = DISubprogram::SPFlagDefinition;
  if (func.isLocalLinkage(func.getLinkage()))
    flags |= DISubprogram::DISPFlags::SPFlagLocalToUnit;

  DISubprogram *subprog = createFunction(file,
                                         sanitised_name,
                                         sanitised_name,
                                         file,
                                         0,
                                         ditype,
                                         0,
                                         DINode::FlagPrototyped,
                                         flags);

  std::string prefix("var");
  for (size_t i = 0; i < types.size(); ++i)
  {
    createParameterVariable(subprog,
                            prefix + std::to_string(i),
                            i,
                            file,
                            0,
                            (DIType *)types[i],
                            true);
  }

  func.setSubprogram(subprog);
}

DIType *DIBuilderBPF::getInt64Ty()
{
  if (!types_.int64)
    types_.int64 = createBasicType("int64", 64, dwarf::DW_ATE_signed);

  return types_.int64;
}

DIType *DIBuilderBPF::getInt8PtrTy()
{
  if (!types_.int8_ptr)
    types_.int8_ptr = createPointerType(
        createBasicType("int8", 8, dwarf::DW_ATE_signed), 64);

  return types_.int8_ptr;
}

} // namespace ast
} // namespace bpftrace
