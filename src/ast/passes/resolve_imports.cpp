#include "resolve_imports.h"

#include "bpftrace.h"
#include "log.h"

namespace bpftrace::ast {

ResolveImports::ResolveImports(ASTContext &ctx,
                               BPFtrace &bpftrace)
    : Visitor<ResolveImports>(ctx),
      bpftrace_(bpftrace)
{
}

void ResolveImports::visit(Import &imp)
{
  if (imp.host_import_source() || imp.host_import_module())
    LOG(ERROR, imp.loc, err_) << "Possible host import, not yet supported";
  if (imp.bpftrace_import_source())
    LOG(ERROR, imp.loc, err_) << "Possible bpftrace import, not yet supported";
  if (imp.bpf_import_source() || imp.bpf_import_module())
    LOG(ERROR, imp.loc, err_) << "Possible source-based BPF import, not yet supported";
  auto path = imp.bpf_import_object();
  if (!path)
    LOG(ERROR, imp.loc, err_) << "Missing BPF target import, looking for file named `<import>.bpf.o`";

  // Open up the file to resolve all the maps and types.
  struct bpf_object *obj = bpf_object__open_file(path->c_str(), nullptr);
  struct btf *btf = bpf_object__btf(obj);

  struct bpf_map *m = nullptr;
  bpf_object__for_each_map(m, obj) {
    const char *name = bpf_map__name(m);
    maps_.insert(std::string(name));

    MapInfo::ExternalInfo external_info;
    external_info.map_type = bpf_map__type(m);
    external_info.max_entries = bpf_map__max_entries(m);

    auto &map_info = bpftrace_.resources.maps_info[std::string(name)];
    map_info.external = external_info;

    // Note that the types here are a bit broken; we can't actually import the
    // BTF into our own hierarchy, but we can resolve at least one level deep
    // via the `get_stype` method.
    const uint32_t key_id = bpf_map__btf_key_type_id(m);
    const uint32_t val_id = bpf_map__btf_value_type_id(m);
    map_info.key_type = bpftrace_.btf_->get_stype(BTF::BTFId{ .btf = btf, .id = key_id }, false);
    map_info.value_type = bpftrace_.btf_->get_stype(BTF::BTFId{ .btf = btf, .id = val_id }, false);
  }
}

void ResolveImports::visit(Map &map)
{
  // If the map identifier is within an import, then rewrite to point to this
  // map. Only the syntax parser cares about the '@' name, which is otherwise
  // treated as sugar that is rewritten with a known prefix. This solves two
  // problems at once: the semantic analyzer won't get confused, and we
  // preserve this exact symbol name.
  if (map.ident.size() > 1 && map.ident[0] == '@' && maps_.contains(map.ident.substr(1))) {
    map.ident = map.ident.substr(1);
  }
}

Pass CreateResolveImportsPass()
{
  return Pass("ResolveImports", [](PassContext &ctx) {
    ResolveImports analyser(ctx.ast_ctx, ctx.b);
    analyser.visit(ctx.ast_ctx.root);

    // Always succeed for now.
    return PassResult::Success();
  });
}

} // namespace bpftrace::ast
