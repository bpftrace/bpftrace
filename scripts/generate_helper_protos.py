#!/usr/bin/env python3
"""
Generate src/btf/helper_protos_table.cpp, the prototypes of all BPF helpers.

Kernel BTF can't supply helper prototypes, as `BPF_CALL_x` erases every helper
to `u64 (u64, u64, u64, u64, u64)`. Instead, this compiles a translation unit
that declares a struct member typed by each helper declaration in libbpf's
`bpf_helper_defs.h`, and converts the resulting BTF into a table.

The set of BPF helpers is frozen (new functionality is added as kfuncs), so
this only needs to be re-run if the libbpf submodule changes a declaration.

Requires `clang` and `bpftool` (both are available in the nix dev shell):

    nix develop --command ./scripts/generate_helper_protos.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBBPF_SRC = os.path.join(ROOT, "libbpf", "src")
OUTPUT = os.path.join(ROOT, "src", "btf", "helper_protos_table.cpp")
STRUCT_NAME = "__bpftrace_helpers"


def helper_names():
    with open(os.path.join(LIBBPF_SRC, "bpf_helper_defs.h")) as f:
        return re.findall(r"\(\* const (bpf_\w+)\)\(", f.read())


def build_btf(names):
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "helpers.c")
        obj = os.path.join(tmp, "helpers.o")
        with open(src, "w") as f:
            f.write("#define __KERNEL__\n")
            f.write("#include <linux/types.h>\n")
            f.write('#include "bpf_helpers.h"\n')
            f.write(f"struct {STRUCT_NAME} {{\n")
            for name in names:
                f.write(f"  __typeof__({name}) {name};\n")
            f.write(f"}} {STRUCT_NAME};\n")
        subprocess.run(
            [
                "clang",
                "-target",
                "bpf",
                "-g",
                "-c",
                "-I",
                os.path.join(ROOT, "src", "stdlib", "include"),
                "-I",
                LIBBPF_SRC,
                src,
                "-o",
                obj,
            ],
            check=True,
        )
        out = subprocess.run(
            ["bpftool", "-j", "btf", "dump", "file", obj],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    return {t["id"]: t for t in json.loads(out)["types"]}


class Table:
    """Flattens BTF into a table where every type follows the types it uses.

    Index 0 is always `void`, matching BTF, so the first entry is index 1.
    """

    def __init__(self, btf):
        self.btf = btf
        self.index = {0: 0}
        self.entries = []

    def add(self, type_id):
        if type_id in self.index:
            return self.index[type_id]
        t = self.btf[type_id]
        kind = t["kind"]
        if kind == "INT":
            entry = (
                f'.kind = HelperType::Kind::Integer, .name = "{t["name"]}", '
                f'.size = {t["size"]}, .encoding = {int_encoding(t)}'
            )
        elif kind == "FWD":
            if t["fwd_kind"] != "struct":
                sys.exit(f"unsupported forward declaration: {t}")
            entry = (
                f'.kind = HelperType::Kind::ForwardStruct, .name = "{t["name"]}"'
            )
        elif kind == "TYPEDEF":
            ref = self.add(t["type_id"])
            entry = (
                f'.kind = HelperType::Kind::Typedef, .name = "{t["name"]}", '
                f".type = {ref}"
            )
        elif kind == "PTR":
            ref = self.add(t["type_id"])
            entry = f".kind = HelperType::Kind::Pointer, .type = {ref}"
        elif kind == "CONST":
            ref = self.add(t["type_id"])
            entry = f".kind = HelperType::Kind::Const, .type = {ref}"
        else:
            sys.exit(f"unsupported BTF kind: {t}")
        self.entries.append((entry, self.c_type(type_id)))
        self.index[type_id] = len(self.entries)
        return self.index[type_id]

    def c_type(self, type_id):
        if type_id == 0:
            return "void"
        t = self.btf[type_id]
        kind = t["kind"]
        if kind in ("INT", "TYPEDEF"):
            return t["name"]
        if kind == "FWD":
            return f"struct {t['name']}"
        if kind == "PTR":
            return f"{self.c_type(t['type_id'])} *"
        if kind == "CONST":
            inner = self.btf.get(t["type_id"])
            if inner and inner["kind"] == "PTR":
                return f"{self.c_type(t['type_id'])} const"
            return f"const {self.c_type(t['type_id'])}"
        sys.exit(f"unsupported BTF kind: {t}")


def int_encoding(t):
    encoding = t["encoding"]
    if encoding == "(none)":
        return "0"
    if encoding == "SIGNED":
        return "BTF_INT_SIGNED"
    if encoding == "BOOL":
        return "BTF_INT_BOOL"
    if encoding == "CHAR":
        return "BTF_INT_CHAR"
    sys.exit(f"unsupported integer encoding: {t}")


def strip(btf, type_id, kind):
    t = btf.get(type_id)
    if t is None or t["kind"] != kind:
        sys.exit(f"expected {kind} for type {type_id}, got {t}")
    return t["type_id"]


def helper_protos(btf):
    helpers = next(
        t
        for t in btf.values()
        if t["kind"] == "STRUCT" and t["name"] == STRUCT_NAME
    )
    for member in helpers["members"]:
        # Each member is a `T (* const)(...)`.
        type_id = member["type_id"]
        if btf[type_id]["kind"] == "CONST":
            type_id = btf[type_id]["type_id"]
        proto = btf[strip(btf, type_id, "PTR")]
        if proto["kind"] != "FUNC_PROTO":
            sys.exit(f"expected FUNC_PROTO for {member['name']}, got {proto}")
        yield member["name"], proto


def generate(btf):
    table = Table(btf)
    protos = []
    for name, proto in helper_protos(btf):
        ret = table.add(proto["ret_type_id"])
        args = [table.add(p["type_id"]) for p in proto["params"]]
        ret_c = table.c_type(proto["ret_type_id"])
        sep = "" if ret_c.endswith("*") else " "
        params_c = ", ".join(
            "..." if p["type_id"] == 0 else table.c_type(p["type_id"])
            for p in proto["params"]
        )
        protos.append((name, ret, args, f"{ret_c}{sep}{name}({params_c})"))

    out = []
    out.append("// Generated by scripts/generate_helper_protos.py. Do not edit.")
    out.append("//")
    out.append("// To regenerate after updating the libbpf submodule:")
    out.append("//   nix develop --command ./scripts/generate_helper_protos.py")
    out.append("")
    out.append('#include "btf/helper_protos.h"')
    out.append("")
    out.append("namespace bpftrace::btf {")
    out.append("")
    out.append("// Index 0 is `void`, so the first entry is index 1.")
    out.append("const std::vector<HelperType> helper_types = {")
    for i, (entry, c_type) in enumerate(table.entries, start=1):
        out.append(f"  // {i}: {c_type}")
        out.append(f"  {{ {entry} }},")
    out.append("};")
    out.append("")
    out.append("const std::vector<HelperProto> helper_protos = {")
    for name, ret, args, decl in protos:
        out.append(f"  // {decl}")
        out.append(
            f'  {{ .name = "{name}", .return_type = {ret}, '
            f".args = {{ {', '.join(str(a) for a in args)} }} }},"
        )
    out.append("};")
    out.append("")
    out.append("} // namespace bpftrace::btf")
    return "\n".join(out) + "\n"


def main():
    names = helper_names()
    if not names:
        sys.exit("no helpers found in bpf_helper_defs.h")
    btf = build_btf(names)
    with open(OUTPUT, "w") as f:
        f.write(generate(btf))
    subprocess.run(["clang-format", "-i", OUTPUT], check=True)


if __name__ == "__main__":
    main()
