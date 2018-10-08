# This script lists all the types in the kernel's tracepoint format files
# which appear with more than one size. This script's output should be
# compared to the code in TracepointFormatParser::adjust_integer_types()

import glob

field_types = {}

for format_file in glob.iglob("/sys/kernel/debug/tracing/events/*/*/format"):
    for line in open(format_file):
        if not line.startswith("\tfield:"):
            continue

        size_section = line.split(";")[2].split(":")
        if size_section[0] != "\tsize":
            continue
        size_val = size_section[1]

        field_section = line.split(";")[0].split(":")
        if field_section[0] != "\tfield":
            continue
        field_val = field_section[1]
        if "[" in field_val or "*" in field_val:
            continue

        field_type = " ".join(field_val.split()[:-1])

        if field_type not in field_types:
            field_types[field_type] = set()
        field_types[field_type].add(size_val)

for t in sorted(field_types):
    sizes = field_types[t]
    if len(sizes) > 1:
        sizes_str = ",".join(sorted(sizes))
        print(f"{t}: {sizes_str}")
