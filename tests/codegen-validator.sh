#!/bin/bash

## Don't add to this
IGNORE="(_LLVM|printf|(logical_and_or_different_type|struct_char_1|struct_integer_ptr_1|struct_integers_1|struct_long_1|struct_nested_struct_anon_1|struct_nested_struct_named_1|struct_nested_struct_ptr_named_1|struct_save_nested|struct_short_1|struct_string_array_1).ll)"
EXIT=0

LLVM=$(command -v llvm-as-7)
if [[ -z "$LLVM" ]]; then
  echo "llvm-as-7 not found"
  exit 1
fi

if [[ -z "$1" ]]; then
  echo "Usage: $0 <source dir>"
  exit 1
fi

for file in "${1}"/tests/codegen/llvm/*.ll; do
  if echo "$file" | grep -qE "$IGNORE"; then
    echo -e "[  SKIP  ]\t$file"
  else
    $LLVM -o /dev/null "${file}"
    if [[ $? -eq 0 ]]; then
      echo -e "[   OK   ]\t$file"
    else
      echo -e "[ FAILED ]\t$file"
      EXIT=1
    fi
  fi
done

exit $EXIT
