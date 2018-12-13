#/usr/bin/env bash

# copy auto.sh and find.py to the bpftrace's executable folder and run 'source auto.sh' to activate

_words_complete()
{
    local first second opts
    COMPREPLY=()
    first="${COMP_WORDS[COMP_CWORD]}"
    second="${COMP_WORDS[COMP_CWORD-1]}"

    COMPREPLY=( $(sudo python find.py ${first}) )
    return 0
}
complete -o nospace -o noquote -F _words_complete bpftrace
