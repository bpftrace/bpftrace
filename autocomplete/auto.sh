#/usr/bin/env bash

# copy auto.sh and find.py to the bpftrace's executable folder and run 'source auto.sh' to activate

_words_complete()
{
    local first second third fourth fifth opts
    COMPREPLY=()
    first="${COMP_WORDS[COMP_CWORD]}"
    second="${COMP_WORDS[COMP_CWORD-1]}"
    third="${COMP_WORDS[COMP_CWORD-2]}"
    fourth="${COMP_WORDS[COMP_CWORD-3]}"
    fifth="${COMP_WORDS[COMP_CWORD-4]}"

    # echo "$fifth$fourth$third$second$first"

    if [[ ${fourth} == \: ]] ; then
        COMPREPLY=( $(python find.py $fifth$fourth$third$second$first) )
        return 0
    elif [[ ${second} == \: ]] ; then
        COMPREPLY=( $(python find.py $third$second$first) )
        return 0
    else
        COMPREPLY=( $(python find.py ${first}) )
        return 0
    fi
    COMPREPLY=( $(python find.py ${first}) )
}
complete -o nospace -F _words_complete bpftrace
