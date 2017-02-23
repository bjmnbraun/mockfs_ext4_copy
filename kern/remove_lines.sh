#!/bin/bash

set -beEu -o pipefail

SEARCH=$1

make clean

function do_remove {
        for file in *
        do
                if [[ $file == *".sh"* ]]
                then
                        continue
                fi

                sed -i "/$SEARCH/d" $file
        done
}

do_remove
