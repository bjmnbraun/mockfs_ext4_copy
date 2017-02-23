#!/bin/bash

set -beEu -o pipefail

SEARCH=$1
REPLACE=$2

make clean

function do_replace {
        for file in *
        do
                if [ $file == "rename.sh" ]
                then
                        continue
                fi

                sed -i -e "s/$SEARCH/$REPLACE/g" $file

                nfilename=${file//$SEARCH/$REPLACE}
                if [ $nfilename != $file ]
                then
                        mv $file $nfilename
                fi
        done
}

do_replace

SEARCH=$(echo $SEARCH | awk '{print toupper($0)}')
REPLACE=$(echo $REPLACE | awk '{print toupper($0)}')

do_replace
