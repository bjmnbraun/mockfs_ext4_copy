#!/bin/bash

set -beEu -o pipefail

#Superuser must have access to these directories before running,
#otherwise you will get a permisison denied on make install

MAIN_ARGS=

#Not necessary but convenient when editing test code to fail here
make

pushd ../kern > /dev/null
./mount-me.sh
popd > /dev/null

#Kernel headers may have changed
make

set -v
./bin/src/main /mnt/mockfs/test $MAIN_ARGS
