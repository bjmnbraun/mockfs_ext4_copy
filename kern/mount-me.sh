#!/bin/bash

#For debugging:
#set -v

set -beEu -o pipefail

ISMOUNTED=$( ( mount | grep "/mnt/mockfs" || true ) | wc -l)

sudo mkdir -p /mnt/mockfs

if [[ $ISMOUNTED != 0 ]]; then
echo "Unmounting mockfs..."
sudo umount /mnt/mockfs
#Seems that unmounting is slightly asynchronous...
fi

ISMOUNTED=$( ( mount | grep "/mnt/mockfs" || true ) | wc -l)
if [[ $ISMOUNTED != 0 ]]; then
echo "Couldn't unmount mockfs!"
exit 1
fi

ISLOADED=$( ( lsmod | grep "mockfs" || true ) | wc -l)

if [[ $ISLOADED != 0 ]]; then
echo "Unloading mockfs..."
sudo rmmod mockfs
#Seems that unloading is slightly asynchronous...
fi

#Try again
ISLOADED=$( ( lsmod | grep "mockfs" || true ) | wc -l)
if [[ $ISLOADED != 0 ]]; then
echo "Couldn't unload mockfs!"
exit 1
fi

make
# > /dev/null
sudo make install > /dev/null

echo "Mounting example filesystem (/mnt/mockfs)..."
sudo mkdir -p /mnt/mockfs
sudo mount -t mockfs /dev/nvme0n1p7 /mnt/mockfs
sudo chmod ugo+rw /mnt/mockfs
