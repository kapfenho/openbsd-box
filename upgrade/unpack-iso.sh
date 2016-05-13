#!/bin/sh -x

if [ $# -lt 1 ] || ! [ -f $1 ] 
then
    echo "ERROR: iso file as parameter required!"
    exit 80
fi

vnconfig vnd0 /home/horst/OpenBSD.iso
mount -t cd9660 /dev/vnd0c /mnt
rm -Rf /tmp/rel
mkdir -p /tmp/rel
cp -p /mnt/`uname -r`/`uname -m`/* /tmp/rel/
umount /mnt

echo 
echo "Release mounted on /mnt, copied to /tmp/rel and umounted"
echo

