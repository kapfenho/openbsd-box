#!/bin/sh

### building xenocara

cd /usr/xenocara
rm -rf /usr/xobj/*
echo "COMP: X make bootstrap"
make bootstrap
echo "COMP: X obj"
make obj
echo "COMP: X make build"
make build
echo "COMP: done"

### create release
#    export RELEASEDIR=/home/releasedir
#    export DESTDIR=/home/destdir
#    cd /usr/src/etc && make release
#    cd /usr/src/distrib/sets && sh checkflist
#
#    export DESTDIR=/home/xdestdir
#    cd /usr/xenocara
#    make release

