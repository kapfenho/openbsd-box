#!/bin/sh

set -o errexit

export    DESTDIR=/home/buildspace/dest
export RELEASEDIR=/home/buildspace/release

rm -R $DESTDIR
mkdir -p $DESTDIR $RELEASEDIR

time {
  # create release
  cd /usr/src/etc && make release
  cd /usr/src/distrib/sets && sh checkflist
  # create xenocara release
  # cd /usr/xenocara && make release
  # add nice index
  cd $RELEASEDIR && /bin/ls -lT >index.txt
}
