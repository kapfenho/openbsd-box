#!/bin/sh

#BSDVERSION=OPENBSD_5_6
#export BSDVERSION

time {
  for i in /usr/src /usr/xenocara /usr/ports
  do
    cd ${i}
    echo "*** Updating ${i}"
    echo
    #cvs -d$CVSROOT up -r$BSDVERSION -Pd
    cvs update
  done
}

exit 0

