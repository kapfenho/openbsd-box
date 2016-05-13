#!/bin/sh

set -o errexit

BSDVERSION=OPENBSD_5_9

time {
  cd /usr
  cvs -d$CVSROOT checkout -r$BSDVERSION -P src xenocara 
}
