#!/bin/sh -x

set -o errexit

time {
  cd /usr/src
  rm -Rf /usr/obj/*                 # delete old objects
  make obj                          # make objects
  cd /usr/src/etc
  env DESTDIR=/ make distrib-dirs   # make sure all dirs are created
  cd /usr/src
  make build                        # build and install
}
