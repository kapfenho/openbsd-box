#!/bin/sh -x

set -o errexit

time {
  cd /usr/xenocara
  rm -Rf /usr/xobj/*
  make bootstrap
  make obj
  make build
}
  cd /usr/src
  make build                        # build and install
}
