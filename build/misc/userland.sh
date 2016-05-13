#!/bin/ksh

rm -Rf /usr/obj/*
cd /usr/src

time {
  echo "==> COMP: make obj"
  make obj
  
  cd /usr/src/etc && env DESTDIR=/ make distrib-dirs
  cd /usr/src
  echo "==> COMP: make build"
  make build
}

