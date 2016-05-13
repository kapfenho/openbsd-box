#!/bin/ksh

set -o errexit

echo "==> COMP: compile kernel"

time {
  cd /usr/src/sys/arch/$(machine -a)/conf
  config GENERIC.MP
  cd ../compile/GENERIC.MP
  make clean && make depend && make
  
  if [ "X${NOINST}" == "X" ] ; then
    make install
  else
    echo "Installation skipped"
  fi
}
