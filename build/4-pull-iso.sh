#!/bin/sh -x

dest=/mnt/install/osimages/openbsd/release
rdir=$(date "+%y%m%d")

if [ -e ${dest} ] ; then
  [[ -w ${dest}/${rdir} ]] || mkdir -p ${dest}/${rdir}
  scp openbsd:/tmp/OpenBSD/OpenBSD.iso ${dest}/${rdir}/
  echo "Saved release in ${dest}/${rdir}/${file}"
else
  echo "ERROR: Destination dir not available"
  echo "Execute  scp openbsd:/tmp/OpenBSD/OpenBSD.iso ..."
  echo
fi

