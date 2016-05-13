#!/bin/sh -x

# thankfully copied from Calomel.org -- Making a bootable OpenBSD CD
#   calomel_make_boot_cd.sh

set -o errexit

   dest=/tmp/dist
 relsrc=/home/buildspace/release
   arch=$(uname -m)
version=$(uname -r)

echo
echo "Building the environment"

rm -Rf ${dist}
mkdir -p ${dist}
cd ${dist}

# wget --passive-ftp --reject "*iso" ftp://ftp.openbsd.org/pub/OpenBSD/$version/$arch/* 
cp -Rp ${relsrc}/* ${dist}/

mkisofs -r -no-emul-boot -b ${version}/${arch}/cdbr -c boot.catalog \
  -o openbsd-${version}-${arch}.iso ${dist}

# burn cd
# nice -18 cdrecord -eject -v speed=32 dev=/dev/rcd0c:0,0,0 -data -pad /tmp/OpenBSD/OpenBSD.iso 
