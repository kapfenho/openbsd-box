#!/bin/sh -x

if [ $# -gt 0 ]
then
  src=${1}
else
  src=$(pwd)
fi

if ! [ -e ${src}/bsd ]
then
  echo "ERROR: release not found!"
  exit 80
fi

# mp version
#
relm=bsd
rels=bsd.sp
if [ -e "${src}/bsd.mp" ] ; then
  relm=bsd.mp
  rels=bsd
fi

rm /obsd ; ln /bsd /obsd && cp "${src}/${relm}" /nbsd && mv /nbsd /bsd
cp "${src}/bsd.rd" /
cp "${src}/${rels}" /bsd.sp

echo
echo "Do you think there is a firmware upgrade?"
echo "Then see comments.."
# optional
# cd /
# tar xzpf /path/base37.tgz "*etc/firmware/*"

echo "reboot now!"

exit 0

