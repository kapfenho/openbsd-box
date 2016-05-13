#!/bin/ksh -x

rel=$(uname -r | tr -d '.')

if [ $# -gt 0 ]
then
  src=${1}
else
  src=$(pwd)
fi

if ! [ -e "${src}/base${rel}.tgz" ]
then
  echo "No release found!"
  exit 80
fi

cd /

# additional files for xwindows:
#   misc xbase xfont xserv xshare

for a in base comp game man
do
  f="${src}/${a}${rel}.tgz"
  if [ -e "${f}" ]
  then
    tar xzpf "${f}"
  else
    echo "Release file ${f} missing!"
    exit 80
  fi
done

cd /dev
./MAKEDEV all
  
echo "Need to upgrade /etc...?"
echo 
# upgrade /etc

echo "Then reboot..."

