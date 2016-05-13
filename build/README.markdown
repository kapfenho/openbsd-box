OpenBSD Build Scripts
=====================

Procedures for Patching the _release_ version with current patches 
and building a release for installing.

Run in numerical order.


## Additional Settings

    # /etc/pkg.conf
    installpath = http://ftp.hostserver.de/pub/OpenBSD/$(uname -r)/packages/$(uname -m)/

    # ~/.cvsrc
    cvs -q -d anoncvs@mirror.osn.de:/cvs
    diff -uNp
    update -Pd -r OPENBSD_5_7
    checkout -P -r OPENBSD_5_7

    # ~/.profile
    export PKG_PATH=http://ftp.hostserver.de/pub/OpenBSD/$(uname -r)/packages/$(machine -a)/
    export CVSROOT=anoncvs@mirror.osn.de:/cvs


