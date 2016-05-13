untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP9EKjEQtautE+YbD9ew7oEKoqCTV1wBTfVC3J07UO8jkNXzlU9KL3SGDh5P6N7RjETwFO1jBs9TSxrBBmOfpkws=

OpenBSD 5.8 errata 3, Sep 28, 2015:

An incorrect operation in uvm could result in system panics.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 003_uvm.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install


Index: sys/uvm/uvm_km.c
===================================================================
RCS file: /cvs/src/sys/uvm/uvm_km.c,v
retrieving revision 1.126
diff -u -p -r1.126 uvm_km.c
--- sys/uvm/uvm_km.c	7 Feb 2015 08:21:24 -0000	1.126
+++ sys/uvm/uvm_km.c	28 Sep 2015 18:07:40 -0000
@@ -259,7 +259,6 @@ uvm_km_pgremove(struct uvm_object *uobj,
 		slot = uao_dropswap(uobj, curoff >> PAGE_SHIFT);
 
 		if (pp != NULL) {
-			atomic_clearbits_int(&pp->pg_flags, PQ_AOBJ);
 			uvm_lock_pageq();
 			uvm_pagefree(pp);
 			uvm_unlock_pageq();
