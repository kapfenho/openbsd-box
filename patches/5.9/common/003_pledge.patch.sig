untrusted comment: signature from openbsd 5.9 base secret key
RWQJVNompF3pwU2GYNuo/9YszQKuXAN1TcqcOcVjSFUOq2IDy/VJV8jOQzotNYEW6ZD+j5+eSOvXMCiXd9GdiDOJRBPMYWARMg0=

OpenBSD 5.9 errata 003, Mar 16, 2016:

Incorrect path processing in pledge_namei() could result in unexpected
program termination of pledge(2)'d programs.

Apply by doing:
    signify -Vep /etc/signify/openbsd-59-base.pub -x 003_pledge.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install

Index: sys/kern/kern_pledge.c
===================================================================
RCS file: /cvs/src/sys/kern/kern_pledge.c,v
diff -u -p -r1.149 kern_pledge.c
--- sys/kern/kern_pledge.c	17 Feb 2016 21:52:06 -0000	1.149
+++ sys/kern/kern_pledge.c	13 Mar 2016 08:17:42 -0000
@@ -615,7 +615,7 @@ pledge_fail(struct proc *p, int error, u
 int
 pledge_namei(struct proc *p, struct nameidata *ni, char *origpath)
 {
-	char path[PATH_MAX];
+	char path[PATH_MAX + 1];
 	int error;
 
 	if ((p->p_p->ps_flags & PS_PLEDGE) == 0 ||
