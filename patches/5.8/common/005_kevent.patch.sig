untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP/QDWTnuNrhNzyjv8srLjB2niZVK046gpTMgQR+CNerZVDnZ/pUbzDxNSwTKZA3uTygQ/oDCoQEGQ0eg6h8MHQM=

OpenBSD 5.8 errata 5, Oct 14, 2015:

A problem with timer kevents could result in a kernel hang (local denial
of service).

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 005_kevent.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install


Index: sys/kern/kern_event.c
===================================================================
RCS file: /cvs/src/sys/kern/kern_event.c,v
retrieving revision 1.61
retrieving revision 1.61.6.1
diff -u -p -r1.61 -r1.61.6.1
--- sys/kern/kern_event.c	19 Dec 2014 05:59:21 -0000	1.61
+++ sys/kern/kern_event.c	14 Oct 2015 18:10:27 -0000	1.61.6.1
@@ -1,4 +1,4 @@
-/*	$OpenBSD: kern_event.c,v 1.61 2014/12/19 05:59:21 tedu Exp $	*/
+/*	$OpenBSD: kern_event.c,v 1.61.6.1 2015/10/14 18:10:27 sthen Exp $	*/
 
 /*-
  * Copyright (c) 1999,2000,2001 Jonathan Lemon <jlemon@FreeBSD.org>
@@ -323,22 +323,28 @@ filt_proc(struct knote *kn, long hint)
 	return (kn->kn_fflags != 0);
 }
 
+static void
+filt_timer_timeout_add(struct knote *kn)
+{
+	struct timeval tv;
+	int tticks;
+
+	tv.tv_sec = kn->kn_sdata / 1000;
+	tv.tv_usec = (kn->kn_sdata % 1000) * 1000;
+	tticks = tvtohz(&tv);
+	timeout_add(kn->kn_hook, tticks ? tticks : 1);
+}
+
 void
 filt_timerexpire(void *knx)
 {
 	struct knote *kn = knx;
-	struct timeval tv;
-	int tticks;
 
 	kn->kn_data++;
 	KNOTE_ACTIVATE(kn);
 
-	if ((kn->kn_flags & EV_ONESHOT) == 0) {
-		tv.tv_sec = kn->kn_sdata / 1000;
-		tv.tv_usec = (kn->kn_sdata % 1000) * 1000;
-		tticks = tvtohz(&tv);
-		timeout_add((struct timeout *)kn->kn_hook, tticks);
-	}
+	if ((kn->kn_flags & EV_ONESHOT) == 0)
+		filt_timer_timeout_add(kn);
 }
 
 
@@ -349,22 +355,16 @@ int
 filt_timerattach(struct knote *kn)
 {
 	struct timeout *to;
-	struct timeval tv;
-	int tticks;
 
 	if (kq_ntimeouts > kq_timeoutmax)
 		return (ENOMEM);
 	kq_ntimeouts++;
 
-	tv.tv_sec = kn->kn_sdata / 1000;
-	tv.tv_usec = (kn->kn_sdata % 1000) * 1000;
-	tticks = tvtohz(&tv);
-
 	kn->kn_flags |= EV_CLEAR;	/* automatically set */
 	to = malloc(sizeof(*to), M_KEVENT, M_WAITOK);
 	timeout_set(to, filt_timerexpire, kn);
-	timeout_add(to, tticks);
 	kn->kn_hook = to;
+	filt_timer_timeout_add(kn);
 
 	return (0);
 }
