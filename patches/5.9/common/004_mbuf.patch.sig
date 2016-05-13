untrusted comment: signature from openbsd 5.9 base secret key
RWQJVNompF3pwQLgacD5PJSK7bVm558XCGoA41bS61EIAmrDw42bFgDX+ZmFpuxMlrgZKhfw3X/05TEALD/s7jzt358nnTfgYgs=

OpenBSD 5.9 errata 004, Apr 30, 2016:

A problem in m_dup_pkt() can result in kernel crashes with carp(4).

Apply by doing:
    signify -Vep /etc/signify/openbsd-59-base.pub -x 004_mbuf.patch.sig \
        -m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install

Index: sys/kern/uipc_mbuf.c
===================================================================
RCS file: /cvs/src/sys/kern/uipc_mbuf.c,v
diff -u -p -r1.219 -r1.219.2.1
--- sys/kern/uipc_mbuf.c	23 Feb 2016 01:39:14 -0000	1.219
+++ sys/kern/uipc_mbuf.c	28 Apr 2016 22:31:55 -0000	1.219.2.1
@@ -1223,7 +1223,7 @@ m_dup_pkt(struct mbuf *m0, unsigned int 
 	if (len > MAXMCLBYTES) /* XXX */
 		return (NULL);
 
-	m = m_get(m0->m_type, wait);
+	m = m_get(wait, m0->m_type);
 	if (m == NULL)
 		return (NULL);
 
@@ -1231,7 +1231,7 @@ m_dup_pkt(struct mbuf *m0, unsigned int 
 		goto fail;
 
 	if (len > MHLEN) {
-		MCLGETI(m, len, NULL, wait);
+		MCLGETI(m, wait, NULL, len);
 		if (!ISSET(m->m_flags, M_EXT))
 			goto fail;
 	}
