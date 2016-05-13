untrusted comment: signature from openbsd 5.9 base secret key
RWQJVNompF3pwVtWwNXXMn3VxzjBZ9adembf8vxexHwdAfyHKWLH5+fJs+1JcG24ZSFNPVBR54nbUlvUGwF29j5Z26YlwcGKcQU=

OpenBSD 5.9 errata 2, Mar 16, 2016:

Insufficient checks in IPv6 socket binding and UDP IPv6 option
processing allow a local user to send UDP packets with a source
(IPv6 address + port) already reserved by another user.

Apply by doing:
    signify -Vep /etc/signify/openbsd-59-base.pub -x 002_in6bind.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install

Index: sys/netinet6/in6_pcb.c
===================================================================
RCS file: /cvs/src/sys/netinet6/in6_pcb.c,v
diff -u -p -u -r1.84 -r1.85
--- sys/netinet6/in6_pcb.c	18 Dec 2015 22:25:16 -0000	1.84
+++ sys/netinet6/in6_pcb.c	12 Mar 2016 09:25:37 -0000	1.85
@@ -264,7 +264,16 @@ in6_pcbbind(struct inpcb *inp, struct mb
 			if (ntohs(lport) < IPPORT_RESERVED &&
 			    (error = suser(p, 0)))
 				return error;
-
+			if (so->so_euid) {
+				t = in_pcblookup(head,
+				    (struct in_addr *)&zeroin6_addr, 0,
+				    (struct in_addr *)&sin6->sin6_addr, lport,
+				    INPLOOKUP_WILDCARD | INPLOOKUP_IPV6,
+				    inp->inp_rtableid);
+				if (t &&
+				    (so->so_euid != t->inp_socket->so_euid))
+					return EADDRINUSE;
+			}
 			t = in_pcblookup(head,
 			    (struct in_addr *)&zeroin6_addr, 0,
 			    (struct in_addr *)&sin6->sin6_addr, lport,
Index: sys/netinet6/udp6_output.c
===================================================================
RCS file: /cvs/src/sys/netinet6/udp6_output.c,v
diff -u -p -u -r1.41 -r1.42
--- sys/netinet6/udp6_output.c	2 Dec 2015 22:13:44 -0000	1.41
+++ sys/netinet6/udp6_output.c	12 Mar 2016 09:25:38 -0000	1.42
@@ -166,6 +166,23 @@ udp6_output(struct inpcb *in6p, struct m
 			splx(s);
 			if (error)
 				goto release;
+		}
+
+		if (!IN6_ARE_ADDR_EQUAL(&in6p->inp_laddr6, laddr) &&
+		    (in6p->inp_socket->so_euid != 0)) {
+			struct inpcb *t;
+
+			t = in_pcblookup(in6p->inp_table,
+			    (struct in_addr *)&zeroin6_addr, 0,
+			    (struct in_addr *)laddr, in6p->inp_lport,
+			    (INPLOOKUP_WILDCARD | INPLOOKUP_IPV6),
+			    in6p->inp_rtableid);
+			if (t &&
+			    (t->inp_socket->so_euid !=
+			    in6p->inp_socket->so_euid)) {
+				error = EADDRINUSE;
+				goto release;
+			}
 		}
 	} else {
 		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->inp_faddr6)) {
