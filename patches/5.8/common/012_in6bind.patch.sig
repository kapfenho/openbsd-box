untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP+heRHmcntD+XgMDwg4ZTMgFWiaY4sSf6GsJ5KxAyqgnG+jkYv9Qj78x5BkolA+9H9MhObuzhsZEJf9RcsQr0QE=

OpenBSD 5.8 errata 12, Mar 16, 2016:

Insufficient checks in IPv6 socket binding and UDP IPv6 option
processing allow a local user to send UDP packets with a source
(IPv6 address + port) already reserved by another user.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 012_in6bind.patch.sig \
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
diff -u -p -r1.69 in6_pcb.c
--- sys/netinet6/in6_pcb.c	19 Jul 2015 02:35:35 -0000	1.69
+++ sys/netinet6/in6_pcb.c	14 Mar 2016 15:10:11 -0000
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
diff -u -p -r1.35 udp6_output.c
--- sys/netinet6/udp6_output.c	8 Jun 2015 22:19:28 -0000	1.35
+++ sys/netinet6/udp6_output.c	14 Mar 2016 15:10:11 -0000
@@ -165,6 +165,23 @@ udp6_output(struct inpcb *in6p, struct m
 		if (in6p->inp_lport == 0 &&
 		    (error = in6_pcbsetport(laddr, in6p, p)) != 0)
 			goto release;
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
+		}
 	} else {
 		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->inp_faddr6)) {
 			error = ENOTCONN;
