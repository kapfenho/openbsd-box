untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP5uu0TCTqeMrb5rpcZH97X9zKJC60egq0vAK3Y7+bV1NNi12hPAuv1rDX2qzuLxFbiE27WKZNwgTiCuuH+e1Tgg=

OpenBSD 5.8 errata 2, Aug 30, 2015:

LibreSSL 2.2.2 incorrectly handles ClientHello messages that do not
include TLS extensions, resulting in such handshakes being aborted.
This patch corrects the handling of such messages.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 002_sslhello.patch.sig \
        -m - | (cd /usr/src && patch -p0)

And then rebuild and install libssl:
    cd /usr/src/lib/libssl
    make obj
    make depend
    make
    make install

Index: lib/libssl/src/ssl/t1_lib.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/ssl/t1_lib.c,v
retrieving revision 1.82
diff -u -p -u -r1.82 t1_lib.c
--- lib/libssl/src/ssl/t1_lib.c	24 Jul 2015 07:57:48 -0000	1.82
+++ lib/libssl/src/ssl/t1_lib.c	28 Aug 2015 15:09:00 -0000
@@ -2087,6 +2087,8 @@ tls1_process_ticket(SSL *s, const unsign
 		return -1;
 
 	/* Now at start of extensions */
+	if (CBS_len(&session_id) == 0)
+		return 0;
 	if (!CBS_get_u16_length_prefixed(&session_id, &extensions))
 		return -1;
 
