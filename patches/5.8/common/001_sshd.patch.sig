untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqPxdggXvy2USZPzpUKVF3XEtBuJJpIt0wlGSonQ9TkMLXmji9WIlWgS2w13WvH/HiMDwssPj+lb00xg0xBzeVDgA=

OpenBSD 5.8 errata 1, Aug 30, 2015:

Inverted logic made "PermitRootLogin prohibit-password" unsafe.
Use "no", or apply the following patch.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 001_sshd.patch.sig \
        -m - | (cd /usr/src && patch -p0)

And then rebuild and install sshd:
    cd /usr/src/usr.bin/ssh
    make obj
    make depend
    make
    make install

Index: usr.bin/ssh/auth.c
===================================================================
RCS file: /cvs/src/usr.bin/ssh/auth.c,v
retrieving revision 1.112
diff -u -p -r1.112 auth.c
--- usr.bin/ssh/auth.c	6 Aug 2015 14:53:21 -0000	1.112
+++ usr.bin/ssh/auth.c	26 Aug 2015 15:10:30 -0000
@@ -263,7 +263,7 @@ auth_root_allowed(const char *method)
 	case PERMIT_NO_PASSWD:
 		if (strcmp(method, "publickey") == 0 ||
 		    strcmp(method, "hostbased") == 0 ||
-		    strcmp(method, "gssapi-with-mic"))
+		    strcmp(method, "gssapi-with-mic") == 0)
 			return 1;
 		break;
 	case PERMIT_FORCED_ONLY:
