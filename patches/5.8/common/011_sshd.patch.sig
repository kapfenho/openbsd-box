untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqPxvkj7H4iMhhnve0o44DWZj9XE2gzkY3/dhaJBTzeGa2hoG+rg5RabK/wkXFbzHBDfA7Igk/XMjW0s7tmIv+6ww=

OpenBSD 5.8 errata 11, Mar 10, 2016:

Lack of credential sanitization allows injection of commands to xauth(1).
More information: http://www.openssh.com/txt/x11fwd.adv

Prevent this problem immediately by not using the "X11Forwarding" feature
(which is disabled by default).

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 011_sshd.patch.sig \
        -m - | (cd /usr/src && patch -p0)

And then rebuild and install sshd:
    cd /usr/src/usr.bin/ssh
    make obj
    make depend
    make
    make install

Index: usr.bin/ssh/session.c
===================================================================
RCS file: /cvs/src/usr.bin/ssh/session.c,v
retrieving revision 1.278
diff -u -p -u -r1.278 session.c
--- usr.bin/ssh/session.c	24 Apr 2015 01:36:00 -0000	1.278
+++ usr.bin/ssh/session.c	9 Mar 2016 17:02:57 -0000
@@ -40,6 +40,7 @@
 #include <sys/socket.h>
 #include <sys/queue.h>
 
+#include <ctype.h>
 #include <errno.h>
 #include <fcntl.h>
 #include <grp.h>
@@ -255,6 +256,22 @@ do_authenticated(Authctxt *authctxt)
 	do_cleanup(authctxt);
 }
 
+/* Check untrusted xauth strings for metacharacters */
+static int
+xauth_valid_string(const char *s)
+{
+	size_t i;
+
+	for (i = 0; s[i] != '\0'; i++) {
+		if (!isalnum((u_char)s[i]) &&
+		    s[i] != '.' && s[i] != ':' && s[i] != '/' &&
+		    s[i] != '-' && s[i] != '_' && s[i] != '[' &&
+		    s[i] != ']')
+		return 0;
+	}
+	return 1;
+}
+
 /*
  * Prepares for an interactive session.  This is called after the user has
  * been successfully authenticated.  During this message exchange, pseudo
@@ -328,7 +345,13 @@ do_authenticated1(Authctxt *authctxt)
 				s->screen = 0;
 			}
 			packet_check_eom();
-			success = session_setup_x11fwd(s);
+			if (xauth_valid_string(s->auth_proto) &&
+			    xauth_valid_string(s->auth_data))
+				success = session_setup_x11fwd(s);
+			else {
+				success = 0;
+				error("Invalid X11 forwarding data");
+			}
 			if (!success) {
 				free(s->auth_proto);
 				free(s->auth_data);
@@ -1800,7 +1823,13 @@ session_x11_req(Session *s)
 	s->screen = packet_get_int();
 	packet_check_eom();
 
-	success = session_setup_x11fwd(s);
+	if (xauth_valid_string(s->auth_proto) &&
+	    xauth_valid_string(s->auth_data))
+		success = session_setup_x11fwd(s);
+	else {
+		success = 0;
+		error("Invalid X11 forwarding data");
+	}
 	if (!success) {
 		free(s->auth_proto);
 		free(s->auth_data);
