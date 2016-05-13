untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP6rjUaBgKYiTVW4j3VNm8K+xHJWNBRj2AlI1BUgbXdjcBwflJh4I6D15KlJ71Be12bl81bhRbAb/UnmdCTqEFQg=

OpenBSD 5.8 errata 10, Jan 14, 2016:

Experimental roaming code in the ssh client could be tricked by a
hostile sshd server, potentially leaking key material.
CVE-2016-0777 and CVE-0216-0778.
Prevent this problem immediately by adding the line "UseRoaming no" to
/etc/ssh/ssh_config.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 010_ssh.patch.sig \
        -m - | (cd /usr/src && patch -p0)

And then rebuild and install sshd:
    cd /usr/src/usr.bin/ssh
    make obj
    make depend
    make
    make install

Index: usr.bin/ssh/readconf.c
===================================================================
RCS file: /cvs/src/usr.bin/ssh/readconf.c,v
retrieving revision 1.239
diff -u -p -r1.239 readconf.c
--- usr.bin/ssh/readconf.c	30 Jul 2015 00:01:34 -0000	1.239
+++ usr.bin/ssh/readconf.c	13 Jan 2016 23:17:23 -0000
@@ -1648,7 +1648,7 @@ initialize_options(Options * options)
 	options->tun_remote = -1;
 	options->local_command = NULL;
 	options->permit_local_command = -1;
-	options->use_roaming = -1;
+	options->use_roaming = 0;
 	options->visual_host_key = -1;
 	options->ip_qos_interactive = -1;
 	options->ip_qos_bulk = -1;
@@ -1819,8 +1819,7 @@ fill_default_options(Options * options)
 		options->tun_remote = SSH_TUNID_ANY;
 	if (options->permit_local_command == -1)
 		options->permit_local_command = 0;
-	if (options->use_roaming == -1)
-		options->use_roaming = 1;
+	options->use_roaming = 0;
 	if (options->visual_host_key == -1)
 		options->visual_host_key = 0;
 	if (options->ip_qos_interactive == -1)
Index: usr.bin/ssh/ssh.c
===================================================================
RCS file: /cvs/src/usr.bin/ssh/ssh.c,v
retrieving revision 1.420
diff -u -p -r1.420 ssh.c
--- usr.bin/ssh/ssh.c	30 Jul 2015 00:01:34 -0000	1.420
+++ usr.bin/ssh/ssh.c	13 Jan 2016 23:17:23 -0000
@@ -1882,9 +1882,6 @@ ssh_session2(void)
 			fork_postauth();
 	}
 
-	if (options.use_roaming)
-		request_roaming();
-
 	return client_loop(tty_flag, tty_flag ?
 	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
 }
