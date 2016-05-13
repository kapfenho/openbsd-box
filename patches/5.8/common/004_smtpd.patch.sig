untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP+CPtVwuDDKSC59Fqoljv/XGVAKE7gQSiY2ofLHDVnE49HhQekaTpjRZ5Yws1oAl7lilam6OB6PRJJuwPALsCQs=

OpenBSD 5.8 errata 4, Oct 1, 2015:

Fix multiple reliability and security issues in smtpd:
    * local and remote users could make smtpd crash or stop serving requests.
    * a buffer overflow in the unprivileged, non-chrooted smtpd (lookup)
      process could allow a local user to cause a crash or potentially
      execute arbitrary code.
    * a use-after-free in the unprivileged, non-chrooted smtpd (lookup)
      process could allow a remote attacker to cause a crash or potentially
      execute arbitrary code.
    * hardlink and symlink attacks allowed a local user to unset chflags or
      leak the first line of an arbitrary file.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 004_smtpd.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install smtpd:
    cd /usr/src/usr.sbin/smtpd
    make obj
    make depend
    make
    make install

Index: usr.sbin/smtpd/control.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/control.c,v
retrieving revision 1.104
diff -u -p -r1.104 control.c
--- usr.sbin/smtpd/control.c	11 Jun 2015 19:27:16 -0000	1.104
+++ usr.sbin/smtpd/control.c	1 Oct 2015 22:54:14 -0000
@@ -71,7 +71,7 @@ static void control_broadcast_verbose(in
 static struct stat_backend *stat_backend = NULL;
 extern const char *backend_stat;
 
-static uint32_t			connid = 0;
+static uint64_t			connid = 0;
 static struct tree		ctl_conns;
 static struct tree		ctl_count;
 static struct stat_digest	digest;
@@ -365,10 +365,14 @@ control_accept(int listenfd, short event
 	}
 	(*count)++;
 
+	do {
+		++connid;
+	} while (tree_get(&ctl_conns, connid));
+
 	c = xcalloc(1, sizeof(*c), "control_accept");
 	c->euid = euid;
 	c->egid = egid;
-	c->id = ++connid;
+	c->id = connid;
 	c->mproc.proc = PROC_CLIENT;
 	c->mproc.handler = control_dispatch_ext;
 	c->mproc.data = c;
Index: usr.sbin/smtpd/lka.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/lka.c,v
retrieving revision 1.175
diff -u -p -r1.175 lka.c
--- usr.sbin/smtpd/lka.c	20 Jan 2015 17:37:54 -0000	1.175
+++ usr.sbin/smtpd/lka.c	1 Oct 2015 22:54:14 -0000
@@ -185,6 +185,7 @@ lka_imsg(struct mproc *p, struct imsg *i
 			free(req_ca_vrfy_smtp->chain_cert_len);
 			free(req_ca_vrfy_smtp->cert);
 			free(req_ca_vrfy_smtp);
+			req_ca_vrfy_smtp = NULL;
 			return;
 
 		case IMSG_SMTP_AUTHENTICATE:
@@ -306,6 +307,7 @@ lka_imsg(struct mproc *p, struct imsg *i
 			free(req_ca_vrfy_mta->chain_cert_len);
 			free(req_ca_vrfy_mta->cert);
 			free(req_ca_vrfy_mta);
+			req_ca_vrfy_mta = NULL;
 			return;
 
 		case IMSG_MTA_LOOKUP_CREDENTIALS:
Index: usr.sbin/smtpd/lka_session.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/lka_session.c,v
retrieving revision 1.69
diff -u -p -r1.69 lka_session.c
--- usr.sbin/smtpd/lka_session.c	20 Jan 2015 17:37:54 -0000	1.69
+++ usr.sbin/smtpd/lka_session.c	1 Oct 2015 22:54:14 -0000
@@ -800,6 +800,10 @@ lka_expand_format(char *buf, size_t len,
 		if (exptoklen == 0)
 			return 0;
 
+		/* writing expanded token at ptmp will overflow tmpbuf */
+		if (sizeof (tmpbuf) - (ptmp - tmpbuf) <= exptoklen)
+			return 0;
+
 		memcpy(ptmp, exptok, exptoklen);
 		pbuf   = ebuf + 1;
 		ptmp  += exptoklen;
Index: usr.sbin/smtpd/mproc.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/mproc.c,v
retrieving revision 1.12
diff -u -p -r1.12 mproc.c
--- usr.sbin/smtpd/mproc.c	11 Jun 2015 19:27:16 -0000	1.12
+++ usr.sbin/smtpd/mproc.c	1 Oct 2015 22:54:14 -0000
@@ -42,6 +42,7 @@
 static void mproc_dispatch(int, short, void *);
 
 static ssize_t msgbuf_write2(struct msgbuf *);
+static ssize_t imsg_read_nofd(struct imsgbuf *);
 
 int
 mproc_fork(struct mproc *p, const char *path, char *argv[])
@@ -151,7 +152,12 @@ mproc_dispatch(int fd, short event, void
 
 	if (event & EV_READ) {
 
-		if ((n = imsg_read(&p->imsgbuf)) == -1) {
+		if (p->proc == PROC_CLIENT)
+			n = imsg_read_nofd(&p->imsgbuf);
+		else
+			n = imsg_read(&p->imsgbuf);
+
+		if (n == -1) {
 			log_warn("warn: %s -> %s: imsg_read",
 			    proc_name(smtpd_process),  p->name);
 			fatal("exiting");
@@ -281,6 +287,29 @@ again:
 	msgbuf_drain(msgbuf, n);
 
 	return (n);
+}
+
+/* This should go into libutil */
+static ssize_t
+imsg_read_nofd(struct imsgbuf *ibuf)
+{
+	ssize_t	 n;
+	char	*buf;
+	size_t	 len;
+
+	buf = ibuf->r.buf + ibuf->r.wpos;
+	len = sizeof(ibuf->r.buf) - ibuf->r.wpos;
+
+    again:
+	if ((n = recv(ibuf->fd, buf, len, 0)) == -1) {
+		if (errno != EINTR && errno != EAGAIN)
+			goto fail;
+		goto again;
+	}
+
+        ibuf->r.wpos += n;
+fail:
+        return (n);
 }
 
 void
Index: usr.sbin/smtpd/mta_session.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/mta_session.c,v
retrieving revision 1.71
diff -u -p -r1.71 mta_session.c
--- usr.sbin/smtpd/mta_session.c	20 Jan 2015 17:37:54 -0000	1.71
+++ usr.sbin/smtpd/mta_session.c	1 Oct 2015 22:54:14 -0000
@@ -1520,12 +1520,28 @@ mta_start_tls(struct mta_session *s)
 static int
 mta_verify_certificate(struct mta_session *s)
 {
+#define MAX_CERTS	16
+#define MAX_CERT_LEN	(MAX_IMSGSIZE - (IMSG_HEADER_SIZE + sizeof(req_ca_vrfy)))
 	struct ca_vrfy_req_msg	req_ca_vrfy;
 	struct iovec		iov[2];
 	X509		       *x;
 	STACK_OF(X509)	       *xchain;
-	int			i;
 	const char	       *pkiname;
+	unsigned char	       *cert_der[MAX_CERTS];
+	int			cert_len[MAX_CERTS];
+	int			i, cert_count, res;
+
+	res = 0;
+	memset(cert_der, 0, sizeof(cert_der));
+	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
+
+	if (s->relay->pki_name)
+		pkiname = s->relay->pki_name;
+	else
+		pkiname = s->helo;
+	if (strlcpy(req_ca_vrfy.pkiname, pkiname, sizeof req_ca_vrfy.pkiname)
+	    >= sizeof req_ca_vrfy.pkiname)
+		return 0;
 
 	x = SSL_get_peer_certificate(s->io.ssl);
 	if (x == NULL)
@@ -1540,47 +1556,68 @@ mta_verify_certificate(struct mta_sessio
 	 *
 	 */
 
+	cert_len[0] = i2d_X509(x, &cert_der[0]);
+	X509_free(x);
+
+	if (cert_len[0] < 0) {
+		log_warnx("warn: failed to encode certificate");	
+		goto end;
+	}
+	log_debug("debug: certificate 0: len=%d", cert_len[0]);
+	if (cert_len[0] > (int)MAX_CERT_LEN) {
+		log_warnx("warn: certificate too long");	
+		goto end;
+	}
+
+	if (xchain) {
+		cert_count = sk_X509_num(xchain);
+		log_debug("debug: certificate chain len: %d", cert_count);
+		if (cert_count >= MAX_CERTS) {
+			log_warnx("warn: certificate chain too long");
+			goto end;
+		}
+	}
+	else
+		cert_count = 0;
+
+	for (i = 0; i < cert_count; ++i) {
+		x = sk_X509_value(xchain, i);
+		cert_len[i+1] = i2d_X509(x, &cert_der[i+1]);
+		if (cert_len[i+1] < 0) {
+			log_warnx("warn: failed to encode certificate");	
+			goto end;
+		}
+		log_debug("debug: certificate %i: len=%d", i+1, cert_len[i+1]);
+		if (cert_len[i+1] > (int)MAX_CERT_LEN) {
+			log_warnx("warn: certificate too long");	
+			goto end;
+		}
+	}
+
 	tree_xset(&wait_ssl_verify, s->id, s);
 	s->flags |= MTA_WAIT;
 
 	/* Send the client certificate */
-	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
-	if (s->relay->pki_name)
-		pkiname = s->relay->pki_name;
-	else
-		pkiname = s->helo;
-	if (strlcpy(req_ca_vrfy.pkiname, pkiname, sizeof req_ca_vrfy.pkiname)
-	    >= sizeof req_ca_vrfy.pkiname)
-		return 0;
-
 	req_ca_vrfy.reqid = s->id;
-	req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
-	if (xchain)
-		req_ca_vrfy.n_chain = sk_X509_num(xchain);
+	req_ca_vrfy.cert_len = cert_len[0];
+	req_ca_vrfy.n_chain = cert_count;
 	iov[0].iov_base = &req_ca_vrfy;
 	iov[0].iov_len = sizeof(req_ca_vrfy);
-	iov[1].iov_base = req_ca_vrfy.cert;
-	iov[1].iov_len = req_ca_vrfy.cert_len;
+	iov[1].iov_base = cert_der[0];
+	iov[1].iov_len = cert_len[0];
 	m_composev(p_lka, IMSG_MTA_SSL_VERIFY_CERT, 0, 0, -1,
 	    iov, nitems(iov));
-	free(req_ca_vrfy.cert);
-	X509_free(x);
 
-	if (xchain) {		
-		/* Send the chain, one cert at a time */
-		for (i = 0; i < sk_X509_num(xchain); ++i) {
-			memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
-			req_ca_vrfy.reqid = s->id;
-			x = sk_X509_value(xchain, i);
-			req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
-			iov[0].iov_base = &req_ca_vrfy;
-			iov[0].iov_len  = sizeof(req_ca_vrfy);
-			iov[1].iov_base = req_ca_vrfy.cert;
-			iov[1].iov_len  = req_ca_vrfy.cert_len;
-			m_composev(p_lka, IMSG_MTA_SSL_VERIFY_CHAIN, 0, 0, -1,
-			    iov, nitems(iov));
-			free(req_ca_vrfy.cert);
-		}
+	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
+	req_ca_vrfy.reqid = s->id;
+
+	/* Send the chain, one cert at a time */
+	for (i = 0; i < cert_count; ++i) {
+		req_ca_vrfy.cert_len = cert_len[i+1];
+		iov[1].iov_base = cert_der[i+1];
+		iov[1].iov_len  = cert_len[i+1];
+		m_composev(p_lka, IMSG_MTA_SSL_VERIFY_CHAIN, 0, 0, -1,
+		    iov, nitems(iov));
 	}
 
 	/* Tell lookup process that it can start verifying, we're done */
@@ -1589,7 +1626,13 @@ mta_verify_certificate(struct mta_sessio
 	m_compose(p_lka, IMSG_MTA_SSL_VERIFY, 0, 0, -1,
 	    &req_ca_vrfy, sizeof req_ca_vrfy);
 
-	return 1;
+	res = 1;
+
+    end:
+	for (i = 0; i < MAX_CERTS; ++i)
+		free(cert_der[i]);
+
+	return res;
 }
 
 static const char *
Index: usr.sbin/smtpd/smtp_session.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/smtp_session.c,v
retrieving revision 1.230
diff -u -p -r1.230 smtp_session.c
--- usr.sbin/smtpd/smtp_session.c	15 May 2015 07:34:45 -0000	1.230
+++ usr.sbin/smtpd/smtp_session.c	1 Oct 2015 22:54:14 -0000
@@ -146,6 +146,7 @@ struct smtp_session {
 	size_t			 rcptfail;
 	TAILQ_HEAD(, smtp_rcpt)	 rcpts;
 
+	size_t			 datain;
 	size_t			 datalen;
 	FILE			*ofile;
 	int			 hdrdone;
@@ -263,11 +264,6 @@ dataline_callback(const char *line, void
 
 	len = strlen(line) + 1;
 
-	if (s->datalen + len > env->sc_maxsize) {
-		s->msgflags |= MF_ERROR_SIZE;
-		return;
-	}
-
 	if (fprintf(s->ofile, "%s\n", line) != (int)len) {
 		s->msgflags |= MF_ERROR_IO;
 		return;
@@ -1821,6 +1817,13 @@ smtp_message_write(struct smtp_session *
 	if (*line == '\0')
 		s->hdrdone = 1;
 
+	/* account for newline */
+	s->datain += strlen(line) + 1;
+	if (s->datain > env->sc_maxsize) {
+		s->msgflags |= MF_ERROR_SIZE;
+		return;
+	}
+
 	/* check for loops */
 	if (!s->hdrdone) {
 		if (strncasecmp("Received: ", line, 10) == 0)
@@ -1903,6 +1906,7 @@ smtp_message_reset(struct smtp_session *
 	s->msgflags = 0;
 	s->destcount = 0;
 	s->rcptcount = 0;
+	s->datain = 0;
 	s->datalen = 0;
 	s->rcvcount = 0;
 	s->hdrdone = 0;
@@ -2062,12 +2066,28 @@ smtp_mailaddr(struct mailaddr *maddr, ch
 static int
 smtp_verify_certificate(struct smtp_session *s)
 {
+#define MAX_CERTS	16
+#define MAX_CERT_LEN	(MAX_IMSGSIZE - (IMSG_HEADER_SIZE + sizeof(req_ca_vrfy)))
 	struct ca_vrfy_req_msg	req_ca_vrfy;
 	struct iovec		iov[2];
 	X509		       *x;
 	STACK_OF(X509)	       *xchain;
-	int			i;
 	const char	       *pkiname;
+	unsigned char	       *cert_der[MAX_CERTS];
+	int			cert_len[MAX_CERTS];
+	int			i, cert_count, res;
+
+	res = 0;
+	memset(cert_der, 0, sizeof(cert_der));
+	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
+
+	if (s->listener->pki_name[0])
+		pkiname = s->listener->pki_name;
+	else
+		pkiname = s->smtpname;
+	if (strlcpy(req_ca_vrfy.pkiname, pkiname, sizeof req_ca_vrfy.pkiname)
+	    >= sizeof req_ca_vrfy.pkiname)
+		return 0;
 
 	x = SSL_get_peer_certificate(s->io.ssl);
 	if (x == NULL)
@@ -2082,47 +2102,67 @@ smtp_verify_certificate(struct smtp_sess
 	 *
 	 */
 
-	tree_xset(&wait_ssl_verify, s->id, s);
+	cert_len[0] = i2d_X509(x, &cert_der[0]);
+	X509_free(x);
 
-	/* Send the client certificate */
-	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
-	if (s->listener->pki_name[0])
-		pkiname = s->listener->pki_name;
+	if (cert_len[0] < 0) {
+		log_warnx("warn: failed to encode certificate");	
+		goto end;
+	}
+	log_debug("debug: certificate 0: len=%d", cert_len[0]);
+	if (cert_len[0] > (int)MAX_CERT_LEN) {
+		log_warnx("warn: certificate too long");	
+		goto end;
+	}
+
+	if (xchain) {
+		cert_count = sk_X509_num(xchain);
+		log_debug("debug: certificate chain len: %d", cert_count);
+		if (cert_count >= MAX_CERTS) {
+			log_warnx("warn: certificate chain too long");	
+			goto end;
+		}
+	}
 	else
-		pkiname = s->smtpname;
+		cert_count = 0;
 
-	if (strlcpy(req_ca_vrfy.pkiname, pkiname, sizeof req_ca_vrfy.pkiname)
-	    >= sizeof req_ca_vrfy.pkiname)
-		return 0;
+	for (i = 0; i < cert_count; ++i) {
+		x = sk_X509_value(xchain, i);
+		cert_len[i+1] = i2d_X509(x, &cert_der[i+1]);
+		if (cert_len[i+1] < 0) {
+			log_warnx("warn: failed to encode certificate");	
+			goto end;
+		}
+		log_debug("debug: certificate %i: len=%d", i+1, cert_len[i+1]);
+		if (cert_len[i+1] > (int)MAX_CERT_LEN) {
+			log_warnx("warn: certificate too long");	
+			goto end;
+		}
+	}
 
+	tree_xset(&wait_ssl_verify, s->id, s);
+
+	/* Send the client certificate */
 	req_ca_vrfy.reqid = s->id;
-	req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
-	if (xchain)
-		req_ca_vrfy.n_chain = sk_X509_num(xchain);
+	req_ca_vrfy.cert_len = cert_len[0];
+	req_ca_vrfy.n_chain = cert_count;
 	iov[0].iov_base = &req_ca_vrfy;
 	iov[0].iov_len = sizeof(req_ca_vrfy);
-	iov[1].iov_base = req_ca_vrfy.cert;
-	iov[1].iov_len = req_ca_vrfy.cert_len;
+	iov[1].iov_base = cert_der[0];
+	iov[1].iov_len = cert_len[0];
 	m_composev(p_lka, IMSG_SMTP_SSL_VERIFY_CERT, 0, 0, -1,
 	    iov, nitems(iov));
-	free(req_ca_vrfy.cert);
-	X509_free(x);
 
-	if (xchain) {		
-		/* Send the chain, one cert at a time */
-		for (i = 0; i < sk_X509_num(xchain); ++i) {
-			memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
-			req_ca_vrfy.reqid = s->id;
-			x = sk_X509_value(xchain, i);
-			req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
-			iov[0].iov_base = &req_ca_vrfy;
-			iov[0].iov_len  = sizeof(req_ca_vrfy);
-			iov[1].iov_base = req_ca_vrfy.cert;
-			iov[1].iov_len  = req_ca_vrfy.cert_len;
-			m_composev(p_lka, IMSG_SMTP_SSL_VERIFY_CHAIN, 0, 0, -1,
-			    iov, nitems(iov));
-			free(req_ca_vrfy.cert);
-		}
+	memset(&req_ca_vrfy, 0, sizeof req_ca_vrfy);
+	req_ca_vrfy.reqid = s->id;
+
+	/* Send the chain, one cert at a time */
+	for (i = 0; i < cert_count; ++i) {
+		req_ca_vrfy.cert_len = cert_len[i+1];
+		iov[1].iov_base = cert_der[i+1];
+		iov[1].iov_len  = cert_len[i+1];
+		m_composev(p_lka, IMSG_SMTP_SSL_VERIFY_CHAIN, 0, 0, -1,
+		    iov, nitems(iov));
 	}
 
 	/* Tell lookup process that it can start verifying, we're done */
@@ -2131,7 +2171,13 @@ smtp_verify_certificate(struct smtp_sess
 	m_compose(p_lka, IMSG_SMTP_SSL_VERIFY, 0, 0, -1,
 	    &req_ca_vrfy, sizeof req_ca_vrfy);
 
-	return 1;
+	res = 1;
+
+    end:
+	for (i = 0; i < MAX_CERTS; ++i)
+		free(cert_der[i]);
+
+	return res;
 }
 
 static void
Index: usr.sbin/smtpd/smtpd.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/smtpd.c,v
retrieving revision 1.239
diff -u -p -r1.239 smtpd.c
--- usr.sbin/smtpd/smtpd.c	3 Jun 2015 02:24:36 -0000	1.239
+++ usr.sbin/smtpd/smtpd.c	1 Oct 2015 22:54:14 -0000
@@ -352,7 +352,8 @@ parent_sig_handler(int sig, short event,
 				} else
 					len = asprintf(&cause, "exited okay");
 			} else
-				fatalx("smtpd: unexpected cause of SIGCHLD");
+				/* WIFSTOPPED or WIFCONTINUED */
+				continue;
 
 			if (len == -1)
 				fatal("asprintf");
@@ -1073,19 +1074,34 @@ offline_enqueue(char *name)
 
 	if (pid == 0) {
 		char	*envp[2], *p, *tmp;
+		int	 fd;
 		FILE	*fp;
 		size_t	 len;
 		arglist	 args;
 
+		if (closefrom(STDERR_FILENO + 1) == -1)
+			_exit(1);
+
 		memset(&args, 0, sizeof(args));
 
-		if (lstat(path, &sb) == -1) {
-			log_warn("warn: smtpd: lstat: %s", path);
+		if ((fd = open(path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK)) == -1) {
+			log_warn("warn: smtpd: open: %s", path);
 			_exit(1);
 		}
 
-		if (chflags(path, 0) == -1) {
-			log_warn("warn: smtpd: chflags: %s", path);
+		if (fstat(fd, &sb) == -1) {
+			log_warn("warn: smtpd: fstat: %s", path);
+			_exit(1);
+		}
+
+		if (! S_ISREG(sb.st_mode)) {
+			log_warnx("warn: smtpd: file %s (uid %d) not regular",
+			    path, sb.st_uid);
+			_exit(1);
+		}
+
+		if (sb.st_nlink != 1) {
+			log_warnx("warn: smtpd: file %s is hard-link", path);
 			_exit(1);
 		}
 
@@ -1096,19 +1112,17 @@ offline_enqueue(char *name)
 			_exit(1);
 		}
 
-		if (! S_ISREG(sb.st_mode)) {
-			log_warnx("warn: smtpd: file %s (uid %d) not regular",
-			    path, sb.st_uid);
+		if (fchflags(fd, 0) == -1) {
+			log_warn("warn: smtpd: chflags: %s", path);
 			_exit(1);
 		}
 
 		if (setgroups(1, &pw->pw_gid) ||
 		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
-		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) ||
-		    closefrom(STDERR_FILENO + 1) == -1)
+		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
 			_exit(1);
 
-		if ((fp = fopen(path, "r")) == NULL)
+		if ((fp = fdopen(fd, "r")) == NULL)
 			_exit(1);
 
 		if (chdir(pw->pw_dir) == -1 && chdir("/") == -1)
@@ -1208,7 +1222,7 @@ parent_forward_open(char *username, char
 	}
 
 	do {
-		fd = open(pathname, O_RDONLY);
+		fd = open(pathname, O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
 	} while (fd == -1 && errno == EINTR);
 	if (fd == -1) {
 		if (errno == ENOENT)
@@ -1217,7 +1231,11 @@ parent_forward_open(char *username, char
 			errno = EAGAIN;
 			return -1;
 		}
-		log_warn("warn: smtpd: parent_forward_open: %s", pathname);
+		if (errno == ELOOP)
+			log_warnx("warn: smtpd: parent_forward_open: %s: "
+			    "cannot follow symbolic links", pathname);
+		else
+			log_warn("warn: smtpd: parent_forward_open: %s", pathname);
 		return -1;
 	}
 
Index: usr.sbin/smtpd/util.c
===================================================================
RCS file: /cvs/src/usr.sbin/smtpd/util.c,v
retrieving revision 1.113
diff -u -p -r1.113 util.c
--- usr.sbin/smtpd/util.c	6 May 2015 08:37:47 -0000	1.113
+++ usr.sbin/smtpd/util.c	1 Oct 2015 22:54:14 -0000
@@ -497,9 +497,6 @@ valid_domainpart(const char *s)
 	return res_hnok(s);
 }
 
-/*
- * Check file for security. Based on usr.bin/ssh/auth.c.
- */
 int
 secure_file(int fd, char *path, char *userdir, uid_t uid, int mayread)
 {
@@ -517,7 +514,7 @@ secure_file(int fd, char *path, char *us
 	/* Check the open file to avoid races. */
 	if (fstat(fd, &st) < 0 ||
 	    !S_ISREG(st.st_mode) ||
-	    (st.st_uid != 0 && st.st_uid != uid) ||
+	    st.st_uid != uid ||
 	    (st.st_mode & (mayread ? 022 : 066)) != 0)
 		return 0;
 
