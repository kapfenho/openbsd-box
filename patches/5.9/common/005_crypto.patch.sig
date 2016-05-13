untrusted comment: signature from openbsd 5.9 base secret key
RWQJVNompF3pwVAgfrp7vECCMZoD2Hl2l33QiUnMyrjP5f4jESBQeXxJt7B6zO9DEnn13/zWKkUIygjFmFXD3wAhC9jmhxSqvQY=

OpenBSD 5.9 errata 5, May 3, 2016:

Fix multiple vulnerabilities in libcrypto relating to ASN.1 and encoding.
From OpenSSL.

Apply by doing:
    signify -Vep /etc/signify/openbsd-59-base.pub -x 005_crypto.patch.sig \
            -m - | (cd /usr/src && patch -p0)

And then rebuild and install libcrypto:
	cd src/lib/libcrypto
	make obj
	make depend
	make
	make install


Index: lib/libssl/src/crypto/constant_time_locl.h
===================================================================
RCS file: lib/libssl/src/crypto/constant_time_locl.h
diff -N lib/libssl/src/crypto/constant_time_locl.h
--- /dev/null	1 Jan 1970 00:00:00 -0000
+++ lib/libssl/src/crypto/constant_time_locl.h	30 Apr 2016 16:16:32 -0000
@@ -0,0 +1,209 @@
+/* crypto/constant_time_locl.h */
+/*-
+ * Utilities for constant-time cryptography.
+ *
+ * Author: Emilia Kasper (emilia@openssl.org)
+ * Based on previous work by Bodo Moeller, Emilia Kasper, Adam Langley
+ * (Google).
+ * ====================================================================
+ * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ * 1. Redistributions of source code must retain the copyright
+ *    notice, this list of conditions and the following disclaimer.
+ * 2. Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in the
+ *    documentation and/or other materials provided with the distribution.
+ * 3. All advertising materials mentioning features or use of this software
+ *    must display the following acknowledgement:
+ *    "This product includes cryptographic software written by
+ *     Eric Young (eay@cryptsoft.com)"
+ *    The word 'cryptographic' can be left out if the rouines from the library
+ *    being used are not cryptographic related :-).
+ * 4. If you include any Windows specific code (or a derivative thereof) from
+ *    the apps directory (application code) you must include an acknowledgement:
+ *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
+ *
+ * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
+ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
+ * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
+ * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
+ * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
+ * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
+ * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ *
+ * The licence and distribution terms for any publically available version or
+ * derivative of this code cannot be changed.  i.e. this code cannot simply be
+ * copied and put under another distribution licence
+ * [including the GNU Public Licence.]
+ */
+
+#ifndef HEADER_CONSTANT_TIME_LOCL_H
+# define HEADER_CONSTANT_TIME_LOCL_H
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/*-
+ * The boolean methods return a bitmask of all ones (0xff...f) for true
+ * and 0 for false. This is useful for choosing a value based on the result
+ * of a conditional in constant time. For example,
+ *
+ * if (a < b) {
+ *   c = a;
+ * } else {
+ *   c = b;
+ * }
+ *
+ * can be written as
+ *
+ * unsigned int lt = constant_time_lt(a, b);
+ * c = constant_time_select(lt, a, b);
+ */
+
+/*
+ * Returns the given value with the MSB copied to all the other
+ * bits. Uses the fact that arithmetic shift shifts-in the sign bit.
+ * However, this is not ensured by the C standard so you may need to
+ * replace this with something else on odd CPUs.
+ */
+static inline unsigned int constant_time_msb(unsigned int a);
+
+/*
+ * Returns 0xff..f if a < b and 0 otherwise.
+ */
+static inline unsigned int constant_time_lt(unsigned int a, unsigned int b);
+/* Convenience method for getting an 8-bit mask. */
+static inline unsigned char constant_time_lt_8(unsigned int a,
+                                               unsigned int b);
+
+/*
+ * Returns 0xff..f if a >= b and 0 otherwise.
+ */
+static inline unsigned int constant_time_ge(unsigned int a, unsigned int b);
+/* Convenience method for getting an 8-bit mask. */
+static inline unsigned char constant_time_ge_8(unsigned int a,
+                                               unsigned int b);
+
+/*
+ * Returns 0xff..f if a == 0 and 0 otherwise.
+ */
+static inline unsigned int constant_time_is_zero(unsigned int a);
+/* Convenience method for getting an 8-bit mask. */
+static inline unsigned char constant_time_is_zero_8(unsigned int a);
+
+/*
+ * Returns 0xff..f if a == b and 0 otherwise.
+ */
+static inline unsigned int constant_time_eq(unsigned int a, unsigned int b);
+/* Convenience method for getting an 8-bit mask. */
+static inline unsigned char constant_time_eq_8(unsigned int a,
+                                               unsigned int b);
+/* Signed integers. */
+static inline unsigned int constant_time_eq_int(int a, int b);
+/* Convenience method for getting an 8-bit mask. */
+static inline unsigned char constant_time_eq_int_8(int a, int b);
+
+/*-
+ * Returns (mask & a) | (~mask & b).
+ *
+ * When |mask| is all 1s or all 0s (as returned by the methods above),
+ * the select methods return either |a| (if |mask| is nonzero) or |b|
+ * (if |mask| is zero).
+ */
+static inline unsigned int constant_time_select(unsigned int mask,
+                                                unsigned int a,
+                                                unsigned int b);
+/* Convenience method for unsigned chars. */
+static inline unsigned char constant_time_select_8(unsigned char mask,
+                                                   unsigned char a,
+                                                   unsigned char b);
+/* Convenience method for signed integers. */
+static inline int constant_time_select_int(unsigned int mask, int a, int b);
+
+static inline unsigned int constant_time_msb(unsigned int a)
+{
+    return 0 - (a >> (sizeof(a) * 8 - 1));
+}
+
+static inline unsigned int constant_time_lt(unsigned int a, unsigned int b)
+{
+    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
+}
+
+static inline unsigned char constant_time_lt_8(unsigned int a, unsigned int b)
+{
+    return (unsigned char)(constant_time_lt(a, b));
+}
+
+static inline unsigned int constant_time_ge(unsigned int a, unsigned int b)
+{
+    return ~constant_time_lt(a, b);
+}
+
+static inline unsigned char constant_time_ge_8(unsigned int a, unsigned int b)
+{
+    return (unsigned char)(constant_time_ge(a, b));
+}
+
+static inline unsigned int constant_time_is_zero(unsigned int a)
+{
+    return constant_time_msb(~a & (a - 1));
+}
+
+static inline unsigned char constant_time_is_zero_8(unsigned int a)
+{
+    return (unsigned char)(constant_time_is_zero(a));
+}
+
+static inline unsigned int constant_time_eq(unsigned int a, unsigned int b)
+{
+    return constant_time_is_zero(a ^ b);
+}
+
+static inline unsigned char constant_time_eq_8(unsigned int a, unsigned int b)
+{
+    return (unsigned char)(constant_time_eq(a, b));
+}
+
+static inline unsigned int constant_time_eq_int(int a, int b)
+{
+    return constant_time_eq((unsigned)(a), (unsigned)(b));
+}
+
+static inline unsigned char constant_time_eq_int_8(int a, int b)
+{
+    return constant_time_eq_8((unsigned)(a), (unsigned)(b));
+}
+
+static inline unsigned int constant_time_select(unsigned int mask,
+                                                unsigned int a,
+                                                unsigned int b)
+{
+    return (mask & a) | (~mask & b);
+}
+
+static inline unsigned char constant_time_select_8(unsigned char mask,
+                                                   unsigned char a,
+                                                   unsigned char b)
+{
+    return (unsigned char)(constant_time_select(mask, a, b));
+}
+
+static inline int constant_time_select_int(unsigned int mask, int a, int b)
+{
+    return (int)(constant_time_select(mask, (unsigned)(a), (unsigned)(b)));
+}
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif                          /* HEADER_CONSTANT_TIME_LOCL_H */
Index: lib/libssl/src/crypto/asn1/a_d2i_fp.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/asn1/a_d2i_fp.c,v
retrieving revision 1.11
diff -u -p -r1.11 a_d2i_fp.c
--- lib/libssl/src/crypto/asn1/a_d2i_fp.c	13 Jul 2014 11:10:20 -0000	1.11
+++ lib/libssl/src/crypto/asn1/a_d2i_fp.c	30 Apr 2016 16:16:32 -0000
@@ -144,6 +144,7 @@ ASN1_item_d2i_fp(const ASN1_ITEM *it, FI
 }
 
 #define HEADER_SIZE   8
+#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)
 static int
 asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
 {
@@ -167,18 +168,22 @@ asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
 		if (want >= (len - off)) {
 			want -= (len - off);
 
-			if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
-				ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
+			if (len + want < len ||
+			    !BUF_MEM_grow_clean(b, len + want)) {
+				ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+				    ERR_R_MALLOC_FAILURE);
 				goto err;
 			}
 			i = BIO_read(in, &(b->data[len]), want);
 			if ((i < 0) && ((len - off) == 0)) {
-				ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_NOT_ENOUGH_DATA);
+				ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+				    ASN1_R_NOT_ENOUGH_DATA);
 				goto err;
 			}
 			if (i > 0) {
 				if (len + i < len) {
-					ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
+					ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+					    ASN1_R_TOO_LONG);
 					goto err;
 				}
 				len += i;
@@ -206,7 +211,8 @@ asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
 			/* no data body so go round again */
 			eos++;
 			if (eos < 0) {
-				ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_HEADER_TOO_LONG);
+				ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+				    ASN1_R_HEADER_TOO_LONG);
 				goto err;
 			}
 			want = HEADER_SIZE;
@@ -221,28 +227,45 @@ asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
 			/* suck in c.slen bytes of data */
 			want = c.slen;
 			if (want > (len - off)) {
+				size_t chunk_max = ASN1_CHUNK_INITIAL_SIZE;
+
 				want -= (len - off);
 				if (want > INT_MAX /* BIO_read takes an int length */ ||
 				    len+want < len) {
-					ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
+					ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+					    ASN1_R_TOO_LONG);
 					goto err;
 				}
-				if (!BUF_MEM_grow_clean(b, len + want)) {
-					ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
+				/*
+				 * Read content in chunks of increasing size
+				 * so we can return an error for EOF without
+				 * having to allocate the entire content length
+				 * in one go.
+				 */
+				size_t chunk = want > chunk_max ? chunk_max : want;
+
+				if (!BUF_MEM_grow_clean(b, len + chunk)) {
+					ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
+					    ERR_R_MALLOC_FAILURE);
 					goto err;
 				}
-				while (want > 0) {
-					i = BIO_read(in, &(b->data[len]), want);
+				want -= chunk;
+				while (chunk > 0) {
+					i = BIO_read(in, &(b->data[len]), chunk);
 					if (i <= 0) {
 						ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
 						    ASN1_R_NOT_ENOUGH_DATA);
 						goto err;
 					}
-					/* This can't overflow because
-					 * |len+want| didn't overflow. */
+					/*
+					 * This can't overflow because |len+want|
+					 * didn't overflow.
+					 */
 					len += i;
-					want -= i;
+					chunk -= i;
 				}
+				if (chunk_max < INT_MAX/2)
+					chunk_max *= 2;
 			}
 			if (off + c.slen < off) {
 				ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
Index: lib/libssl/src/crypto/asn1/a_type.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/asn1/a_type.c,v
retrieving revision 1.16
diff -u -p -r1.16 a_type.c
--- lib/libssl/src/crypto/asn1/a_type.c	19 Mar 2015 14:00:22 -0000	1.16
+++ lib/libssl/src/crypto/asn1/a_type.c	30 Apr 2016 16:16:32 -0000
@@ -127,9 +127,7 @@ ASN1_TYPE_cmp(ASN1_TYPE *a, ASN1_TYPE *b
 		break;
 
 	case V_ASN1_INTEGER:
-	case V_ASN1_NEG_INTEGER:
 	case V_ASN1_ENUMERATED:
-	case V_ASN1_NEG_ENUMERATED:
 	case V_ASN1_BIT_STRING:
 	case V_ASN1_OCTET_STRING:
 	case V_ASN1_SEQUENCE:
Index: lib/libssl/src/crypto/asn1/tasn_dec.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/asn1/tasn_dec.c,v
retrieving revision 1.29
diff -u -p -r1.29 tasn_dec.c
--- lib/libssl/src/crypto/asn1/tasn_dec.c	12 Dec 2015 21:05:11 -0000	1.29
+++ lib/libssl/src/crypto/asn1/tasn_dec.c	30 Apr 2016 16:16:32 -0000
@@ -861,9 +861,7 @@ asn1_ex_c2i(ASN1_VALUE **pval, const uns
 		break;
 
 	case V_ASN1_INTEGER:
-	case V_ASN1_NEG_INTEGER:
 	case V_ASN1_ENUMERATED:
-	case V_ASN1_NEG_ENUMERATED:
 		tint = (ASN1_INTEGER **)pval;
 		if (!c2i_ASN1_INTEGER(tint, &cont, len))
 			goto err;
Index: lib/libssl/src/crypto/asn1/tasn_enc.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/asn1/tasn_enc.c,v
retrieving revision 1.17
diff -u -p -r1.17 tasn_enc.c
--- lib/libssl/src/crypto/asn1/tasn_enc.c	22 Dec 2015 08:44:44 -0000	1.17
+++ lib/libssl/src/crypto/asn1/tasn_enc.c	30 Apr 2016 16:16:32 -0000
@@ -603,9 +603,7 @@ asn1_ex_i2c(ASN1_VALUE **pval, unsigned 
 		break;
 
 	case V_ASN1_INTEGER:
-	case V_ASN1_NEG_INTEGER:
 	case V_ASN1_ENUMERATED:
-	case V_ASN1_NEG_ENUMERATED:
 		/* These are all have the same content format
 		 * as ASN1_INTEGER
 		 */
Index: lib/libssl/src/crypto/evp/e_aes_cbc_hmac_sha1.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/evp/e_aes_cbc_hmac_sha1.c,v
retrieving revision 1.9
diff -u -p -r1.9 e_aes_cbc_hmac_sha1.c
--- lib/libssl/src/crypto/evp/e_aes_cbc_hmac_sha1.c	10 Sep 2015 15:56:25 -0000	1.9
+++ lib/libssl/src/crypto/evp/e_aes_cbc_hmac_sha1.c	30 Apr 2016 16:16:32 -0000
@@ -60,6 +60,7 @@
 #include <openssl/aes.h>
 #include <openssl/sha.h>
 #include "evp_locl.h"
+#include "constant_time_locl.h"
 
 #ifndef EVP_CIPH_FLAG_AEAD_CIPHER
 #define EVP_CIPH_FLAG_AEAD_CIPHER	0x200000
@@ -281,6 +282,8 @@ aesni_cbc_hmac_sha1_cipher(EVP_CIPHER_CT
 			maxpad = len - (SHA_DIGEST_LENGTH + 1);
 			maxpad |= (255 - maxpad) >> (sizeof(maxpad) * 8 - 8);
 			maxpad &= 255;
+
+			ret &= constant_time_ge(maxpad, pad);
 
 			inp_len = len - (SHA_DIGEST_LENGTH + pad + 1);
 			mask = (0 - ((inp_len - len) >>
Index: lib/libssl/src/crypto/evp/encode.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/evp/encode.c,v
retrieving revision 1.20
diff -u -p -r1.20 encode.c
--- lib/libssl/src/crypto/evp/encode.c	7 Feb 2015 13:19:15 -0000	1.20
+++ lib/libssl/src/crypto/evp/encode.c	30 Apr 2016 16:16:32 -0000
@@ -56,6 +56,7 @@
  * [including the GNU Public Licence.]
  */
 
+#include <sys/limits.h>
 #include <stdio.h>
 #include <string.h>
 
@@ -124,13 +125,13 @@ EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, un
     const unsigned char *in, int inl)
 {
 	int i, j;
-	unsigned int total = 0;
+	size_t total = 0;
 
 	*outl = 0;
 	if (inl == 0)
 		return;
 	OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
-	if ((ctx->num + inl) < ctx->length) {
+	if (ctx->length - ctx->num > inl) {
 		memcpy(&(ctx->enc_data[ctx->num]), in, inl);
 		ctx->num += inl;
 		return;
@@ -147,7 +148,7 @@ EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, un
 		*out = '\0';
 		total = j + 1;
 	}
-	while (inl >= ctx->length) {
+	while (inl >= ctx->length && total <= INT_MAX) {
 		j = EVP_EncodeBlock(out, in, ctx->length);
 		in += ctx->length;
 		inl -= ctx->length;
@@ -155,6 +156,11 @@ EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, un
 		*(out++) = '\n';
 		*out = '\0';
 		total += j + 1;
+	}
+	if (total > INT_MAX) {
+		/* Too much output data! */
+		*outl = 0;
+		return;
 	}
 	if (inl != 0)
 		memcpy(&(ctx->enc_data[0]), in, inl);
Index: lib/libssl/src/crypto/evp/evp_enc.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/crypto/evp/evp_enc.c,v
retrieving revision 1.27
diff -u -p -r1.27 evp_enc.c
--- lib/libssl/src/crypto/evp/evp_enc.c	10 Sep 2015 15:56:25 -0000	1.27
+++ lib/libssl/src/crypto/evp/evp_enc.c	30 Apr 2016 16:16:32 -0000
@@ -334,7 +334,7 @@ EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, u
 		return 0;
 	}
 	if (i != 0) {
-		if (i + inl < bl) {
+		if (bl - i > inl) {
 			memcpy(&(ctx->buf[i]), in, inl);
 			ctx->buf_len += inl;
 			*outl = 0;
Index: lib/libssl/src/ssl/s3_pkt.c
===================================================================
RCS file: /cvs/src/lib/libssl/src/ssl/s3_pkt.c,v
retrieving revision 1.57
diff -u -p -r1.57 s3_pkt.c
--- lib/libssl/src/ssl/s3_pkt.c	12 Sep 2015 16:10:07 -0000	1.57
+++ lib/libssl/src/ssl/s3_pkt.c	30 Apr 2016 16:14:30 -0000
@@ -956,6 +956,7 @@ start:
 
 		memcpy(buf, &(rr->data[rr->off]), n);
 		if (!peek) {
+			memset(&(rr->data[rr->off]), 0, n);
 			rr->length -= n;
 			rr->off += n;
 			if (rr->length == 0) {
