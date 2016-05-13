untrusted comment: signature from openbsd 5.8 base secret key
RWQNNZXtC/MqP+d8P00767XDYRlDEB8PXiGrF41Wg0dHkknO1qrx0D0UXht/nXcPLl/V3BMEyEbBfXfNTCb8ez4oGnWLJffziQI=

OpenBSD 5.8 errata 8, Nov 9, 2015

Insufficient validation of RSN element group cipher values in 802.11
beacons and probe responses could result in system panics.

Apply by doing:
    signify -Vep /etc/signify/openbsd-58-base.pub -x 008_rsn.patch.sig \
	-m - | (cd /usr/src && patch -p0)

And then rebuild and install a kernel:
    cd /usr/src/sys/arch/`machine`/conf
    KK=`sysctl -n kern.osversion | cut -d# -f1`
    config $KK
    cd ../compile/$KK
    make
    make install

Index: sys/net80211/ieee80211_input.c
===================================================================
RCS file: /cvs/src/sys/net80211/ieee80211_input.c,v
retrieving revision 1.137
diff -u -p -r1.137 ieee80211_input.c
--- sys/net80211/ieee80211_input.c	15 Jul 2015 22:16:42 -0000	1.137
+++ sys/net80211/ieee80211_input.c	8 Nov 2015 11:31:27 -0000
@@ -1221,7 +1221,9 @@ ieee80211_parse_rsn_body(struct ieee8021
 	if (frm + 4 > efrm)
 		return 0;
 	rsn->rsn_groupcipher = ieee80211_parse_rsn_cipher(frm);
-	if (rsn->rsn_groupcipher == IEEE80211_CIPHER_USEGROUP)
+	if (rsn->rsn_groupcipher == IEEE80211_CIPHER_NONE ||
+	    rsn->rsn_groupcipher == IEEE80211_CIPHER_USEGROUP ||
+	    rsn->rsn_groupcipher == IEEE80211_CIPHER_BIP)
 		return IEEE80211_STATUS_BAD_GROUP_CIPHER;
 	frm += 4;
 
@@ -1285,6 +1287,8 @@ ieee80211_parse_rsn_body(struct ieee8021
 	if (frm + 4 > efrm)
 		return 0;
 	rsn->rsn_groupmgmtcipher = ieee80211_parse_rsn_cipher(frm);
+	if (rsn->rsn_groupmgmtcipher != IEEE80211_CIPHER_BIP)
+		return IEEE80211_STATUS_BAD_GROUP_CIPHER;
 
 	return IEEE80211_STATUS_SUCCESS;
 }
