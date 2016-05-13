#!/bin/sh -x

rm -f /usr/libexec/smtpd/makemap

# People requiring these backends should install the opensmtpd-extras main package.
rm -f /usr/libexec/smtpd/table-ldap
rm -f /usr/libexec/smtpd/table-passwd
rm -f /usr/libexec/smtpd/table-sqlite
rm -f /usr/share/man/man5/table_passwd.5

rm -f /usr/share/misc/termcap.db /usr/share/misc/terminfo.db

rm -f /usr/X11R6/include/intel_*.h
rm -f /usr/X11R6/include/r600_pci_ids.h
rm -f /usr/X11R6/include/radeon_*.h

rm -f /usr/include/malloc.h

rm -f /usr/libexec/auth/login_tis
rm -f /etc/rc.d/yppasswdd /usr/sbin/rpc.yppasswdd

cd /usr/X11R6/include/freetype2
rm -rf config
rm -f freetype.h ftadvanc.h ftbbox.h ftbdf.h ftbitmap.h ftbzip2.h \
          ftcache.h ftcffdrv.h ftchapters.h ftcid.h fterrdef.h \
          fterrors.h ftfntfmt.h ftgasp.h ftglyph.h ftgxval.h ftgzip.h \
          ftimage.h ftincrem.h ftlcdfil.h ftlist.h ftlzw.h ftmac.h \
          ftmm.h ftmodapi.h ftmoderr.h ftotval.h ftoutln.h ftpfr.h \
          ftrender.h ftsizes.h ftsnames.h ftstroke.h ftsynth.h \
          ftsystem.h fttrigon.h fttypes.h ftwinfnt.h t1tables.h \
          ttnameid.h tttables.h tttags.h ttunpat.h
