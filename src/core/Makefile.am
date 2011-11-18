noinst_LTLIBRARIES = \
	libsipe_core.la \
	libsipe_core_crypto_nss.la \
	libsipe_core_libxml2.la \
	libsipe_core_purple.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_core_la_SOURCES = \
	http-conn.h \
	http-conn.c \
	sipmsg.h \
	sipmsg.c \
	sip-csta.h \
	sip-csta.c \
	sip-sec.h \
	sip-sec.c \
	sip-sec-mech.h \
	sip-transport.h \
	sip-transport.c \
	sipe-buddy.h \
	sipe-buddy.c \
	sipe-cal.h \
	sipe-cal.c \
	sipe-certificate.h \
	sipe-certificate.c \
	sipe-cert-crypto.h \
	sipe-chat.h \
	sipe-chat.c \
	sipe-conf.h \
	sipe-conf.c \
	sipe-core-private.h \
	sipe-core.c \
	sipe-crypt.h \
	sipe-dialog.h \
	sipe-dialog.c \
	sipe-digest.h \
	sipe-domino.h \
	sipe-domino.c \
	sipe-ews.h \
	sipe-ews.c \
	sipe-ft.h \
	sipe-ft.c \
	sipe-ft-tftp.c \
	sipe-group.h \
	sipe-group.c \
	sipe-groupchat.h \
	sipe-groupchat.c \
	sipe-im.h \
	sipe-im.c \
	sipe-incoming.h \
	sipe-incoming.c \
	sipe-schedule.h \
	sipe-schedule.c \
	sipe-session.h \
	sipe-session.c \
	sipe-sign.h \
	sipe-sign.c \
	sipe-subscriptions.h \
	sipe-subscriptions.c \
	sipe-svc.h \
	sipe-svc.c \
	sipe-tls.h \
	sipe-tls.c \
	sipe-user.c \
	sipe-user.h \
	sipe-xml.h \
	uuid.h \
	uuid.c

if SIPE_OS_WIN32
libsipe_core_la_SOURCES += \
	sip-sec-sspi.h \
	sip-sec-sspi.c \
	sipe-win32dep.h \
	sipe-win32dep.c
else
libsipe_core_la_SOURCES += \
	md4.h \
	md4.c \
	sip-sec-ntlm.h \
	sip-sec-ntlm.c \
	sip-sec-tls-dsk.h \
	sip-sec-tls-dsk.c \
	sipe-utils.h \
	sipe-utils.c

noinst_LTLIBRARIES += \
	libsipe_core_tests.la

libsipe_core_tests_la_SOURCES = \
	sip-sec-ntlm-tests.c
endif

libsipe_core_crypto_nss_la_SOURCES = \
	sipe-cert-crypto-nss.c \
	sipe-crypt-nss.c \
	sipe-digest-nss.c

libsipe_core_libxml2_la_SOURCES = \
	sipe-xml.c

libsipe_core_purple_la_SOURCES = \
	sipe.h \
	sipe.c

if SIPE_OS_WIN32
# sipe-utils.c contain windows networking dependency wrapped in purple
libsipe_core_purple_la_SOURCES += \
	sipe-utils.h \
	sipe-utils.c
endif

AM_CFLAGS = $(st)

libsipe_core_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	-I$(srcdir)/../api

if !SIPE_OS_WIN32
libsipe_core_tests_la_CFLAGS = $(libsipe_core_la_CFLAGS)
endif

if SIP_SEC_KRB5
libsipe_core_la_SOURCES += sip-sec-krb5.h sip-sec-krb5.c
libsipe_core_la_CFLAGS  += $(KRB5_CFLAGS)
endif

if SIPE_MIME_GMIME
noinst_LTLIBRARIES           += libsipe_core_mime.la
libsipe_core_mime_la_SOURCES  = sipe-mime.c
libsipe_core_mime_la_CFLAGS   = $(libsipe_core_la_CFLAGS) $(GMIME_CFLAGS)
endif

if SIPE_OS_WIN32
libsipe_core_la_CFLAGS  += -DHAVE_SSPI=1
endif

libsipe_core_crypto_nss_la_CFLAGS = \
	$(libsipe_core_la_CFLAGS) \
	$(NSS_CFLAGS) \
	$(VALGRIND_CFLAGS)

libsipe_core_libxml2_la_CFLAGS = $(libsipe_core_la_CFLAGS) $(LIBXML2_CFLAGS)

if SIPE_INCLUDE_PURPLE
libsipe_core_purple_la_CFLAGS = $(libsipe_core_la_CFLAGS) $(PURPLE_CFLAGS)
endif

if SIPE_WITH_VV
libsipe_core_la_SOURCES += sipe-media.h sipe-media.c \
	sdpmsg.h sdpmsg.c
endif

check_PROGRAMS = sipe_xml_tests
sipe_xml_tests_SOURCES = sipe-xml-tests.c
sipe_xml_tests_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_xml_tests_LDADD = \
	libsipe_core.la \
	libsipe_core_libxml2.la \
	$(LIBXML2_LIBS) \
	$(GLIB_LIBS)

# disables "caching" of memory blocks in tests
TESTS_ENVIRONMENT = G_SLICE="always-malloc"
TESTS = $(check_PROGRAMS)
