EXTRA_DIST = \
	Makefile.mingw \
	libsiperc.rc.in

noinst_LTLIBRARIES = \
	libsipe_core.la \
	libsipe_core_crypto.la \
	libsipe_core_libxml2.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_core_la_SOURCES = \
	sipmsg.h \
	sipmsg.c \
	sip-csta.h \
	sip-csta.c \
	sip-sec.h \
	sip-sec.c \
	sip-sec-basic.h \
	sip-sec-basic.c \
	sip-sec-digest.h \
	sip-sec-digest.c \
	sip-sec-mech.h \
	sip-sec-tls-dsk.h \
	sip-sec-tls-dsk.c \
	sip-soap.h \
	sip-soap.c \
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
	sipe-ews.h \
	sipe-ews.c \
	sipe-ews-autodiscover.h \
	sipe-ews-autodiscover.c \
	sipe-ft.h \
	sipe-ft.c \
	sipe-ft-tftp.h \
	sipe-ft-tftp.c \
	sipe-group.h \
	sipe-group.c \
	sipe-groupchat.h \
	sipe-groupchat.c \
	sipe-http.h \
	sipe-http.c \
	sipe-http-request.h \
	sipe-http-request.c \
	sipe-http-transport.h \
	sipe-http-transport.c \
	sipe-im.h \
	sipe-im.c \
	sipe-incoming.h \
	sipe-incoming.c \
	sipe-lync-autodiscover.h \
	sipe-lync-autodiscover.c \
	sipe-mime-common.c \
	sipe-notify.h \
	sipe-notify.c \
	sipe-ocs2005.h \
	sipe-ocs2005.c \
	sipe-ocs2007.h \
	sipe-ocs2007.c \
	sipe-schedule.h \
	sipe-schedule.c \
	sipe-session.h \
	sipe-session.c \
	sipe-sign.h \
	sipe-sign.c \
	sipe-status.h \
	sipe-status.c \
	sipe-subscriptions.h \
	sipe-subscriptions.c \
	sipe-svc.h \
	sipe-svc.c \
	sipe-tls.h \
	sipe-tls.c \
	sipe-ucs.h \
	sipe-ucs.c \
	sipe-user.h \
	sipe-user.c \
	sipe-utils.h \
	sipe-utils.c \
	sipe-webticket.h \
	sipe-webticket.c \
	sipe-xml.h \
	uuid.h \
	uuid.c

if SIPE_OS_WIN32
libsipe_core_la_SOURCES += \
	sip-sec-sspi.h \
	sip-sec-sspi.c \
	sipe-domino.h \
	sipe-domino.c \
	sipe-win32dep.h \
	sipe-win32dep.c
else

if !SIP_SEC_GSSAPI_ONLY
libsipe_core_la_SOURCES += \
	sip-sec-ntlm.h \
	sip-sec-ntlm.c

noinst_LTLIBRARIES += \
	libsipe_core_tests.la

libsipe_core_tests_la_SOURCES = \
	sip-sec-ntlm-tests.c
libsipe_core_tests_la_LIBADD = \
	libsipe_core_la-sipmsg.lo \
	libsipe_core_la-sipe-sign.lo \
	libsipe_core_la-sipe-utils.lo \
	libsipe_core_la-uuid.lo
endif

endif

if SIPE_OPENSSL
libsipe_core_crypto_la_SOURCES = \
	sipe-cert-crypto-openssl.c \
	sipe-crypt-openssl.c \
	sipe-digest-openssl.c
else
libsipe_core_crypto_la_SOURCES = \
	sipe-cert-crypto-nss.c \
	sipe-crypt-nss.c \
	sipe-digest-nss.c
if !SIP_SEC_GSSAPI_ONLY
libsipe_core_crypto_la_SOURCES += \
	md4.h \
	md4.c
endif
endif

libsipe_core_libxml2_la_SOURCES = \
	sipe-xml.c

AM_CFLAGS = $(st)

libsipe_core_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	-I$(srcdir)/../api

if !SIPE_OS_WIN32
if !SIP_SEC_GSSAPI_ONLY
libsipe_core_tests_la_CFLAGS = $(libsipe_core_la_CFLAGS)
endif
endif

if SIP_SEC_GSSAPI
libsipe_core_la_SOURCES += \
	sip-sec-gssapi.h \
	sip-sec-gssapi.c
libsipe_core_la_CFLAGS  += $(KRB5_CFLAGS)

if !SIP_SEC_GSSAPI_ONLY
libsipe_core_la_SOURCES += \
	sip-sec-negotiate.h \
	sip-sec-negotiate.c
endif
endif


if SIPE_MIME_GMIME
noinst_LTLIBRARIES           += libsipe_core_mime.la
libsipe_core_mime_la_SOURCES  = sipe-mime.c
libsipe_core_mime_la_CFLAGS   = $(libsipe_core_la_CFLAGS) $(GMIME_CFLAGS)
endif

if SIPE_OS_WIN32
libsipe_core_la_CFLAGS  += -DHAVE_SSPI=1
endif

libsipe_core_crypto_la_CFLAGS = \
	$(libsipe_core_la_CFLAGS)
if SIPE_OPENSSL
libsipe_core_crypto_la_CFLAGS += \
	$(OPENSSL_CFLAGS)
else
libsipe_core_crypto_la_CFLAGS += \
	$(NSS_CFLAGS) \
	$(VALGRIND_CFLAGS)
endif

libsipe_core_libxml2_la_CFLAGS = $(libsipe_core_la_CFLAGS) $(LIBXML2_CFLAGS)

if SIPE_WITH_VV
libsipe_core_la_SOURCES += sipe-media.h sipe-media.c \
	sdpmsg.h sdpmsg.c \
	sipe-msrtp.c
endif

if SIPE_HAVE_XDATA
libsipe_core_la_SOURCES += \
	sipe-ft-lync.h sipe-ft-lync.c

if SIPE_HAVE_APPSHARE
libsipe_core_la_SOURCES += \
	sipe-appshare.c \
	sipe-appshare.h \
	sipe-appshare-client.h \
	sipe-appshare-remmina.c \
	sipe-appshare-xfreerdp.c

libsipe_core_la_CFLAGS += $(GIO_CFLAGS)

if SIPE_HAVE_RDP_SERVER
libsipe_core_la_CFLAGS += \
	$(FREERDP_SHADOW_CFLAGS)
endif
endif
endif

check_PROGRAMS =

check_PROGRAMS += sipe_xml_tests
sipe_xml_tests_SOURCES = sipe-xml-tests.c
sipe_xml_tests_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_xml_tests_LDADD = \
	libsipe_core_libxml2.la \
	libsipe_core_la-sipe-utils.lo \
	$(LIBXML2_LIBS) \
	$(GLIB_LIBS)

check_PROGRAMS += sip_sec_digest_tests
sip_sec_digest_tests_SOURCES = sip-sec-digest-tests.c
sip_sec_digest_tests_CFLAGS = $(libsipe_core_la_CFLAGS)
sip_sec_digest_tests_LDADD = \
	libsipe_core_la-sipe-utils.lo
if SIPE_OPENSSL
sip_sec_digest_tests_LDADD += \
	libsipe_core_crypto_la-sipe-crypt-openssl.lo \
	libsipe_core_crypto_la-sipe-digest-openssl.lo \
	$(OPENSSL_LIBS)
else
sip_sec_digest_tests_LDADD += \
	libsipe_core_crypto_la-sipe-crypt-nss.lo \
	libsipe_core_crypto_la-sipe-digest-nss.lo \
	$(NSS_LIBS)
endif
sip_sec_digest_tests_LDADD += \
	$(GLIB_LIBS)

# disables "caching" of memory blocks in tests
TESTS_ENVIRONMENT = G_SLICE="always-malloc"
TESTS = $(check_PROGRAMS)

noinst_PROGRAMS =

if !SIPE_OS_WIN32
# TODO: the code needs some TLC from a MinGW expert to compile...
noinst_PROGRAMS += sipe_tls_analyzer
sipe_tls_analyzer_SOURCES = sipe-tls-analyzer.c
sipe_tls_analyzer_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_tls_analyzer_LDADD = \
	$(GLIB_LIBS)

noinst_PROGRAMS += sipe_tls_tester
sipe_tls_tester_SOURCES = sipe-tls-tester.c
sipe_tls_tester_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_tls_tester_LDADD = \
	libsipe_core_la-sipe-tls.lo

if SIPE_OPENSSL
sipe_tls_tester_LDADD += \
	libsipe_core_crypto_la-sipe-cert-crypto-openssl.lo \
	libsipe_core_crypto_la-sipe-crypt-openssl.lo \
	libsipe_core_crypto_la-sipe-digest-openssl.lo \
	$(OPENSSL_LIBS)
else
sipe_tls_tester_LDADD += \
	libsipe_core_crypto_la-sipe-cert-crypto-nss.lo \
	libsipe_core_crypto_la-sipe-crypt-nss.lo \
	libsipe_core_crypto_la-sipe-digest-nss.lo \
	$(NSS_LIBS)
endif
sipe_tls_tester_LDADD += \
	$(GLIB_LIBS)
endif

noinst_PROGRAMS += sipe_ntlm_analyzer
sipe_ntlm_analyzer_SOURCES = sip-sec-ntlm-analyzer.c
sipe_ntlm_analyzer_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_ntlm_analyzer_LDADD = \
	$(GLIB_LIBS)
