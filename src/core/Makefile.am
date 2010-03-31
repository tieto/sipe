noinst_LTLIBRARIES = \
	libsipe_core.la \
	libsipe_core_tests.la \
	libsipe_core_purple.la

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	sipe-win32dep.h \
	sipe-win32dep.c

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
	sip-sec-ntlm.h \
	sip-sec-ntlm.c \
	sip-transport.h \
	sip-transport.c \
	sipe-buddy.h \
	sipe-buddy.c \
	sipe-cal.h \
	sipe-cal.c \
	sipe-chat.h \
	sipe-chat.c \
	sipe-core-private.h \
	sipe-core.c \
	sipe-dialog.h \
	sipe-dialog.c \
	sipe-domino.h \
	sipe-domino.c \
	sipe-ews.h \
	sipe-ews.c \
	sipe-schedule.h \
	sipe-schedule.c \
	sipe-session.h \
	sipe-session.c \
	sipe-sign.h \
	sipe-sign.c \
	sipe-utils.h \
	sipe-utils.c \
	sipe-xml.h \
	sipe-xml.c \
	uuid.h \
	uuid.c

libsipe_core_tests_la_SOURCES = \
	sip-sec-ntlm-tests.c

libsipe_core_purple_la_SOURCES = \
	sipe.h \
	sipe.c \
	sipe-conf.h \
	sipe-conf.c \
	sipe-ft.h \
	sipe-ft.c

AM_CFLAGS = $(st)

libsipe_core_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(LIBXML2_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	-I$(srcdir)/../api

libsipe_core_tests_la_CFLAGS = $(libsipe_core_la_CFLAGS)

if SIP_SEC_KRB5
libsipe_core_la_SOURCES += sip-sec-krb5.h sip-sec-krb5.c
libsipe_core_la_CFLAGS  += $(KRB5_CFLAGS)
endif

if SIPE_MIME_GMIME
libsipe_core_la_SOURCES += sipe-mime.c
libsipe_core_la_CFLAGS  += $(GMIME_CFLAGS)
endif

if SIPE_CRYPTO_NSS
libsipe_core_la_SOURCES += \
	md4.h \
	md4.c \
	sipe-crypt.c \
	sipe-digest.c
libsipe_core_la_CFLAGS  += $(NSS_CFLAGS)
endif

if SIPE_INCLUDE_PURPLE
libsipe_core_purple_la_CFLAGS = $(libsipe_core_la_CFLAGS) $(PURPLE_CFLAGS)
endif

if SIPE_WITH_VV
libsipe_core_la_SOURCES += sipe-media.h sipe-media.c
endif

check_PROGRAMS = sipe_xml_tests
sipe_xml_tests_SOURCES = sipe-xml-tests.c
sipe_xml_tests_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_xml_tests_LDADD = libsipe_core.la $(LIBXML2_LIBS) $(GLIB_LIBS)

# disables "caching" of memory blocks in tests
TESTS_ENVIRONMENT = G_SLICE="always-malloc"
TESTS = $(check_PROGRAMS)
