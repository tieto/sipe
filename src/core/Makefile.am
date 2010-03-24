noinst_LTLIBRARIES = libsipe_core.la libsipe_core_purple.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_core_la_SOURCES = \
	sipmsg.h \
	sipmsg.c \
	sip-csta.h \
	sip-csta.c \
	sip-sec.h \
	sip-sec.c \
	sip-sec-mech.h \
	sipe-cal.h \
	sipe-cal.c \
	sipe-chat.h \
	sipe-chat.c \
	sipe-dialog.h \
	sipe-dialog.c \
	sipe-session.h \
	sipe-session.c \
	sipe-sign.h \
	sipe-sign.c \
	sipe-xml.h \
	sipe-xml.c

libsipe_core_purple_la_SOURCES = \
	sipe.h \
	sipe.c \
	sipe-conf.h \
	sipe-conf.c \
	sipe-utils.h \
	sipe-utils.c \
	http-conn.h \
	http-conn.c \
	sipe-ews.h \
	sipe-ews.c \
	sipe-mime.h \
	sipe-mime.c \
	sip-sec-ntlm.h \
	sip-sec-ntlm.c \
	sipe-ft.h \
	sipe-ft.c \
	uuid.h \
	uuid.c

AM_CFLAGS = $(st)

libsipe_core_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(LIBXML2_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	-I$(srcdir)/../api

if SIP_SEC_KRB5
libsipe_core_la_SOURCES += sip-sec-krb5.h sip-sec-krb5.c
libsipe_core_la_CFLAGS  += $(KRB5_CFLAGS)
endif

if SIPE_INCLUDE_PURPLE
libsipe_core_purple_la_CFLAGS = \
	$(libsipe_core_la_CFLAGS) \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/../purple
endif

check_PROGRAMS = sipe_xml_tests
sipe_xml_tests_SOURCES = sipe-xml-tests.c
sipe_xml_tests_CFLAGS = $(libsipe_core_la_CFLAGS)
sipe_xml_tests_LDADD = libsipe_core.la
sipe_xml_tests_LDFLAGS = $(LIBXML2_LIBS) $(GLIB_LIBS)
if SIPE_INCLUDE_PURPLE
sipe_xml_tests_LDADD   += libsipe_core_purple.la
sipe_xml_tests_LDFLAGS += $(PURPLE_LIBS)
endif

# disables "caching" of memory blocks in tests
TESTS_ENVIRONMENT = G_SLICE="always-malloc"
TESTS = $(check_PROGRAMS)
