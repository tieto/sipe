noinst_LTLIBRARIES = libsipecore.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipecore_la_SOURCES = \
	sip-prefix.h \
	sipmsg.c \
	sipmsg.h \
	sipe.h \
	sipe.c \
	sipe-chat.h \
	sipe-chat.c \
	sipe-conf.h \
	sipe-conf.c \
	sipe-dialog.h \
	sipe-dialog.c \
	sipe-session.h \
	sipe-session.c \
	sipe-utils.h \
	sipe-utils.c \
	sipe-cal.h \
	sipe-cal.c \
	http-conn.h \
	http-conn.c \
	sipe-ews.h \
	sipe-ews.c \
	sip-csta.c \
	sip-csta.h \
	sip-sec.h \
	sip-sec.c \
	sip-sec-mech.h \
	sip-sec-ntlm.h \
	sip-sec-ntlm.c \
	sipe-sign.h \
	sipe-sign.c \
	sipe-ft.h \
	sipe-ft.c \
	sipe-xml.h \
	sipe-xml.c \
	uuid.h \
	uuid.c

if SIP_SEC_KRB5
libsipecore_la_SOURCES += \
	sip-sec-krb5.h \
	sip-sec-krb5.c
endif

AM_CFLAGS = $(st)

libsipecore_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(LIBXML2_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(KRB5_CFLAGS) \
	-I$(srcdir)/../api

if SIPE_INCLUDE_PURPLE
libsipecore_la_CFLAGS += $(PURPLE_CFLAGS) -I$(srcdir)/../purple
endif

check_PROGRAMS = sipe_xml_tests
sipe_xml_tests_SOURCES = sipe-xml-tests.c
sipe_xml_tests_CFLAGS = $(libsipecore_la_CFLAGS)
sipe_xml_tests_LDFLAGS = -L.libs -lsipecore $(LIBXML2_LIBS) $(GLIB_LIBS)

TESTS = $(check_PROGRAMS)
