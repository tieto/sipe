
pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_la_SOURCES = \
	sip-prefix.h	\
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
	sipe-nls.h \
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
	uuid.h \
	uuid.c

if SIP_SEC_KRB5
libsipe_la_SOURCES +=  \
	sip-sec-krb5.h \
	sip-sec-krb5.c
endif

AM_CFLAGS = $(st)

libsipe_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(PURPLE_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(KRB5_CFLAGS) \
	-DPURPLE_PLUGINS

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined \
	$(KRB5_LDFLAGS)

libsipe_la_LIBADD = \
        $(GLIB_LIBS) \
	$(PURPLE_LIBS) \
	$(KRB5_LIBS)

tests: tests.c .libs/libsipe.so
	set -e; \
	$(CC) $(libsipe_la_CFLAGS) $^ -o $@; \
	LD_LIBRARY_PATH=.libs ./tests; \
	rm -f tests

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
