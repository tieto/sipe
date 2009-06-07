
pkgdir = $(libdir)/pidgin

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_la_SOURCES = \
	sip-prefix.h	\
	sipkrb5.h	\
	sipkrb5.c	\
	sipmsg.c \
	sipmsg.h \
	sipe.h \
	sipe.c \
	sip-sec.h \
	sip-sec.c \
	sip-sec-mech.h \
	sip-sec-ntlm.h \
	sip-sec-ntlm.c \
	sipe-sign.h \
	sipe-sign.c \
	uuid.h \
	uuid.c

AM_CFLAGS = $(st) 

libsipe_la_CFLAGS = \
	-Werror \
        $(DEBUG_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(PURPLE_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(KRB5_CFLAGS)

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined \
	$(KRB5_LDFLAGS)

libsipe_la_LIBADD = \
        $(GLIB_LIBS) $(PURPLE_LIBS) $(KRB5_LIBS)


if SIPE_STATIC
libsipe_la_LIBADD += $(SIPE_LIBA)
else
libsipe_la_LIBADD += $(SIPE_LIBS)
endif

tests: tests.c $(libsipe_la_SOURCES)
	$(CC) $(libsipe_la_CFLAGS) $(libsipe_la_LIBADD) .libs/libsipe.so tests.c -o tests; \
	LD_LIBRARY_PATH=.libs ./tests; \
	rm tests;

AM_CPPFLAGS = \
	-DDATADIR=\"$(datadir)/pidgin\" \
	-DLIBDIR=\"$(libdir)/pidgin\" \
	-DPIDGIN_PLUGINS
