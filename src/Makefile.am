
pkgdir = $(libdir)/pidgin

pkg_LTLIBRARIES = libsipe.la

libsipe_la_SOURCES = \
	sip-prefix.h	\
	sip-internal.h	\
	sip-ntlm.h	\
	sip-ntlm.c	\
	sipkrb5.h	\
	sipkrb5.c	\
	sipmsg.c \
	sipmsg.h \
	sipe.h \
	sipe.c \
	sipe-sign.h \
	sipe-sign.c \
	uuid.h \
	uuid.c

AM_CFLAGS = $(st) 

libsipe_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(PIDGIN_CFLAGS) \
	-I/usr/include/krb5 \
	-I/usr/include/gssapi

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined -lkrb5 -lgssapi_krb5

libsipe_la_LIBADD = \
        $(GLIB_LIBS) $(PIDGIN_LIBS)


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
