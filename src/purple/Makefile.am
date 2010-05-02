pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

noinst_LTLIBRARIES = libsipe_backend.la

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_backend_la_SOURCES = \
	purple-private.h \
	purple-connection.c \
	purple-debug.c \
	purple-dnsquery.c \
	purple-markup.c \
	purple-network.c \
	purple-schedule.c \
	purple-setting.c \
	purple-transport.c

libsipe_la_SOURCES = \
	purple-plugin.c

AM_CFLAGS = $(st)

libsipe_backend_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/../api

libsipe_la_CFLAGS = $(libsipe_backend_la_CFLAGS)

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined

libsipe_la_LIBADD = \
	../core/libsipe_core.la \
	../core/libsipe_core_purple.la \
	libsipe_backend.la \
        $(LIBXML2_LIBS) \
        $(GLIB_LIBS) \
	$(PURPLE_LIBS)

if SIP_SEC_KRB5
libsipe_la_LIBADD += $(KRB5_LDFLAGS)
endif

check_PROGRAMS = tests tests_load
tests_SOURCES  = tests.c
tests_CFLAGS   = $(libsipe_la_CFLAGS)
tests_LDADD    = \
	../core/libsipe_core_tests.la \
	../core/libsipe_core.la \
	libsipe_backend.la \
	$(PURPLE_LIBS)
tests_load_SOURCES = tests-load.c
tests_load_CFLAGS  = $(GMODULE_CFLAGS)
tests_load_LDADD   = $(GMODULE_LIBS)

if SIPE_MIME_GMIME
libsipe_la_LIBADD += $(GMIME_LIBS)
tests_LDADD       += $(GMIME_LIBS)
else
libsipe_backend_la_SOURCES += purple-mime.c
endif

if SIPE_CRYPTO_NSS
libsipe_la_LIBADD += $(NSS_LIBS)
tests_LDADD       += $(NSS_LIBS)
else
libsipe_backend_la_SOURCES += purple-crypt.c purple-digest.c
endif

if SIPE_WITH_VV
libsipe_backend_la_SOURCES += purple-media.c
libsipe_backend_la_CFLAGS  += $(NICE_CFLAGS)
libsipe_la_LIBADD          += $(NICE_LIBS)
endif

TESTS = $(check_PROGRAMS)

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
