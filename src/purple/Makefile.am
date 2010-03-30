pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

noinst_LTLIBRARIES = libsipe_backend.la

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_backend_la_SOURCES = \
	purple-crypt.c \
	purple-debug.c \
	purple-digest.c \
	purple-markup.c \
	purple-network.c

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
libsipe_la_LDFLAGS += $(KRB5_LDFLAGS)
endif

check_PROGRAMS = tests
tests_SOURCES  = tests.c
tests_CFLAGS   = $(libsipe_la_CFLAGS)
tests_LDADD    = \
	../core/libsipe_core_tests.la \
	../core/libsipe_core.la \
	libsipe_backend.la
tests_LDFLAGS  = $(PURPLE_LIBS)

if SIPE_MIME_GMIME
libsipe_la_LIBADD  += $(GMIME_LIBS)
tests_LDFLAGS      += $(GMIME_LIBS)
else
libsipe_backend_la_SOURCES += purple-mime.c
endif

TESTS = $(check_PROGRAMS)

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
