pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	core-depurple.h

libsipe_la_SOURCES = \
	purple-debug.c \
	purple-plugin.c

AM_CFLAGS = $(st)

libsipe_la_CFLAGS = \
        $(DEBUG_CFLAGS) \
        $(QUALITY_CFLAGS) \
        $(LIBXML2_CFLAGS) \
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/../api \
	-I$(srcdir)/../core

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined \
	$(KRB5_LDFLAGS)

libsipe_la_LIBADD = \
	../core/libsipecore.la \
        $(LIBXML2_LIBS) \
        $(GLIB_LIBS) \
	$(KRB5_LIBS) \
	$(PURPLE_LIBS)

check_PROGRAMS = tests
tests_SOURCES = tests.c
tests_CFLAGS = $(libsipe_la_CFLAGS)
tests_LDADD = ../core/libsipecore.la
tests_LDFLAGS = $(PURPLE_LIBS)

TESTS = $(check_PROGRAMS)

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
