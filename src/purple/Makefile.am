pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

pkg_LTLIBRARIES = libsipe.la

MAINTAINERCLEANFILES = \
	Makefile.in

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

tests: tests.c ../core/.libs/libsipecore.a
	set -e; \
	$(CC) $(libsipe_la_CFLAGS) $^ $(PURPLE_LIBS) -o $@; \
	./tests; \
	rm -f tests

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
