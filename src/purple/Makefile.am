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
        $(GLIB_CFLAGS) \
        $(LOCALE_CPPFLAGS) \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/../api \
	-I$(srcdir)/../core

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined

libsipe_la_LIBADD = \
	../core/libsipe_core.la \
	../core/libsipe_core_purple.la \
        $(LIBXML2_LIBS) \
        $(GLIB_LIBS) \
	$(PURPLE_LIBS)

if SIP_SEC_KRB5
libsipe_la_LDFLAGS += $(KRB5_LDFLAGS)
libsipe_la_LIBADD  += $(KRB5_LIBS)
endif

check_PROGRAMS = tests
tests_SOURCES = tests.c
tests_CFLAGS = $(libsipe_la_CFLAGS)
tests_LDADD = ../core/libsipe_core.la ../core/libsipe_core_purple.la
tests_LDFLAGS = libsipe.la $(PURPLE_LIBS)

TESTS = $(check_PROGRAMS)

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so
