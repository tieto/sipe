SUBDIRS = data

MAINTAINERCLEANFILES = \
	Makefile.in

libexec_PROGRAMS = telepathy-sipe

telepathy_sipe_SOURCES = \
	telepathy-connection.c \
	telepathy-debug.c \
	telepathy-dnsquery.c \
	telepathy-main.c \
	telepathy-private.h \
	telepathy-protocol.c \
	telepathy-stubs.c \
	telepathy-transport.c

AM_CFLAGS = $(st)

telepathy_sipe_CFLAGS = \
	$(DEBUG_CFLAGS) \
	$(QUALITY_CFLAGS) \
	$(LOCALE_CPPFLAGS) \
	$(TELEPATHY_GLIB_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I$(srcdir)/../api

telepathy_sipe_LDADD = \
	../core/libsipe_core.la \
	../core/libsipe_core_crypto_nss.la \
	../core/libsipe_core_libxml2.la \
	../core/libsipe_core_mime.la \
	$(GMIME_LIBS) \
	$(LIBXML2_LIBS) \
	$(NSS_LIBS) \
	$(TELEPATHY_GLIB_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)
