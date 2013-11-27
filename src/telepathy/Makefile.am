SUBDIRS = data

MAINTAINERCLEANFILES = \
	Makefile.in

libexec_PROGRAMS = telepathy-sipe

telepathy_sipe_SOURCES = \
	telepathy-buddy.c \
	telepathy-connection.c \
	telepathy-debug.c \
	telepathy-dnsquery.c \
	telepathy-main.c \
	telepathy-private.h \
	telepathy-protocol.c \
	telepathy-schedule.c \
	telepathy-search.c \
	telepathy-status.c \
	telepathy-stubs.c \
	telepathy-tls.c \
	telepathy-transport.c

AM_CFLAGS = $(st)

telepathy_sipe_CFLAGS = \
	$(DEBUG_CFLAGS) \
	$(QUALITY_CFLAGS) \
	$(LOCALE_CPPFLAGS) \
	$(TELEPATHY_GLIB_CFLAGS) \
	$(DBUS_GLIB_CFLAGS) \
	$(GIO_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I$(srcdir)/../api

telepathy_sipe_LDADD = \
	../core/libsipe_core.la \
	../core/libsipe_core_crypto.la \
	../core/libsipe_core_libxml2.la \
	../core/libsipe_core_mime.la \
	$(GMIME_LIBS) \
	$(LIBXML2_LIBS) \
	$(NSS_LIBS) \
	$(OPENSSL_LIBS) \
	$(TELEPATHY_GLIB_LIBS) \
	$(DBUS_GLIB_LIBS) \
	$(GIO_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)
