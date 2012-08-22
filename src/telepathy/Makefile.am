MAINTAINERCLEANFILES = \
	Makefile.in

libexec_PROGRAMS = telepathy-sipe

telepathy_sipe_SOURCES = \
	telepathy-main.c

AM_CFLAGS = $(st)

telepathy_sipe_CFLAGS = \
	$(DEBUG_CFLAGS) \
	$(QUALITY_CFLAGS) \
	$(TELEPATHY_GLIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I$(srcdir)/../api

telepathy_sipe_LDADD = \
	$(TELEPATHY_GLIB_LIBS) \
	$(GLIB_LIBS)
