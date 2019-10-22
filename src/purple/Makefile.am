pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

noinst_LTLIBRARIES = libsipe_backend.la

pkg_LTLIBRARIES = libsipe.la

EXTRA_DIST = \
	pidgin-sipe.metainfo.xml

MAINTAINERCLEANFILES = \
	Makefile.in

libsipe_backend_la_SOURCES = \
	purple-private.h \
	purple-buddy.c \
	purple-chat.c \
	purple-connection.c \
	purple-debug.c \
	purple-dnsquery.c \
	purple-ft.c \
	purple-groupchat.c \
	purple-im.c \
	purple-markup.c \
	purple-network.c \
	purple-notify.c \
	purple-schedule.c \
	purple-search.c \
	purple-setting.c \
	purple-status.c \
	purple-transport.c \
	purple-user.c

libsipe_la_SOURCES = \
	purple-plugin-common.c

if SIPE_PURPLE3
libsipe_la_SOURCES += purple-plugin3.c
else
libsipe_la_SOURCES += purple-plugin.c
endif

AM_CFLAGS = $(st)

libsipe_backend_la_CFLAGS = \
	$(DEBUG_CFLAGS) \
	$(QUALITY_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(PURPLE_CFLAGS) \
	-I$(srcdir)/../api

if !SIPE_OS_WIN32
libsipe_backend_la_CFLAGS += \
        $(LOCALE_CPPFLAGS)
endif

libsipe_la_CFLAGS = $(libsipe_backend_la_CFLAGS)

libsipe_la_LDFLAGS = \
	-module -avoid-version -no-undefined \
	$(ADDITIONAL_LDFLAGS)

libsipe_la_LIBADD = \
	../core/libsipe_core.la \
	../core/libsipe_core_crypto.la \
	../core/libsipe_core_libxml2.la \
	libsipe_backend.la \
	$(DBUS_LIBS) \
	$(LIBXML2_LIBS) \
	$(NSS_LIBS) \
	$(OPENSSL_LIBS) \
	$(GLIB_LIBS) \
	$(PURPLE_LIBS)

if SIPE_OS_WIN32
libsipe_la_CFLAGS += -DHAVE_SSPI=1
libsipe_la_LIBADD += -lws2_32 -lsecur32
endif

if SIP_SEC_GSSAPI
libsipe_la_LIBADD += $(KRB5_LDFLAGS)
endif

check_PROGRAMS = tests_load
tests_load_SOURCES = tests-load.c
tests_load_CFLAGS  = $(GMODULE_CFLAGS)
tests_load_LDADD   = $(GMODULE_LIBS)

if !SIPE_OS_WIN32
if !SIP_SEC_GSSAPI_ONLY
check_PROGRAMS += tests
tests_SOURCES   = tests.c
tests_CFLAGS    = $(libsipe_la_CFLAGS)
tests_LDADD     = \
	../core/libsipe_core_tests.la \
	../core/libsipe_core_crypto.la \
	libsipe_backend.la \
	$(NSS_LIBS) \
	$(OPENSSL_LIBS) \
	$(PURPLE_LIBS)
endif
endif

# D-Bus functionality no longer available in 3.x.x API
if !SIPE_PURPLE3
if SIPE_DBUS
libsipe_backend_la_SOURCES += \
	purple-dbus.c \
	purple-dbus.h \
	purple-dbus-bindings.c
endif
endif

if SIPE_MIME_GMIME
libsipe_la_LIBADD += \
	../core/libsipe_core_mime.la \
	$(GMIME_LIBS)
if !SIPE_OS_WIN32
if !SIP_SEC_GSSAPI_ONLY
tests_LDADD       += \
	../core/libsipe_core_mime.la \
	$(GMIME_LIBS)
endif
endif
else
libsipe_backend_la_SOURCES += purple-mime.c
endif

if SIPE_WITH_VV
noinst_LTLIBRARIES            += libsipe_backend_vv.la
libsipe_backend_vv_la_SOURCES  = purple-media.c
libsipe_backend_vv_la_CFLAGS   = \
	$(libsipe_backend_la_CFLAGS) \
	$(NICE_CFLAGS) \
	$(GSTREAMER_CFLAGS) \
	$(FARSTREAM_CFLAGS)
libsipe_la_LIBADD             += \
	libsipe_backend_vv.la \
	$(NICE_LIBS) \
	$(GSTREAMER_LIBS) \
	$(FARSTREAM_LIBS)

if SIPE_HAVE_APPSHARE_SERVER
libsipe_la_LIBADD             += \
	$(FREERDP_SHADOW_LIBS)
endif
endif

TESTS = $(check_PROGRAMS)

# Remove any libsipe.so from the old incorrect installation location
install-exec-local:
	rm -f $(DESTDIR)$(libdir)/pidgin/libsipe.so

desktopdir = $(datadir)/applications
desktop_DATA = sipe-url-handler.desktop

bin_SCRIPTS = sipe-url-handler

if SIPE_WITH_APPSTREAM
pidginmetainfofiledir   = $(datadir)/metainfo
pidginmetainfofile_DATA = pidgin-sipe.metainfo.xml

check: validate-metainfo

.PHONY: validate-metainfo
validate-metainfo: $(pidginmetainfofile_DATA)
	appstreamcli validate --pedantic --nonet $< || \
	appstreamcli validate --pedantic         $< || \
	appstream-validate                       $<
endif
