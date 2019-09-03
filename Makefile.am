SUBDIRS = src pixmaps po

EXTRA_DIST = \
	contrib \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	pidgin-sipe.nsi \
	pidgin-sipe.wxs \
	siplcs.vcxproj \
	siplcs.vcxproj.filters \
	Makefile.mingw \
	po/Makefile.mingw \
	HACKING

CLEANFILES = \
	intltool-extract \
	intltool-update \
	intltool-merge

MAINTAINERCLEANFILES = \
	compile \
	GITVERSION \
	INSTALL \
	aclocal.m4 \
	ltmain.sh \
	Makefile.in \
	depcomp \
	missing \
	install-sh \
	configure \
	config.sub \
	config.guess \
	config.h.in \
	intltool-extract.in \
	intltool-merge.in   \
	intltool-update.in  \
	mkinstalldirs \
	test-driver \
	ylwrap

maintainer-clean-local:
	-rm -rf m4

ACLOCAL_AMFLAGS = -I m4
