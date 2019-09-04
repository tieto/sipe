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
	po/Makefile.mingw

CLEANFILES = \
	intltool-extract \
	intltool-update \
	intltool-merge

MAINTAINERCLEANFILES = \
	aclocal.m4 \
	ABOUT-NLS \
	compile \
	configure \
	config.guess \
	config.h.in \
	config.rpath \
	config.sub \
	depcomp \
	GITVERSION \
	INSTALL \
	install-sh \
	intltool-extract.in \
	intltool-merge.in   \
	intltool-update.in  \
	ltmain.sh \
	Makefile.in \
	missing \
	mkinstalldirs \
	po/Makevars.template \
	po/Rules-quot \
	po/*.header \
	po/*.sed \
	po/*.sin \
	test-driver \
	ylwrap

maintainer-clean-local:
	-rm -rf m4

ACLOCAL_AMFLAGS = -I m4
