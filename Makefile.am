EXTRA_DIST = LICENSE

SUBDIRS = src pixmaps m4macros

CLEANFILES = \
	intltool-extract \
	intltool-update \
	intltool-merge

MAINTAINERCLEANFILES = \
	compile \
	INSTALL \
	config.h.in \
	aclocal.m4 \
	ltmain.sh \
	Makefile.in \
	depcomp \
	missing \
	install-sh \
	configure \
	config.sub \
	config.guess \
	intltool-extract.in \
	intltool-merge.in   \
	intltool-update.in  \
	mkinstalldirs

tests:
	pushd src; make tests; popd;
