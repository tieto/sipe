dnl ###########################################################################
dnl # Configure paths for libpurple
dnl # Gary Kramlich 2005
dnl #
dnl # Based off of glib-2.0.m4 by Owen Taylor
dnl ###########################################################################

dnl ###########################################################################
dnl # AM_PATH_PURPLE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl #
dnl # Test for purple and define PURPLE_CFLAGS, PURPLE_LIBS, PURPLE_DATADIR, and
dnl # PURPLE_LIBDIR
dnl ###########################################################################
AC_DEFUN([AM_PATH_PURPLE],
[dnl
	AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

	no_purple=""

	if test x"$PKG_CONFIG" != x"no" ; then
		if $PKG_CONFIG --atleast-pkgconfig-version 0.7 ; then
			:
		else
			echo "*** pkg-config is too old;  version 0.7 or newer is required."
			no_purple="yes"
			PKG_CONFIG="no"
		fi
	else
		no_purple="yes"
	fi

	min_version=ifelse([$1], ,2.0.0,$1)
	found_version=""

	AC_MSG_CHECKING(for purple - version >= $min_version)

	if test x"$no_purple" = x"" ; then
		PURPLE_DATADIR=`$PKG_CONFIG --variable=datadir purple`
		PURPLE_LIBDIR=`$PKG_CONFIG --variable=libdir purple`

		PURPLE_CFLAGS=`$PKG_CONFIG --cflags purple`
		PURPLE_LIBS=`$PKG_CONFIG --libs purple`

		purple_version=`$PKG_CONFIG --modversion purple`
		purple_major_version=`echo $purple_version | cut -d. -f 1`
		purple_minor_version=`echo $purple_version | cut -d. -f 2`

		dnl # stash the micro version in a temp variable.  Then stash
		dnl # the numeric for it in purple_micro_version and anything
		dnl # else in purple_extra_version.
		purple_micro_version_temp=`echo $purple_version | cut -d. -f 3`
		purple_micro_version=`echo $purple_micro_version_temp | sed 's/[[^0-9]]//g'`
		purple_extra_version=`echo $purple_micro_version_temp | sed 's/[[0-9]]//g'`

		dnl # get the major, minor, and macro that the user gave us
		min_major_version=`echo $min_version | cut -d. -f 1`
		min_minor_version=`echo $min_version | cut -d. -f 2`
		min_micro_version=`echo $min_version | cut -d. -f 3`

		dnl # check the users version against the version from pkg-config
		if test $purple_major_version -eq $min_major_version -a \
			$purple_minor_version -ge $min_minor_version -a \
			$purple_micro_version -ge $min_micro_version
		then
			:
		else
			no_purple="yes"
			found_version="$purple_major_version.$purple_minor_version.$purple_micro_version$purple_extra_version"
		fi

		dnl # Do we want a compile test here?
	fi

	if test x"$no_purple" = x"" ; then
		AC_MSG_RESULT(yes (version $purple_major_version.$purple_minor_version.$purple_micro_version$purple_extra_version))
		ifelse([$2], , :, [$2])
	else
		AC_MSG_RESULT(no)
		if test x"$PKG_CONFIG" = x"no" ; then
			echo "*** A new enough version of pkg-config was not found."
			echo "*** See http://www.freedesktop.org/software/pkgconfig/"
		fi

		if test x"found_version" != x"" ; then
			echo "*** A new enough version of purple was not found."
			echo "*** You have version $found_version"
			echo "*** See http://pidgin.im/"
		fi

		PURPLE_CFLAGS=""
		PURPLE_LIBS=""
		PURPLE_DATADIR=""
		PURPLE_LIBDIR=""

		ifelse([$3], , :, [$3])
	fi

	AC_SUBST(PURPLE_CFLAGS)
	AC_SUBST(PURPLE_LIBS)
	AC_SUBST(PURPLE_DATADIR)
	AC_SUBST(PURPLE_LIBDIR)
])
