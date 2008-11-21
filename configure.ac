# version of this package
m4_define(pidgin_sipe_version,	1.2.0)

# lower and upper-bound versions of Pidgin
m4_define(pidgin_version_max,		2.0.0)

AC_INIT([pidgin-sipe], [1.2.0])

AC_PREREQ([2.50])
AM_INIT_AUTOMAKE([1.9 dist-bzip2 tar-ustar])

AC_DISABLE_STATIC

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
LIBTOOL="$LIBTOOL --silent"

AC_HEADER_STDC

GAIM_MIN=pidgin_version_min
GAIM_MAX=pidgin_version_max
AC_SUBST(PIDGIN_MIN)
AC_SUBST(PIDGIN_MAX)

# tell pkgconfig to look in the same prefix we're installing this to,
# as that's likely where gaim will be found if it's not in the default
# pkgconfig path
PREFIX=$ac_default_prefix
if test "$prefix" != "NONE"; then
   PREFIX=$prefix
fi

PKG_CONFIG_PATH="$PKG_CONFIG_PATH":"$PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH

# debug mode
AC_ARG_ENABLE(debug,
	[  --enable-debug	  compile with debugging support],,
	enable_debug=no)

if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi

# Check for Pidgin
PKG_CHECK_MODULES(libpurple,
[pidgin >= pidgin_version_max],
[
	AC_DEFINE(HAVE_PIDGIN, 1, [Define if we've found pidgin.])
])

PIDGIN_CFLAGS=`$PKG_CONFIG --cflags purple`
PIDGIN_LIBS=`$PKG_CONFIG --libs purple`

AC_SUBST(PIDGIN_CFLAGS)
AC_SUBST(PIDGIN_LIBS)

dnl Check for inet_aton
AC_CHECK_FUNC(inet_aton, , [AC_CHECK_LIB(resolv, inet_aton, ,
                                         [AC_ERROR(inet_aton not found)])])

SIPE_LIBA=`$PKG_CONFIG sipe --variable=libarchive`
AC_SUBST(SIPE_LIBA)

AC_ARG_ENABLE(static-sipe,
        [  --enable-static-sipe  statically link in Simple Exchange],
	        sipe_static="yes", sipe_static="no")

AM_CONDITIONAL(SIPE_STATIC, test $sipe_static = yes)

# substitutions and generated files
AC_CONFIG_FILES(
	[src/config.h]
	[Makefile 
	pixmaps/Makefile 
	m4macros/Makefile
	pixmaps/16/Makefile 
	pixmaps/22/Makefile 
	pixmaps/48/Makefile 
	src/Makefile]
)

AC_OUTPUT()


echo
echo -n "Simple Exchange linking mode... : "
if test "$sipe_static" = "yes" ; then
   echo "static"
   echo "Simple Exchange library...      : $SIPE_LIBA"
else
   echo "dynamic"
fi

echo
echo configure complete, now run \`make\`
echo

# The End.
