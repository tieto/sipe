dnl ensure recent enough version of Autoconf
AC_PREREQ([2.50])

dnl Use `VERSION' files to get version.
m4_define([SIPE_VERSION_DATA], m4_include([VERSION]))

dnl Strip off newline characters.
m4_define([SIPE_VERSION],
          m4_substr(SIPE_VERSION_DATA,
                    [0], m4_decr(m4_len(SIPE_VERSION_DATA))))

dnl initialize package name, version, bugtracker & homepage
AC_INIT([pidgin-sipe], SIPE_VERSION,
	[http://sourceforge.net/tracker/?group_id=194563], [],
	[http://sipe.sourceforge.net/])

dnl setup automake and require recent enough version
AM_INIT_AUTOMAKE([1.9 dist-bzip2 no-define tar-ustar])

dnl set programming language
AC_LANG(C)
AC_HEADER_STDC

dnl setup shared library generation
LT_INIT([disable-static])

dnl checks for tools
IT_PROG_INTLTOOL([0.35.0])
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl checks for library functions
AC_CHECK_FUNCS([setenv unsetenv])

dnl tell pkgconfig to look in the same prefix where we're installing this to,
dnl as that is likely where libpurple will be found if it is not in the default
dnl pkgconfig path
PREFIX=$ac_default_prefix
if test "$prefix" != "NONE"; then
	PREFIX=$prefix
fi

PKG_CONFIG_PATH="$PKG_CONFIG_PATH":"$PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH

dnl debug mode
AC_ARG_ENABLE(debug,
	[AS_HELP_STRING([--enable-debug],
			[compile with debugging support [default=no]])],
	,
	enable_debug="no")

if test "$enable_debug" = yes; then
   AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])
fi

DEBUG_CFLAGS="${DEBUG_CFLAGS}"
AC_SUBST(DEBUG_CFLAGS)

dnl quality check mode
dnl For people who are interested in finding bugs and not hiding them
AC_ARG_ENABLE(quality-check,
	[AS_HELP_STRING([--enable-quality-check],
			[compile with compiler checks enabled [default=yes]])],
	,
	enable_quality_check="yes")

if test "$enable_quality_check" = yes; then
	QUALITY_CFLAGS="${QUALITY_CFLAGS} -Werror -Wall -Wextra"
else
	QUALITY_CFLAGS="${QUALITY_CFLAGS}"
fi
AC_SUBST(QUALITY_CFLAGS)

dnl Check for pkg-config before using it
PKG_PROG_PKG_CONFIG

AC_ARG_WITH([krb5],
	[AC_HELP_STRING([--with-krb5=PREFIX],
		[compile sipe plugin with Kerberos 5 support @<:@default=no@:>@])],
	[test "$withval" = "no" || kerberos="$withval"],
	[kerberos="no"])

dnl check for Kerberos
AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LDFLAGS)
AC_SUBST(KRB5_LIBS)

AM_CONDITIONAL(SIP_SEC_KRB5, test "$kerberos" != "no")
if test "$kerberos" != "no" ; then
        if test "$kerberos" != "yes" ; then
                KRB5_CFLAGS="-I${kerberos}/include"
                KRB5_LDFLAGS="-L${kerberos}/lib"
        fi
        orig_LDFLAGS="$LDFLAGS"
        LDFLAGS="$LDFLAGS $KRB5_LDFLAGS"
        AC_CHECK_LIB(krb5, krb5_rd_req,
                        [KRB5_LIBS="-lkrb5"],
                        [AC_CHECK_LIB(krb5, krb5_rd_req,
                                [KRB5_LIBS="-lkrb5"],
                                [AC_ERROR(Kerberos 5 libraries not found)],
                                )],
                        -lkrb5)
        AC_CHECK_LIB(gssapi_krb5, gss_krb5_export_lucid_sec_context,
                        [KRB5_LIBS="$KRB5_LIBS -lgssapi_krb5"],
                        [AC_CHECK_LIB(gssapi, gss_krb5_export_lucid_sec_context,
                                [KRB5_LIBS="$KRB5_LIBS -lgssapi_krb5"],
                                [AC_ERROR(GSSAPI libraries not found)],
                                )],
                        -lgssapi_krb5)
	savedLIBS="$LIBS"
	LIBS="$KRB5_LIBS $LIBS"
	AC_CHECK_FUNCS([krb5_get_error_message])
	LIBS="$savedLIBS"
	AC_DEFINE(HAVE_KERBEROS, 1, [Define if kerberos should be used in sipe.])
fi

dnl check for glib
PKG_CHECK_MODULES(GLIB, [glib-2.0])

dnl check for libxml2
PKG_CHECK_MODULES(LIBXML2, [libxml-2.0])

dnl assumption check: sizof(uuid_t) must be 16 (see uuid.c)
AC_MSG_CHECKING([that sizeof(uuid_t) is 16])
ac_save_CFLAGS=$CFLAGS
CFLAGS="$GLIB_CFLAGS -Werror -Wall -Wextra"
dnl note the [[[ quoting: our code contains []!
AC_RUN_IFELSE(
	AC_LANG_PROGRAM(
		[[[
#include <glib.h>
#include <stdio.h>

/* Copied from uuid.c */
typedef struct {
   guint32 time_low;
   guint16 time_mid;
   guint16 time_hi_and_version;
   guint8  clock_seq_hi_and_reserved;
   guint8  clock_seq_low;
   guint8  node[6];
} uuid_t;
		]]],
		[return(sizeof(uuid_t) == 16 ? 0 : 1);]),
	[AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(failed)
	 AC_ERROR(sizeof(uuid_t) is not 16

Please notify the SIPE developers and provide the following information:

 host:     $host
 build:    $build
 compiler: $CC
)])
CFLAGS=$ac_save_CFLAGS

dnl check for libpurple
purple="yes"
AC_ARG_WITH([purple],
	[AC_HELP_STRING([--with-purple],
		[compile sipe plugin for libpurple clients @<:@default=autodetect@:>@])],
	[test "$withval" = "yes" || purple="no"],
	[])
if test "$purple" != "no"; then
	PKG_CHECK_MODULES(PURPLE, [purple >= 2.4.0],
		[],
		[purple="no"])
fi

dnl support for libpurple plugin
AM_CONDITIONAL(SIPE_INCLUDE_PURPLE, test "$purple" != "no")
if test "$purple" != "no"; then

	dnl unfortunately PURPLE_MAJOR_VERSION is not exported by purple.m4
	PURPLE_MAJOR_VERSION=`$PKG_CONFIG --modversion purple | cut -d. -f 1`
	AC_SUBST(PURPLE_MAJOR_VERSION)

	dnl let user now if he has a 32- and 64-bit header conflict...
	AC_MSG_CHECKING([for 32- and 64-bit header conflicts])
	ac_save_CFLAGS=$CFLAGS
	CFLAGS="$PURPLE_CFLAGS -Werror -Wall -Wextra"
	AC_COMPILE_IFELSE(
		AC_LANG_PROGRAM(
			[
#include <glib.h>
#include <cipher.h>

/* Compile some code that has caused trouble in the past */
void testfunc(unsigned long len)
{
  PurpleCipherContext *rc4 = NULL;
  purple_cipher_context_set_option(rc4, "key_len", GUINT_TO_POINTER(len));
}
			],
			[testfunc(16);]),
		[AC_MSG_RESULT(none)],
		[AC_MSG_RESULT(failed)
		 AC_ERROR(conflicts found.

Check that you have the correct glib/libpurple headers installed for
your architecture or set PURPLE_CFLAGS to override the system defaults.
)])
	CFLAGS=$ac_save_CFLAGS
fi

dnl check for telepathy
telepathy="yes"
AC_ARG_WITH([telepathy],
	[AC_HELP_STRING([--with-telepathy],
		[compile sipe plugin for telepathy clients @<:@default=autodetect@:>@])],
	[test "$withval" = "yes" || telepathy="no"],
	[])
if test "$telepathy" != "no"; then
	PKG_CHECK_MODULES(TELEPATHY, [telepathy-glib],
		[],
		[telepathy="no"])
fi

dnl support for telepathy plugin
AM_CONDITIONAL(SIPE_INCLUDE_TELEPATHY, test "$telepathy" != "no")
dnl NOTHING IMPLEMENTED YET!!!
dnl if test "$telepathy" != "no"; then
dnl fi

dnl sanity check
AS_IF([test "$purple" = "no" -a "$telepathy" = "no"],
	[AC_ERROR(at least one plugin must be selected

If you didn't use a --without option then please check that you have
the headers for the packages "purple" or "telepathy-glib" installed.
)],
	[])

dnl i18n
AC_MSG_CHECKING([locale_CPPFLAGS])
LOCALE_CPPFLAGS='-DLOCALEDIR=\"$(prefix)/$(DATADIRNAME)/locale\"'
AC_SUBST([LOCALE_CPPFLAGS])
AC_MSG_RESULT([$LOCALE_CPPFLAGS])
AM_GLIB_GNU_GETTEXT

dnl codeset
AM_LANGINFO_CODESET

dnl substitutions and generated files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	pixmaps/Makefile
	m4macros/Makefile
	po/Makefile.in
	pixmaps/16/Makefile
	pixmaps/22/Makefile
	pixmaps/48/Makefile
	src/Makefile
	src/core/Makefile
	src/api/Makefile
	src/purple/Makefile
	src/telepathy/Makefile
	])

dnl generate files
AC_OUTPUT()

dnl additional info for the user
echo
if test "$purple" != "no" ; then
	echo "Compiling libpurple plugin"
	echo "PURPLE_CFLAGS  : $PURPLE_CFLAGS"
	echo "PURPLE_LIBS    : $PURPLE_LIBS"
else
	echo "Skipping libpurple plugin"
fi

echo
if test "$telepathy" != "no" ; then
	echo "Compiling telepathy plugin"
	echo
	echo "NOTHING IMPLEMENTED YET!!!"
	echo
	echo "TELEPATHY_CFLAGS: $TELEPATHY_CFLAGS"
	echo "TELEPATHY_LIBS  : $TELEPATHY_LIBS"
else
	echo "Skipping telepathy plugin"
fi
if test "$kerberos" != "no" ; then
	echo
	echo "Compiling with kerberos 5 support"
	echo "KRB5_CFLAGS    : $KRB5_CFLAGS"
	echo "KRB5_LDFLAGS   : $KRB5_LDFLAGS"
	echo "KRB5_LIBS      : $KRB5_LIBS"
fi

if test "$enable_debug" != "no"; then
	echo
	echo "Compiling with debugging enabled"
	echo "DEBUG_CFLAGS   : $DEBUG_CFLAGS"
fi

if test -n "${QUALITY_CFLAGS}"; then
	echo
	echo "Compiling with compiler checks enabled"
	echo "QUALITY_CFLAGS : $QUALITY_CFLAGS"
fi

echo
echo "configure complete, now run 'make'"
echo

dnl The End.
