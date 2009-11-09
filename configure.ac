dnl Use `VERSION' files to get version.
m4_define([SIPE_VERSION_DATA], m4_include([VERSION]))

dnl Strip off newline characters.
m4_define([_SIPE_VERSION],
          m4_substr(SIPE_VERSION_DATA,
                    [0], m4_decr(m4_len(SIPE_VERSION_DATA))))

dnl version of this package
m4_define(pidgin_sipe_version, _SIPE_VERSION)

AC_INIT([pidgin-sipe], _SIPE_VERSION)
AC_DEFINE(SIPE_VERSION, "_SIPE_VERSION", [Define sipe version.])

AC_PREREQ([2.50])
AM_INIT_AUTOMAKE([1.9 dist-bzip2 tar-ustar])

AC_DISABLE_STATIC

AC_PROG_CC
IT_PROG_INTLTOOL([0.35.0])
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_HEADER_STDC

dnl tell pkgconfig to look in the same prefix we're installing this to,
dnl as that's likely where libpurple will be found if it's not in the default
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

AC_ARG_WITH(krb5, [AC_HELP_STRING([--with-krb5=PREFIX], [compile sipe plugin with Kerberos 5 support])], kerberos="$withval", kerberos="no")

dnl check for Kerberos
AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LDFLAGS)
AC_SUBST(KRB5_LIBS)

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
	AC_DEFINE(USE_KERBEROS, 1, [Define if kerberos should be used in sipe.])
fi
AM_CONDITIONAL(SIP_SEC_KRB5, test "$kerberos" != "no")

dnl check for libpurple
PKG_CHECK_MODULES(PURPLE, [purple >= 2.3.1],
	[AC_DEFINE(HAVE_PIDGIN, 1, [Define if we've found libpurple])])
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

dnl check for inet_aton
AC_CHECK_FUNC(inet_aton,,
	[AC_CHECK_LIB(resolv, inet_aton,, [AC_ERROR(inet_aton not found)])])

dnl static linking
SIPE_LIBA=`$PKG_CONFIG sipe --variable=libarchive`
AC_SUBST(SIPE_LIBA)

AC_ARG_ENABLE(static-sipe,
	[AS_HELP_STRING([--enable-static-sipe],
			[statically linked plugin [default=no]])],
	,
	sipe_static="no")

AM_CONDITIONAL(SIPE_STATIC, test $sipe_static = yes)

dnl i18n
AC_MSG_CHECKING([locale_CPPFLAGS])
LOCALE_CPPFLAGS='-DLOCALEDIR=\"$(prefix)/$(DATADIRNAME)/locale\"'
AC_SUBST([LOCALE_CPPFLAGS])
AC_MSG_RESULT([$LOCALE_CPPFLAGS])

GETTEXT_PACKAGE=$PACKAGE
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Gettext Package])
AM_GLIB_GNU_GETTEXT

dnl codeset
AM_LANGINFO_CODESET

dnl substitutions and generated files
AC_CONFIG_FILES(
	[src/config.h]
	[Makefile 
	pixmaps/Makefile 
	m4macros/Makefile
	po/Makefile.in
	pixmaps/16/Makefile 
	pixmaps/22/Makefile 
	pixmaps/48/Makefile 
	src/Makefile]
)

dnl generate files
AC_OUTPUT()

dnl additional info for the user
echo
echo -n "Simple SIPE linking mode : "
if test "$sipe_static" = "yes" ; then
	echo "static"
	echo "Simple SIPE library...      : $SIPE_LIBA"
else
	echo "dynamic"
fi

if test "$kerberos" != "no" ; then
	echo
	echo "Compiling with kerberos 5 support"
	echo "KRB5_LDFLAGS   : $KRB5_LDFLAGS"
	echo "KRB5_CFLAGS    : $KRB5_CFLAGS"
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
