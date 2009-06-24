# version of this package
m4_define(pidgin_sipe_version,	1.5.0)

# lower and upper-bound versions of Pidgin
m4_define(pidgin_version_max,		2.0.0)

AC_INIT([pidgin-sipe], [1.5.0])

AC_PREREQ([2.50])
AM_INIT_AUTOMAKE([1.9 dist-bzip2 tar-ustar])

AC_DISABLE_STATIC

AC_PROG_CC
IT_PROG_INTLTOOL([0.35.0])
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_HEADER_STDC
AC_CHECK_HEADER([zlib.h], 
		[], 
		[AC_MSG_ERROR([You must have zlib.h and zlib installed])])



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

AC_ARG_WITH(krb5, [AC_HELP_STRING([--with-krb5=PREFIX], [compile sipe plugin with Kerberos 5 support])], kerberos="$withval", kerberos="no")

dnl #######################################################################
dnl # Check for Kerberos
dnl #######################################################################
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
	AC_DEFINE(USE_KERBEROS, 1, [Define if kerberos should be used in sipe.])
fi
AM_CONDITIONAL(SIP_SEC_KRB5, test "$kerberos" != "no")

# Check for Purple
PKG_CHECK_MODULES(PURPLE,
[purple >= pidgin_version_max],
[
	AC_DEFINE(HAVE_PIDGIN, 1, [Define if we've found pidgin.])
])

AC_SUBST(PURPLE_CFLAGS)
AC_SUBST(PURPLE_LIBS)

dnl Check for com_err
PKG_CHECK_MODULES(COM_ERR, [com_err],,)

dnl Check for inet_aton
AC_CHECK_FUNC(inet_aton, , [AC_CHECK_LIB(resolv, inet_aton, ,
                                         [AC_ERROR(inet_aton not found)])])

SIPE_LIBA=`$PKG_CONFIG sipe --variable=libarchive`
AC_SUBST(SIPE_LIBA)

AC_ARG_ENABLE(static-sipe,
        [  --enable-static-sipe  statically link in Simple Exchange],
	        sipe_static="yes", sipe_static="no")

AM_CONDITIONAL(SIPE_STATIC, test $sipe_static = yes)

AC_MSG_CHECKING([locale_CPPFLAGS])
LOCALE_CPPFLAGS='-DLOCALEDIR=\"$(prefix)/$(DATADIRNAME)/locale\"'
AC_SUBST([LOCALE_CPPFLAGS])
AC_MSG_RESULT([$LOCALE_CPPFLAGS])

dnl i18n
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

AC_OUTPUT()


echo
echo -n "Simple SIPE linking mode... : "
if test "$sipe_static" = "yes" ; then
   echo "static"
   echo "Simple SIPE library...      : $SIPE_LIBA"
else
   echo "dynamic"
fi

if test "$kerberos" != "no" ; then
echo
echo "Compiled with kerberos 5 support"
echo "LDFLAGS :$KRB5_LDFLAGS"
echo "CFLAGS  :$KRB5_CFLAGS"
echo "LIBS    :$KRB5_LIBS"
echo
fi
echo
echo configure complete, now run \`make\`
echo

# The End.
