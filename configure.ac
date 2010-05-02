dnl ensure recent enough version of Autoconf
AC_PREREQ([2.50])

dnl Use `VERSION' files to get version.
m4_define([SIPE_VERSION_DATA], m4_include([VERSION]))

dnl Strip off newline characters.
m4_define([SIPE_VERSION],
          m4_substr(SIPE_VERSION_DATA,
                    [0], m4_decr(m4_len(SIPE_VERSION_DATA))))

dnl homepage
m4_define([SIPE_HOMEPAGE], [http://sipe.sourceforge.net/])

dnl initialize package name, version, bugtracker & homepage
AC_INIT([pidgin-sipe], SIPE_VERSION,
	[https://sourceforge.net/tracker/?atid=949931&group_id=194563], [],
	SIPE_HOMEPAGE)

dnl setup automake and require recent enough version
AM_INIT_AUTOMAKE([1.9 dist-bzip2 no-define tar-ustar])

dnl set PACKAGE_URL for autoconf < 2.64
AS_IF([test "x${PACKAGE_URL}" = x],
	[AC_MSG_NOTICE([set PACKAGE_URL for autoconf < 2.64])
	 AC_DEFINE(PACKAGE_URL, "SIPE_HOMEPAGE", [Define to the home page for this package.])
])

dnl set programming language
AC_LANG(C)
AM_PROG_CC_C_O
AC_HEADER_STDC

dnl setup shared library generation
LT_INIT([disable-static])

dnl checks for tools
IT_PROG_INTLTOOL([0.35.0])
AC_PROG_INSTALL
AC_PROG_RANLIB

dnl checks for header files
AC_CHECK_HEADERS([sys/sockio.h])

dnl checks for library functions
AC_CHECK_FUNCS([])

dnl tell pkgconfig to look in the same prefix where we're installing this to,
dnl as that is likely where libpurple will be found if it is not in the default
dnl pkgconfig path
PREFIX=$ac_default_prefix
AS_IF([test "x$prefix" != xNONE],
	[PREFIX=$prefix])

PKG_CONFIG_PATH="$PKG_CONFIG_PATH":"$PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH

dnl debug mode
AC_ARG_ENABLE(debug,
	[AS_HELP_STRING([--enable-debug],
			[compile with debugging support [default=no]])],
	[],
	[enable_debug=no])

AS_IF([test "x$enable_debug" = xyes],
	[AC_DEFINE(DEBUG, 1, [Define if debugging is enabled.])])
AC_SUBST(DEBUG_CFLAGS)

dnl quality check mode
dnl For people who are interested in finding bugs and not hiding them
AC_ARG_ENABLE(quality-check,
	[AS_HELP_STRING([--enable-quality-check],
			[compile with compiler checks enabled [default=yes]])],
	[],
	[enable_quality_check=yes])

AS_IF([test "x$enable_quality_check" = xyes],
	[QUALITY_CFLAGS="$QUALITY_CFLAGS -Werror -Wall"
	 ac_save_CFLAGS=$CFLAGS

	 dnl GCC >= 3.4
	 AC_MSG_CHECKING([if $CC supports -Wextra])
	 CFLAGS="$QUALITY_CFLAGS -Wextra"
	 AC_COMPILE_IFELSE(
		AC_LANG_PROGRAM(),
		[AC_MSG_RESULT(yes)
		 QUALITY_CFLAGS="$QUALITY_CFLAGS -Wextra"],
		[AC_MSG_RESULT(no)]
	 )

	 dnl declaration-after-statement (ISO C90 behaviour, as on Windows & GCC < 3)
	 AC_MSG_CHECKING([if $CC supports -Werror=declaration-after-statement])
	 CFLAGS="$QUALITY_CFLAGS -Werror=declaration-after-statement"
	 AC_COMPILE_IFELSE(
		AC_LANG_PROGRAM(),
		[AC_MSG_RESULT(yes)
		 QUALITY_CFLAGS="$QUALITY_CFLAGS -Werror=declaration-after-statement"],
		[AC_MSG_RESULT(no)]
	 )
	 CFLAGS=$ac_save_CFLAGS])
AC_SUBST(QUALITY_CFLAGS)

dnl Check for pkg-config before using it
PKG_PROG_PKG_CONFIG

dnl build option: with voice & video support (for all backends)
AC_ARG_WITH(vv,
	[AC_HELP_STRING([--with-vv],
		[compile with voice and video support @<:@default=check@:>@])],
	[AS_IF([test "x$withval" = xyes], [with_vv=check])],
	[with_vv=check])

dnl check for Kerberos 5 support
AC_ARG_WITH([krb5],
	[AC_HELP_STRING([--with-krb5],
		[compile with Kerberos 5 support @<:@default=check@:>@])],
	[AS_IF([test "x$withval" = xyes], [with_krb5=check])],
	[with_krb5=check])

AS_IF([test "x$with_krb5" = xno], [], dnl disabled by user
      [test "x$with_krb5" = xcheck],  dnl autodetect with krb5-config
	[AC_MSG_CHECKING(if Kerberos 5 is available)
	 AS_IF([AC_RUN_LOG([krb5-config --version])],
		[KRB5_CFLAGS=`krb5-config --cflags 2>/dev/null`
		 KRB5_LDFLAGS=""

		 dnl same as AC_CHECK_LIB()
		 LIBS="$LIBS `krb5-config --libs gssapi 2>/dev/null`"
		 AC_DEFINE(HAVE_LIBKRB5, 1, [Define to 1 if you have the `krb5' library (-lkrb5)])],
		[AC_MSG_RESULT(no)
		 with_krb5=no])],
      [                               dnl path specified by user
	KRB5_CFLAGS="-I${with_krb5}/include"
	KRB5_LDFLAGS="-L${with_krb5}/lib"
	ac_save_LDFLAGS="$LDLAGS"
	LDFLAGS="$LDFLAGS $KRB5_LDFLAGS"
	AC_CHECK_LIB(krb5, krb5_rd_req,          [],
		[AC_CHECK_LIB(krb5, krb5_rd_req, [],
			[AC_ERROR(Kerberos 5 libraries not found)])])
	AC_CHECK_LIB(gssapi_krb5, gss_krb5_export_lucid_sec_context, [],
			[AC_ERROR(GSSAPI Kerberos 5 libraries not found)])
	LDFLAGS="$ac_save_LDFLAGS"])
AM_CONDITIONAL(SIP_SEC_KRB5, [test "x$with_krb5" != xno])
AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LDFLAGS)

dnl check for glib
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.12.0])
PKG_CHECK_MODULES(GMODULE, [gmodule-2.0 >= 2.12.0])

dnl check for gmime
dnl See also: https://bugzilla.gnome.org/show_bug.cgi?id=613653#c8
PKG_CHECK_MODULES(GMIME, [gmime-2.6 >= 2.5.2],
	[ac_have_gmime=yes],
	[PKG_CHECK_MODULES(GMIME, [gmime-2.4 >= 2.4.16],
		[ac_have_gmime=yes],
		[ac_have_gmime=no])
])
AM_CONDITIONAL(SIPE_MIME_GMIME, [test "x$ac_have_gmime" = xyes])
AS_IF([test "x$ac_have_gmime" = xyes],
	[AC_DEFINE(HAVE_GMIME, 1, [Define if gmime should be used in sipe.])])

dnl check for NSS
PKG_CHECK_MODULES(NSS, [nss],
	[ac_have_nss=yes],
	[PKG_CHECK_MODULES(NSS, [mozilla-nss],
		[ac_have_nss=yes],
		[PKG_CHECK_MODULES(NSS, [microb-engine-nss],
			[ac_have_nss=yes],
			[ac_have_nss=no])
	])
])
AM_CONDITIONAL(SIPE_CRYPTO_NSS, [test "x$ac_have_nss" = xyes])
AS_IF([test "x$ac_have_nss" = xyes],
	[AC_DEFINE(HAVE_NSS, 1, [Define if nss should be used in sipe.])])

dnl check for libxml2
PKG_CHECK_MODULES(LIBXML2, [libxml-2.0])

dnl assumption check: sizof(uuid_t) must be 16 (see uuid.c)
AC_MSG_CHECKING([that sizeof(uuid_t) is 16])
ac_save_CFLAGS=$CFLAGS
CFLAGS="$GLIB_CFLAGS $QUALITY_CFLAGS"
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
	[AC_MSG_FAILURE([sizeof(uuid_t) is not 16

Please notify the SIPE developers and provide the following information:

 host:     $host
 build:    $build
 compiler: $CC
])])
CFLAGS=$ac_save_CFLAGS

dnl build option: purple backend
AC_ARG_ENABLE([purple],
	[AC_HELP_STRING([--enable-purple], [build purple plugin @<:@default=yes@:>@])],
	[],
	[enable_purple=yes])
with_purple_vv=no
AS_IF([test "x$enable_purple" != xno],
	[PKG_CHECK_MODULES(PURPLE, [purple >= 2.4.0],
		[dnl unfortunately PURPLE_MAJOR_VERSION is not exported by purple.m4
		 PURPLE_MAJOR_VERSION=`$PKG_CONFIG --modversion purple | cut -d. -f 1`
		 AC_SUBST(PURPLE_MAJOR_VERSION)

		 dnl let user now if he has a 32- and 64-bit header conflict...
		 AC_MSG_CHECKING([for 32- and 64-bit header conflicts])
		 ac_save_CFLAGS=$CFLAGS
		 CFLAGS="$PURPLE_CFLAGS $QUALITY_CFLAGS"
		 AC_COMPILE_IFELSE(
			AC_LANG_PROGRAM([
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
			[AC_MSG_FAILURE([conflicts found.

Check that you have the correct glib/libpurple headers installed for
your architecture or set PURPLE_CFLAGS to override the system defaults.
])
			])

		 dnl purple SSL support is mandatory
		 AC_MSG_CHECKING([for purple SSL support])
		 ac_save_LIBS=$LIBS
		 LIBS="$PURPLE_LIBS"
		 AC_RUN_IFELSE(
			AC_LANG_PROGRAM([
#include <glib.h>
#include <plugin.h>
#include <sslconn.h>
],
					[
	purple_plugins_init();
	purple_plugins_probe(G_MODULE_SUFFIX);
	purple_ssl_init();
	return(purple_ssl_is_supported()?0:1);
					]),
			[AC_MSG_RESULT(ok)],
			[AC_MSG_FAILURE([your purple hasn't been compiled with SSL support.
])
			])

		 dnl check whether enable voice and video support
		 AS_IF([test "x$with_vv" = xno], [], dnl disabled by user
		       [test "x$with_vv" = xcheck],  dnl autodetect
			 [AC_MSG_CHECKING(for purple voice and video support)
			  AC_RUN_IFELSE(
				AC_LANG_PROGRAM(
					[[[
#include <libpurple/media.h>
					]]],
					[return (purple_media_get_type() == G_TYPE_NONE ? 1 : 0);]
			  	),
				[AC_MSG_RESULT(ok)
				 PKG_CHECK_MODULES(NICE, [nice >= 0.0.11],
					[with_purple_vv=yes],
                                        [AC_MSG_NOTICE(libnice required: disabling purple voice and video support)])],
				[AC_MSG_RESULT(no - your purple hasn't been compiled with voice and video support.)])
			 ])
		 CFLAGS=$ac_save_CFLAGS
		 LIBS=$ac_save_LIBS],
		[enable_purple=no])])
AM_CONDITIONAL(SIPE_INCLUDE_PURPLE, [test "x$enable_purple" != xno])

dnl check if libnice has compatibility patch for OC2007R2
AS_IF([test x$with_purple_vv = xyes],
	ac_save_LIBS=$LIBS
	ac_save_CFLAGS=$CFLAGS
	LIBS="$NICE_LIBS"
	CFLAGS="$NICE_CFLAGS"

	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <agent.h>]],[[return NICE_COMPATIBILITY_OC2007R2]])],
		AC_DEFINE(NICE_HAS_COMPATIBILITY, 1, [Define if libnice is compatible with Office Communicator]),
		[])

	CFLAGS=$ac_save_CFLAGS
	LIBS=$ac_save_LIBS,
	[]
)

dnl build option: telepathy backend
AC_ARG_ENABLE([telepathy],
	[AC_HELP_STRING([--enable-telepathy], [build telepathy plugin @<:@default=yes@:>@])],
	[],
	[enable_telepathy=yes])
AS_IF([test "x$enable_telepathy" != xno],
	[PKG_CHECK_MODULES(TELEPATHY, [telepathy-glib],
		[dnl GMIME is a build requirement
		 AS_IF([test "x$ac_have_gmime" = xyes],
			[],
			[AC_ERROR(GMIME package is required for telepathy plugin)])

		 dnl NSS is a build requirement
		 AS_IF([test "x$ac_have_nss" = xyes],
			[],
			[AC_ERROR(NSS package is required for telepathy plugin)])

		 dnl NOTHING IMPLEMENTED YET!!!
		],
		[enable_telepathy=no])])
AM_CONDITIONAL(SIPE_INCLUDE_TELEPATHY, [test "x$enable_telepathy" != xno])

dnl build option: kopete backend
AC_ARG_ENABLE([kopete],
	[AC_HELP_STRING([--enable-kopete], [build kopete plugin @<:@default=no@:>@])],
	[],
	[enable_kopete=no])
AS_IF([test "x$enable_kopete" != xno],
	[dnl GMIME is a build requirement
	 AS_IF([test "x$ac_have_gmime" = xyes],
		[],
		[AC_ERROR(GMIME package is required for kopete plugin)])

	 dnl NSS is a build requirement
	 AS_IF([test "x$ac_have_nss" = xyes],
		[],
		[AC_ERROR(NSS package is required for kopete plugin)])

	 dnl NOTHING IMPLEMENTED YET!!!
	],
	[enable_kopete=no])
AM_CONDITIONAL(SIPE_INCLUDE_KOPETE, [test "x$enable_kopete" != xno])

dnl sanity check
AS_IF([test "x$enable_purple" = xno -a "x$enable_telepathy" = xno -a "x$enable_kopete" = xno],
	[AC_ERROR(at least one plugin must be selected

If you didn't use a --enable option then please check that you have
the headers for the packages "purple" or "telepathy-glib" installed.
)],
	[])

dnl enable voice & video support if any backend supports it
AS_IF([test "x$with_purple_vv" != xno],
	[AC_DEFINE(HAVE_VV, 1, [Define if voice & video is enabled.])])
AM_CONDITIONAL(SIPE_WITH_VV, [test "x$with_purple_vv" != xno])

dnl i18n
AC_MSG_CHECKING([locale_CPPFLAGS])
LOCALE_CPPFLAGS='-DLOCALEDIR=\"$(prefix)/$(DATADIRNAME)/locale\"'
AC_SUBST([LOCALE_CPPFLAGS])
AC_MSG_RESULT([$LOCALE_CPPFLAGS])
AM_GLIB_GNU_GETTEXT
AC_SUBST(GETTEXT_PACKAGE, "${PACKAGE_NAME}")

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
	pixmaps/scalable/Makefile
	src/Makefile
	src/core/Makefile
	src/api/Makefile
	src/purple/Makefile
	src/telepathy/Makefile
	src/kopete/Makefile
	])

dnl generate files
AC_OUTPUT()

dnl additional info for the user
AS_ECHO()
AS_IF([test "x$enable_purple" = xno], 
	[AS_ECHO("Not building purple plugin")],
	[AS_ECHO("Build purple plugin")
	 AS_ECHO("PURPLE_CFLAGS  : $PURPLE_CFLAGS")
	 AS_ECHO("PURPLE_LIBS    : $PURPLE_LIBS")
	 AS_IF([test "x$with_purple_vv" = xno],
	  [AS_ECHO("Voice and video: disabled")],
	  [AS_ECHO("Voice and video: enabled")])
	])
AS_ECHO()
AS_IF([test "x$enable_telepathy" = xno],
	[AS_ECHO("Not building telepathy plugin")],
	[AS_ECHO("Build telepathy plugin")
	 AS_ECHO()
	 AS_ECHO("NOTHING IMPLEMENTED YET!!!")
	 AS_ECHO()
	 AS_ECHO("TELEPATHY_CFLAGS: $TELEPATHY_CFLAGS")
	 AS_ECHO("TELEPATHY_LIBS  : $TELEPATHY_LIBS")])
AS_ECHO()
AS_IF([test "x$enable_kopete" = xno],
	[AS_ECHO("Not building kopete plugin")],
	[AS_ECHO("Build kopete plugin")
	 AS_ECHO()
	 AS_ECHO("NOTHING IMPLEMENTED YET!!!")
	 AS_ECHO()])
AS_ECHO()
AS_IF([test "x$with_krb5" = xno],
	[AS_ECHO("Not building with Kerberos 5 support")],
	[AS_ECHO("Build with Kerberos 5 support")
	 AS_ECHO("KRB5_CFLAGS    : $KRB5_CFLAGS")
	 AS_ECHO("KRB5_LDFLAGS   : $KRB5_LDFLAGS")])
AS_ECHO()
AS_IF([test "x$enable_debug" = xno],
	[AS_ECHO("Debugging not enabled")],
	[AS_ECHO("Build with debugging enabled")
	 AS_ECHO("DEBUG_CFLAGS   : $DEBUG_CFLAGS")])
AS_ECHO()
AS_IF([test "x$QUALITY_CFLAGS" = x],
	[AS_ECHO("Compiler checks disabled")],
	[AS_ECHO("Build with compiler checks enabled")
	 AS_ECHO("QUALITY_CFLAGS : $QUALITY_CFLAGS")])
AS_ECHO()
AS_ECHO("configure complete. Now run 'make'")
AS_ECHO()

dnl The End.
