/**
 * @file internal.h Internal definitions and includes
 * @ingroup core
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef _GAIM_INTERNAL_H_
#define _GAIM_INTERNAL_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/*
 * If we're using NLS, make sure gettext works.  If not, then define
 * dummy macros in place of the normal gettext macros.
 *
 * Also, the perl XS config.h file sometimes defines _  So we need to
 * make sure _ isn't already defined before trying to define it.
 *
 * The Singular/Plural/Number ngettext dummy definition below was
 * taken from an email to the texinfo mailing list by Manuel Guerrero.
 * Thank you Manuel, and thank you Alex's good friend Google.
 */
#ifdef ENABLE_NLS
#  include <locale.h>
#  include <libintl.h>
#  define _(String) ((const char *)gettext(String))
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  include <locale.h>
#  define N_(String) (String)
#  ifndef _
#    define _(String) ((const char *)String)
#  endif
#  define ngettext(Singular, Plural, Number) ((Number == 1) ? ((const char *)Singular) : ((const char *)Plural))
#endif

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

#define MSG_LEN 2048
/* The above should normally be the same as BUF_LEN,
 * but just so we're explicitly asking for the max message
 * length. */
#define BUF_LEN MSG_LEN
#define BUF_LONG BUF_LEN * 2

#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/time.h>
#include <sys/wait.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif

#ifdef GAIM_PLUGINS
# include <gmodule.h>
# ifndef _WIN32
#  include <dlfcn.h>
# endif
#endif

#ifndef _WIN32
# include <netinet/in.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <sys/un.h>
# include <sys/utsname.h>
# include <netdb.h>
# include <signal.h>
# include <unistd.h>
#endif

#ifndef MAXPATHLEN
# define MAXPATHLEN 1024
#endif

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 255
#endif

#define PATHSIZE 1024

#include <glib.h>
#if !GLIB_CHECK_VERSION(2,4,0)
#	define G_MAXUINT32 ((guint32) 0xffffffff)
#endif

#if GLIB_CHECK_VERSION(2,6,0)
#	include <glib/gstdio.h>
#endif

#if !GLIB_CHECK_VERSION(2,6,0)
#	define g_freopen freopen
#	define g_fopen fopen
#	define g_rmdir rmdir
#	define g_remove remove
#	define g_unlink unlink
#	define g_lstat lstat
#	define g_stat stat
#	define g_mkdir mkdir
#	define g_rename rename
#	define g_open open
#endif

#if !GLIB_CHECK_VERSION(2,8,0) && !defined _WIN32
#	define g_access access
#endif

#if !GLIB_CHECK_VERSION(2,10,0)
#	define g_slice_new(type) g_new(type, 1)
#	define g_slice_new0(type) g_new0(type, 1)
#	define g_slice_free(type, mem) g_free(mem)
#endif

#ifdef _WIN32
#include "win32dep.h"
#endif

/* ugly ugly ugly */
/* This is a workaround for the fact that G_GINT64_MODIFIER and G_GSIZE_FORMAT
 * are only defined in Glib >= 2.4 */
#ifndef G_GINT64_MODIFIER
#	if GLIB_SIZEOF_LONG == 8
#		define G_GINT64_MODIFIER "l"
#	else
#		define G_GINT64_MODIFIER "ll"
#	endif
#endif

#ifndef G_GSIZE_FORMAT
#	if GLIB_SIZEOF_LONG == 8
#		define G_GSIZE_FORMAT "lu"
#	else
#		define G_GSIZE_FORMAT "u"
#	endif
#endif

/* Safer ways to work with static buffers. When using non-static
 * buffers, either use g_strdup_* functions (preferred) or use
 * g_strlcpy/g_strlcpy directly. */
#define gaim_strlcpy(dest, src) g_strlcpy(dest, src, sizeof(dest))
#define gaim_strlcat(dest, src) g_strlcat(dest, src, sizeof(dest))

#define PURPLE_WEBSITE "http://pidgin.sf.im/"

#ifndef _WIN32
/* Everything needs to include this, because
 * everything gets the autoconf macros */
#include "sip-prefix.h"
#endif /* _WIN32 */

#endif /* _GAIM_INTERNAL_H_ */
