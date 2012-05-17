/**
 * @file sipe-common.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

/*
 * Everything in here must be independent of any other header file!
 *
 * I.e. it must be possible to include this header
 * in any module without requiring any other #include.
 */

#ifdef __GNUC__
#define SIPE_UNUSED_PARAMETER __attribute__((unused))
#else
#define SIPE_UNUSED_PARAMETER
#endif

/* in order to remove internal.h dependency in mingw builds */
#ifndef G_GNUC_NULL_TERMINATED
#	if    defined(__GNUC__) && (__GNUC__ >= 4)
#		define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#	else
#		define G_GNUC_NULL_TERMINATED
#	endif
#endif

#ifdef _MSC_VER
typedef long ssize_t;
#endif
