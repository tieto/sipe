/**
 * @file sipe-nls.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-12 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef ENABLE_NLS
#include <glib/gi18n.h>
#else
#define _(String) ((const char *) (String))
#define N_(String) ((const char *) (String))
#define gettext(String) ((const char *) (String))
#define dngettext(package, StringS, StringP, p) ((const char *) ((p) ? (StringP) : (StringS)))
#endif /* ENABLE_NLS */
