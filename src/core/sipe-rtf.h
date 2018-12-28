/**
 * @file sipe-rtf.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2018 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * Simple parser to extract plain text from RTF and transform it to HTML
 */

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/**
 * Extract plain text from RTF and transform it to HTML
 *
 * @param rtf pointer to RTF text
 * @return    string with HTML. Must be g_free()'d.
 */
gchar *sipe_rtf_to_html(const gchar *rtf);
