/**
 * @file sipe-core-private.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * Private part of the Sipe data structure
 *
 * This part contains the information only needed by the core
 */
struct sipe_account_data; /* to be removed... */
struct sipe_core_private {
	/**
	 * The public part is the first item, i.e. a pointer to the
	 * public part can also be used as a pointer to the private part.
	 */
	struct sipe_core_public public;

	/* the original data structure*/
	struct sipe_account_data *temporary;
};

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
