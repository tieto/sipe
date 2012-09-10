/**
 * @file sipe-group.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
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

struct sipe_group {
	gchar *name;
	int id;
};

int sipe_group_compare(struct sipe_group *group1, struct sipe_group *group2);

struct sipe_group *sipe_group_find_by_id(struct sipe_core_private *sipe_private, int id);

struct sipe_group *sipe_group_find_by_name(struct sipe_core_private *sipe_private,
					   const gchar * name);

void sipe_group_create(struct sipe_core_private *sipe_private,
		       const gchar *name,
		       const gchar * who);

gboolean sipe_group_rename(struct sipe_core_private *sipe_private,
			   struct sipe_group *group,
			   const gchar *name);

void sipe_group_add(struct sipe_core_private *sipe_private,
		    struct sipe_group * group);


