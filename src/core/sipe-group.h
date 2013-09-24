/**
 * @file sipe-group.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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

/* Forward declarations */
struct sipe_buddy;
struct sipe_core_private;
struct sipe_ucs_transaction;

struct sipe_group {
	gchar *name;
	gchar *exchange_key;
	gchar *change_key;
	guint id;
	gboolean is_obsolete;
};

struct sipe_group *sipe_group_find_by_id(struct sipe_core_private *sipe_private,
					 guint id);

struct sipe_group *sipe_group_find_by_name(struct sipe_core_private *sipe_private,
					   const gchar * name);

void sipe_group_create(struct sipe_core_private *sipe_private,
		       struct sipe_ucs_transaction *trans,
		       const gchar *name,
		       const gchar *who);

gboolean sipe_group_rename(struct sipe_core_private *sipe_private,
			   struct sipe_group *group,
			   const gchar *name);

/**
 * Creates @c sipe_group structure for a new group and adds it into the group
 * list of given account. If buddy is already in the list, its existing
 * structure is returned.
 *
 * @param sipe_private SIPE core data
 * @param name         name of group (may be @c NULL)
 * @param exchange_key Exchange key (may be @c NULL)
 * @param change_key   Change key (may be @c NULL)
 * @param id           numeric ID of group
 *
 * @return @c sipe_group structure or @c NULL if group creation failed
 */
struct sipe_group *sipe_group_add(struct sipe_core_private *sipe_private,
				  const gchar *name,
				  const gchar *exchange_key,
				  const gchar *change_key,
				  guint id);

/* remove group from core & backend */
void sipe_group_remove(struct sipe_core_private *sipe_private,
		       struct sipe_group *group);

/* update alias/group list for a buddy on the server */
void sipe_group_update_buddy(struct sipe_core_private *sipe_private,
			     struct sipe_buddy *buddy);

/**
 * Prepare group list for an update
 *
 * @param sipe_private SIPE core data
 */
void sipe_group_update_start(struct sipe_core_private *sipe_private);

/**
 * Finish group list update. This will remove obsolete groups.
 *
 * NOTE: this must be call after sipe_buddy_update_finish(), i.e. it
 *       assumes that the group is no longer associated with any buddy.
 *
 * @param sipe_private SIPE core data
 */
void sipe_group_update_finish(struct sipe_core_private *sipe_private);

/**
 * Return first group
 *
 * @param sipe_private SIPE core data
 *
 * @return sipe_group structure or @c NULL if there are no groups
 */
struct sipe_group *sipe_group_first(struct sipe_core_private *sipe_private);

/**
 * Number of groups
 *
 * @param sipe_private SIPE core data
 */
guint sipe_group_count(struct sipe_core_private *sipe_private);

/**
 * Initialize group data
 *
 * @param sipe_private SIPE core data
 */
void sipe_group_init(struct sipe_core_private *sipe_private);

/**
 * Free group data
 *
 * @param sipe_private SIPE core data
 */
void sipe_group_free(struct sipe_core_private *sipe_private);
