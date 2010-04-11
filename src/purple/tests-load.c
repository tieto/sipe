/**
 * @file tests-load.c
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

#include <stdlib.h>
#include <stdio.h>

#include <gmodule.h>

/* test that libsipe.so loads succesfully */
int main(int argc, char *argv[])
{
	int rc = 1;

	(void) argc;
	(void) argv;

	/* well if this doesn't work, what's the use of a plugin? */
	if (g_module_supported()) {
		gchar *name = g_module_build_path(".libs", "sipe");
		GModule *module = g_module_open(name, G_MODULE_BIND_LOCAL);
		if (module) {
			g_module_close(module);
			/* all OK */
			printf("plugin loaded OK\n");
			rc = 0;
		} else {
			fprintf(stderr, "plugin loaded error: %s\n",
				g_module_error());
		}
		g_free(name);
	}
	return(rc);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
