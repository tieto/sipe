/**
 * @file tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
 * Copyright (C) 2008 Novell, Inc.
 *
 * Implemented with reference to the follow documentation:
 *   - http://davenport.sourceforge.net/ntlm.html
 *   - MS-NLMP: http://msdn.microsoft.com/en-us/library/cc207842.aspx
 *   - MS-SIP : http://msdn.microsoft.com/en-us/library/cc246115.aspx
 *
 * Please use "make tests" to build & run them!
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

#include <glib.h>

#include "cipher.h"
#include "debug.h"
#include "signals.h"

gboolean sip_sec_ntlm_tests(void);

int main()
{
	/* Initialization that libpurple/core.c would normally do */
	purple_signals_init();
	purple_debug_init();
	purple_debug_set_enabled(TRUE);
	purple_ciphers_init();

	/* Run tests */
	return(sip_sec_ntlm_tests() ? 0 : 1);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
