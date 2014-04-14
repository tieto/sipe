/**
 * @file tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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

#include "version.h"
#if !PURPLE_VERSION_CHECK(3,0,0)
#include "cipher.h"
#endif

#include "debug.h"
#include "signals.h"

#include "sipe-common.h"
#include "sipe-core.h"

/* stub for purple-user.c */
void sipe_core_user_ask_cb(SIPE_UNUSED_PARAMETER gpointer key,
			   SIPE_UNUSED_PARAMETER gboolean accepted)
{
}

gboolean sip_sec_ntlm_tests(void);

int main()
{
	/* Initialization that libpurple/core.c would normally do */
	purple_signals_init();
	purple_debug_init();
	purple_debug_set_enabled(TRUE);
#if !PURPLE_VERSION_CHECK(3,0,0)
	purple_ciphers_init();
#endif

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
