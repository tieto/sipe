 /**
 * @file sipe-groupchat.c
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
 * This module implements the OCS2007R2 Group Chat functionality
 *
 * Documentation references:
 *
 *  Microsoft TechNet: Key Protocols and Windows Services Used by Group Chat
 *   <http://technet.microsoft.com/en-us/library/ee323484%28office.13%29.aspx>
 *  Microsoft TechNet: Group Chat Call Flows
 *   <http://technet.microsoft.com/en-us/library/ee323524%28office.13%29.aspx>
 *  Microsoft Office Communications Server 2007 R2 Technical Reference Guide
 *   <http://go.microsoft.com/fwlink/?LinkID=159649>
 *  XML XCCOS message specification
 *   <???> (searches on the internet currently reveal nothing)
 */

#include <glib.h>

#include "sip-transport.h"
#include "sipe-groupchat.h"

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
