/*
 * sipkrb5.c - Methods for Using Kerberos Authentication with SIP
 * per MS SIPAE
 *
 * http://msdn.microsoft.com/en-us/library/cc431510.aspx
 *
 */

/* 
 * Copyright (C)2008 Andrew Rechenberg
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */


gchar *purple_krb5_gen_auth_token(const gchar *authuser, const gchar *realm, const gchar *password, const gchar *hostname, const gchar *service);
