/**
 * @file sipe-win32dep.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 pier11 <pier11@operamail.com> (fix for REG_EXPAND_SZ)
 * Copyright (C) 2002-2003, Herman Bloggs <hermanator12002@yahoo.com>
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

/* This file is an attempt to fix purple's wpurple_read_reg_string()
 * which doesn't read REG_EXPAND_SZ types from registry, only REG_SZ.
 * The code is identical (v2.6.6) apart from one line.
 *
 * The nead is desperate to read Lotus Notes' notes.ini file location
 * stored in REG_EXPAND_SZ type.
 */

#include "glib.h"

#include "sipe-win32dep.h"
#include "sipe-backend.h"

static HKEY _reg_open_key(HKEY rootkey, const char *subkey, REGSAM access) {
	HKEY reg_key = NULL;
	LONG rv;

	if(G_WIN32_HAVE_WIDECHAR_API()) {
		wchar_t *wc_subkey = g_utf8_to_utf16(subkey, -1, NULL,
			NULL, NULL);
		rv = RegOpenKeyExW(rootkey, wc_subkey, 0, access, &reg_key);
		g_free(wc_subkey);
	} else {
		char *cp_subkey = g_locale_from_utf8(subkey, -1, NULL,
			NULL, NULL);
		rv = RegOpenKeyExA(rootkey, cp_subkey, 0, access, &reg_key);
		g_free(cp_subkey);
	}

	if (rv != ERROR_SUCCESS) {
		char *errmsg = g_win32_error_message(rv);
		SIPE_DEBUG_ERROR("Could not open reg key '%s' subkey '%s'.\nMessage: (%ld) %s\n",
					((rootkey == HKEY_LOCAL_MACHINE) ? "HKLM" :
					 (rootkey == HKEY_CURRENT_USER) ? "HKCU" :
					  (rootkey == HKEY_CLASSES_ROOT) ? "HKCR" : "???"),
					subkey, rv, errmsg);
		g_free(errmsg);
	}

	return reg_key;
}

static gboolean _reg_read(HKEY reg_key, const char *valname, LPDWORD type, LPBYTE data, LPDWORD data_len) {
	LONG rv;

	if(G_WIN32_HAVE_WIDECHAR_API()) {
		wchar_t *wc_valname = NULL;
		if (valname)
			wc_valname = g_utf8_to_utf16(valname, -1, NULL, NULL, NULL);
		rv = RegQueryValueExW(reg_key, wc_valname, 0, type, data, data_len);
		g_free(wc_valname);
	} else {
		char *cp_valname = NULL;
		if(valname)
			cp_valname = g_locale_from_utf8(valname, -1, NULL, NULL, NULL);
		rv = RegQueryValueExA(reg_key, cp_valname, 0, type, data, data_len);
		g_free(cp_valname);
	}

	if (rv != ERROR_SUCCESS) {
		char *errmsg = g_win32_error_message(rv);
		SIPE_DEBUG_ERROR("Could not read from reg key value '%s'.\nMessage: (%ld) %s\n",
					valname, rv, errmsg);
		g_free(errmsg);
	}

	return (rv == ERROR_SUCCESS);
}

char *wpurple_read_reg_expand_string(HKEY rootkey, const char *subkey, const char *valname) {

	DWORD type;
	DWORD nbytes;
	HKEY reg_key = _reg_open_key(rootkey, subkey, KEY_QUERY_VALUE);
	char *result = NULL;

	if(reg_key) {
		if(_reg_read(reg_key, valname, &type, NULL, &nbytes) && (type == REG_SZ || type == REG_EXPAND_SZ)) {
			LPBYTE data;
			if(G_WIN32_HAVE_WIDECHAR_API())
				data = (LPBYTE) g_new(wchar_t, ((nbytes + 1) / sizeof(wchar_t)) + 1);
			else
				data = (LPBYTE) g_malloc(nbytes + 1);

			if(_reg_read(reg_key, valname, &type, data, &nbytes)) {
				if(G_WIN32_HAVE_WIDECHAR_API()) {
					wchar_t *wc_temp = (wchar_t*) data;
					wc_temp[nbytes / sizeof(wchar_t)] = '\0';
					result = g_utf16_to_utf8(wc_temp, -1,
						NULL, NULL, NULL);
				} else {
					char *cp_temp = (char*) data;
					cp_temp[nbytes] = '\0';
					result = g_locale_to_utf8(cp_temp, -1,
						NULL, NULL, NULL);
				}
			}
			g_free(data);
		}
		RegCloseKey(reg_key);
	}

	return result;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
