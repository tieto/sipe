/**
 * @file miranda-plugin.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#pragma comment(lib, "Secur32.lib")

#ifdef HAVE_GSSAPI_GSSAPI_H
#pragma comment(lib, "krb5_32.lib")
#pragma comment(lib, "gssapi32.lib")
#pragma comment(lib, "comerr32.lib")
#endif

#include <windows.h>
#include <Windowsx.h>
#include <win2k.h>
#include <Richedit.h>
#include <stdio.h>

#include <glib.h>

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_protomod.h"
#include "m_system.h"
#include "m_database.h"
#include "m_options.h"
#include "m_netlib.h"
#include "m_chat.h"
#include "m_clist.h"
#include "m_langpack.h"
#include "m_message.h"
#include "m_genmenu.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "miranda-private.h"
#include "miranda-resource.h"

/* FIXME: Not here */
void CreateProtoService(const SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc);

HANDLE sipe_miranda_incoming_netlibuser = NULL;
CRITICAL_SECTION sipe_miranda_debug_CriticalSection;

gchar *sipe_backend_version(void)
{
	char version[200];

	if (CallService(MS_SYSTEM_GETVERSIONTEXT, sizeof(version), (LPARAM)version)) {
		strcpy(version, "Unknown");
	}

	return g_strdup_printf("Miranda %s SIPLCS " __DATE__ " " __TIME__, version );
}

/*
 * Miranda globals
 *
 * Global variables related to miranda core or UI
 */
static BOOL (WINAPI *pfnEnableThemeDialogTexture)(HANDLE, DWORD) = 0;
HINSTANCE hInst;
PLUGINLINK* pluginLink;
struct MM_INTERFACE mmi;
int hLangpack;

/*
 * Dialog boxes
 */
static void
EnableDlgItem(HWND hwndDlg, UINT control, gboolean enable)
{
	EnableWindow(GetDlgItem(hwndDlg, control), enable);
}

static void
CheckDlgItem(HWND hwndDlg, UINT control, int state)
{
	Button_SetCheck(GetDlgItem(hwndDlg, control), state);
}

INT_PTR CALLBACK DlgProcSipSimpleOptsAbout(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			SIPPROTO *pr = (SIPPROTO *)lParam;
			SETTEXTEX tex;
			gchar *tmp, *about;
			LOCK;
			tmp = sipe_core_about();
			about = sipe_miranda_html2rtf(tmp);
			g_free(tmp);
			UNLOCK;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			tex.flags = ST_DEFAULT;
			tex.codepage = 437;

			SendDlgItemMessage(hwndDlg, IDC_ABOUTSIPE, EM_SETTEXTEX, (WPARAM)&tex, (LPARAM)about );

			g_free(about);
		}
	}

	return FALSE;
}

static INT_PTR CALLBACK DlgProcSipSimpleOpts(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static int lock=0;

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			const SIPPROTO *pr = (const SIPPROTO *)lParam;
			char *str;
			gboolean state;
			WORD iptype;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			lock++;

#if defined(HAVE_GSSAPI_GSSAPI_H) || defined(HAVE_SSPI)
			state = sipe_miranda_getBool(pr, "sso", FALSE);
			if (state)
			{
				CheckDlgItem(hwndDlg, IDC_USESSO, BST_CHECKED);
				EnableDlgItem(hwndDlg, IDC_LOGIN, FALSE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, FALSE);
			} else {
#endif
				CheckDlgItem(hwndDlg, IDC_USESSO, BST_UNCHECKED);
				EnableDlgItem(hwndDlg, IDC_LOGIN, TRUE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, TRUE);
#if defined(HAVE_GSSAPI_GSSAPI_H) || defined(HAVE_SSPI)
			}
#endif

			str = sipe_miranda_getString(pr, "username");
			SetDlgItemTextA(hwndDlg, IDC_HANDLE, str);
			SendDlgItemMessage(hwndDlg, IDC_HANDLE, EM_SETLIMITTEXT, 50, 0);
			mir_free(str);

			str = sipe_miranda_getString(pr, "login");
			SetDlgItemTextA(hwndDlg, IDC_LOGIN, str);
			SendDlgItemMessage(hwndDlg, IDC_LOGIN, EM_SETLIMITTEXT, 50, 0);
			mir_free(str);

			str = sipe_miranda_getString(pr, "password");
			if (str) CallService(MS_DB_CRYPT_DECODESTRING, strlen(str),(LPARAM)str);
			SetDlgItemTextA(hwndDlg, IDC_PASSWORD, str);
			SendDlgItemMessage(hwndDlg, IDC_PASSWORD, EM_SETLIMITTEXT, 16, 0);
			mir_free(str);

			SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_ADDSTRING, 0, (LPARAM)_T("Auto"));
			SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_ADDSTRING, 0, (LPARAM)_T("NTLM"));
#if defined(HAVE_GSSAPI_GSSAPI_H) || defined(HAVE_SSPI)
			SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_ADDSTRING, 0, (LPARAM)_T("Kerberos"));
#endif
			SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_ADDSTRING, 0, (LPARAM)_T("TLS-DSK"));

			sipe_miranda_getWord(pr, NULL, "authscheme", &iptype);
			if (iptype == SIPE_AUTHENTICATION_TYPE_NTLM)
				SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("NTLM"));
			else if (iptype == SIPE_AUTHENTICATION_TYPE_KERBEROS)
				SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("Kerberos"));
			else if (iptype == SIPE_AUTHENTICATION_TYPE_TLS_DSK)
				SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("TLS-DSK"));
			else
				SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("Auto"));

			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("Auto"));
			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("SSL/TLS"));
			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("TCP"));

			str = sipe_miranda_getString(pr, "transport");
			if (!str || !strcmp(str, "auto"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("Auto"));
			else if (!strcmp(str, "tls"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("SSL/TLS"));
			else if (!strcmp(str, "tcp"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("TCP"));

			str = sipe_miranda_getGlobalString("public_ip");
			SetDlgItemTextA(hwndDlg, IDC_PUBLICIP, str);
			SendDlgItemMessage(hwndDlg, IDC_PUBLICIP, EM_SETLIMITTEXT, 20, 0);
			mir_free(str);

			str = sipe_miranda_getGlobalString("ipprog");
			SetDlgItemTextA(hwndDlg, IDC_IPPROGEXE, str);
			SendDlgItemMessage(hwndDlg, IDC_IPPROGEXE, EM_SETLIMITTEXT, 60, 0);
			mir_free(str);

			str = sipe_miranda_get_local_ip();
			SetDlgItemTextA(hwndDlg, IDC_IPLOCALFOUND, str);

			sipe_miranda_getGlobalWord("iptype", &iptype);
			if (iptype == SIPE_MIRANDA_IP_LOCAL)
			{
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPLOCAL);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, FALSE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, FALSE);
			} else if (iptype == SIPE_MIRANDA_IP_MANUAL) {
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPMANUAL);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, TRUE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, FALSE);
			} else {
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPPROG);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, FALSE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, TRUE);
			}

			lock--;
			return TRUE;
		}

		case WM_COMMAND:
		{
			int code = wParam >> 16;
			int id = wParam & 0xffff;

			if (LOWORD(wParam) == IDC_IPLOCAL)
			{
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPLOCAL);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, FALSE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, FALSE);
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			} else if (LOWORD(wParam) == IDC_IPMANUAL) {
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPMANUAL);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, TRUE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, FALSE);
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			} else if (LOWORD(wParam) == IDC_IPPROG) {
				CheckRadioButton(hwndDlg, IDC_IPLOCAL, IDC_IPPROG, IDC_IPPROG);
				EnableDlgItem(hwndDlg, IDC_PUBLICIP, FALSE);
				EnableDlgItem(hwndDlg, IDC_IPPROGEXE, TRUE);
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			} else if (LOWORD(wParam) == IDC_USESSO) {
				if (IsDlgButtonChecked(hwndDlg, IDC_USESSO) == BST_CHECKED)
				{
					EnableDlgItem(hwndDlg, IDC_LOGIN, FALSE);
					EnableDlgItem(hwndDlg, IDC_PASSWORD, FALSE);
					SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
				} else {
					CheckRadioButton(hwndDlg, IDC_SSO, IDC_MSO, IDC_MSO);
					EnableDlgItem(hwndDlg, IDC_LOGIN, TRUE);
					EnableDlgItem(hwndDlg, IDC_PASSWORD, TRUE);
				}
			} else if (!lock && (code == EN_CHANGE || code == CBN_SELCHANGE)) {
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			}
			return TRUE;
		}

		case WM_NOTIFY:
		{
			if (((LPNMHDR)lParam)->code == (UINT)PSN_APPLY)
			{
				char buf[100];
				TCHAR tbuf[100];

				const SIPPROTO *pr = (const SIPPROTO *)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

				GetDlgItemTextA(hwndDlg, IDC_HANDLE, buf, sizeof(buf));
				sipe_miranda_setString(pr, "username", buf);

				GetDlgItemTextA(hwndDlg, IDC_LOGIN, buf, sizeof(buf));
				sipe_miranda_setString(pr, "login", buf);

				GetDlgItemTextA(hwndDlg, IDC_PASSWORD, buf, sizeof(buf));
				CallService(MS_DB_CRYPT_ENCODESTRING, sizeof(buf),(LPARAM)buf);
				sipe_miranda_setString(pr, "password", buf);

				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, WM_GETTEXT, 100, (LPARAM)tbuf );

				if (!_tcscmp(tbuf, _T("Auto")))
					sipe_miranda_setString(pr, "transport", "auto");
				else if (!_tcscmp(tbuf, _T("SSL/TLS")))
					sipe_miranda_setString(pr, "transport", "tls");
				else if (!_tcscmp(tbuf, _T("TCP")))
					sipe_miranda_setString(pr, "transport", "tcp");

				SendDlgItemMessage(hwndDlg, IDC_AUTHTYPE, WM_GETTEXT, 100, (LPARAM)tbuf );

				if (!_tcscmp(tbuf, _T("NTLM")))
					sipe_miranda_setWord(pr, NULL, "authscheme", SIPE_AUTHENTICATION_TYPE_NTLM);
				else if (!_tcscmp(tbuf, _T("Kerberos")))
					sipe_miranda_setWord(pr, NULL, "authscheme", SIPE_AUTHENTICATION_TYPE_KERBEROS);
				else if (!_tcscmp(tbuf, _T("TLS-DSK")))
					sipe_miranda_setWord(pr, NULL, "authscheme", SIPE_AUTHENTICATION_TYPE_TLS_DSK);
				else
					sipe_miranda_setWord(pr, NULL, "authscheme", SIPE_AUTHENTICATION_TYPE_AUTOMATIC);

				GetDlgItemTextA(hwndDlg, IDC_PUBLICIP, buf, sizeof(buf));
				sipe_miranda_setGlobalString("public_ip", buf);

				GetDlgItemTextA(hwndDlg, IDC_IPPROGEXE, buf, sizeof(buf));
				sipe_miranda_setGlobalString("ipprog", buf);

				if (IsDlgButtonChecked(hwndDlg, IDC_IPLOCAL) == BST_CHECKED)
				{
					sipe_miranda_setGlobalWord("iptype", SIPE_MIRANDA_IP_LOCAL);
				} else if (IsDlgButtonChecked(hwndDlg, IDC_IPMANUAL) == BST_CHECKED) {
					sipe_miranda_setGlobalWord("iptype", SIPE_MIRANDA_IP_MANUAL);
				} else {
					sipe_miranda_setGlobalWord("iptype", SIPE_MIRANDA_IP_PROG);
				}
				return TRUE;
			}
			return TRUE;
		}

	}

	return FALSE;
}

INT_PTR CALLBACK DlgProcAccMgrUI(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{
			const SIPPROTO *pr = (const SIPPROTO *)lParam;
			char *str;
			gboolean sso;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			sso = sipe_miranda_getBool(pr, "sso", FALSE);
			if (sso)
			{
				CheckRadioButton(hwndDlg, IDC_SSO, IDC_MSO, IDC_SSO);
				EnableDlgItem(hwndDlg, IDC_LOGIN, FALSE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, FALSE);
			} else {
				CheckRadioButton(hwndDlg, IDC_SSO, IDC_MSO, IDC_MSO);
				EnableDlgItem(hwndDlg, IDC_LOGIN, TRUE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, TRUE);
			}

			str = sipe_miranda_getString(pr, "username");
			SetDlgItemTextA(hwndDlg, IDC_HANDLE, str);
			mir_free(str);

			str = sipe_miranda_getString(pr, "login");
			SetDlgItemTextA(hwndDlg, IDC_LOGIN, str);
			mir_free(str);

			str = sipe_miranda_getString(pr, "password");
			if (str) CallService(MS_DB_CRYPT_DECODESTRING, strlen(str),(LPARAM)str);
			SetDlgItemTextA(hwndDlg, IDC_PASSWORD, str);
			mir_free(str);

			SendDlgItemMessage(hwndDlg, IDC_HANDLE, EM_SETLIMITTEXT, 50, 0);
			SendDlgItemMessage(hwndDlg, IDC_LOGIN, EM_SETLIMITTEXT, 50, 0);
			SendDlgItemMessage(hwndDlg, IDC_PASSWORD, EM_SETLIMITTEXT, 16, 0);

			return TRUE;
		}

		case WM_COMMAND:
			if (LOWORD(wParam) == IDC_SSO)
			{
				EnableDlgItem(hwndDlg, IDC_LOGIN, FALSE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, FALSE);
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			} else if (LOWORD(wParam) == IDC_MSO) {
				EnableDlgItem(hwndDlg, IDC_LOGIN, TRUE);
				EnableDlgItem(hwndDlg, IDC_PASSWORD, TRUE);
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			} else if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == GetFocus()) {
				switch(LOWORD(wParam))
				{
					case IDC_HANDLE:
					case IDC_LOGIN:
					case IDC_PASSWORD:
						SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
						break;
				}
			}
			break;

		case WM_NOTIFY:
			if (((LPNMHDR)lParam)->code == (UINT)PSN_APPLY)
			{
				char buf[100];

				const SIPPROTO *pr = (const SIPPROTO *)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

				if (IsDlgButtonChecked(hwndDlg, IDC_SSO) == BST_CHECKED)
				{
					sipe_miranda_setBool(pr, "sso", TRUE);
				} else {
					sipe_miranda_setBool(pr, "sso", FALSE);
				}

				GetDlgItemTextA(hwndDlg, IDC_HANDLE, buf, sizeof(buf));
				sipe_miranda_setString(pr, "username", buf);

				GetDlgItemTextA(hwndDlg, IDC_LOGIN, buf, sizeof(buf));
				sipe_miranda_setString(pr, "login", buf);

				GetDlgItemTextA(hwndDlg, IDC_PASSWORD, buf, sizeof(buf));
				CallService(MS_DB_CRYPT_ENCODESTRING, sizeof(buf),(LPARAM)buf);
				sipe_miranda_setString(pr, "password", buf);

				return TRUE;
			}
			break;
	}

	return FALSE;
}


/*
 * Miranda service support functions
 *
 * Functions called by our service functions
 */
static void fix_contact_groups(SIPPROTO *pr)
{
	GSList *contacts = sipe_miranda_buddy_find_all(pr, NULL, NULL);
	char *group;

	CONTACTS_FOREACH(contacts)
		group = DBGetString(hContact, "CList", "Group");
		sipe_miranda_setContactString(pr, hContact, "Group", group);
		mir_free(group);
	CONTACTS_FOREACH_END

}

static INT_PTR sipe_miranda_start_chat(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	struct sipe_core_public *sipe_public = pr->sip;

	DBVARIANT dbv;
	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		LOCK;
		sipe_core_buddy_new_chat(sipe_public, dbv.pszVal);
		UNLOCK;
		DBFreeVariant( &dbv );
		return TRUE;
	}

	return FALSE;
}

static void OnModulesLoaded(SIPPROTO *pr)
{
	TCHAR descr[MAX_PATH];
	NETLIBUSER nlu = {0};
	GCREGISTER gcr;
	DBEVENTTYPEDESCR eventType = {0};

	SIPE_DEBUG_INFO_NOFORMAT("OnEvent::OnModulesLoaded");

	nlu.cbSize = sizeof(nlu);
	nlu.flags = NUF_OUTGOING | NUF_INCOMING | NUF_TCHAR;
	nlu.szSettingsModule = pr->proto.m_szModuleName;
	_sntprintf(descr, SIZEOF(descr), TranslateT("%s server connection"), pr->proto.m_tszUserName );
	nlu.ptszDescriptiveName = descr;

	pr->m_hServerNetlibUser = (HANDLE)CallService(MS_NETLIB_REGISTERUSER, 0, (LPARAM)&nlu);

	gcr.cbSize = sizeof(gcr);
	gcr.dwFlags = 0;
	gcr.pszModule = pr->proto.m_szModuleName;
	gcr.pszModuleDispName = "Sip/Simple";
	gcr.iMaxText = 0;
	gcr.nColors = 0;

	if (CallService(MS_GC_REGISTER, 0, (LPARAM)&gcr))
	{
		SIPE_DEBUG_INFO_NOFORMAT("OnEvent::OnModulesLoaded Failed to register chat");
	}

        // Register custom database events
	eventType.cbSize = DBEVENTTYPEDESCR_SIZE;
	eventType.module = pr->proto.m_szModuleName;
	eventType.eventType = SIPE_EVENTTYPE_ERROR_NOTIFY;
	eventType.descr = "Message error notification";
	eventType.textService = SIPE_DB_GETEVENTTEXT_ERROR_NOTIFY;
	eventType.flags = DETF_HISTORY | DETF_MSGWINDOW;
	// for now keep default "message" icon
	CallService(MS_DB_EVENT_REGISTERTYPE, 0, (LPARAM)&eventType);

	eventType.cbSize = DBEVENTTYPEDESCR_SIZE;
	eventType.module = pr->proto.m_szModuleName;
	eventType.eventType = SIPE_EVENTTYPE_INFO_NOTIFY;
	eventType.descr = "Message info notification";
	eventType.textService = SIPE_DB_GETEVENTTEXT_INFO_NOTIFY;
	eventType.flags = DETF_HISTORY | DETF_MSGWINDOW;
	// for now keep default "message" icon
	CallService(MS_DB_EVENT_REGISTERTYPE, 0, (LPARAM)&eventType);

	eventType.cbSize = DBEVENTTYPEDESCR_SIZE;
	eventType.module = pr->proto.m_szModuleName;
	eventType.eventType = SIPE_EVENTTYPE_IM_TOPIC;
	eventType.descr = "Chat topic set";
	eventType.textService = SIPE_DB_GETEVENTTEXT_IM_TOPIC;
	eventType.flags = DETF_HISTORY | DETF_MSGWINDOW;
	// for now keep default "message" icon
	CallService(MS_DB_EVENT_REGISTERTYPE, 0, (LPARAM)&eventType);

}

int OnOptionsInit(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	OPTIONSDIALOGPAGE odp = {0};
	HMODULE hUxTheme = 0;

	if (IsWinVerXPPlus())
	{
		hUxTheme = GetModuleHandleA("uxtheme.dll");
		if (hUxTheme)
			pfnEnableThemeDialogTexture = (BOOL (WINAPI *)(HANDLE, DWORD))GetProcAddress(hUxTheme, "EnableThemeDialogTexture");
	}

	odp.cbSize = sizeof(odp);
	odp.position = -800000000;
	odp.hInstance = hInst;
	odp.ptszGroup = LPGENT("Network");
	odp.dwInitParam = (LPARAM)pr;
	odp.ptszTitle = pr->proto.m_tszUserName;
	odp.flags = ODPF_BOLDGROUPS | ODPF_TCHAR;

	odp.ptszTab = LPGENT("Account");
	odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_SIPSIMPLE);
	odp.pfnDlgProc = DlgProcSipSimpleOpts;
	CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

	odp.ptszTab = LPGENT("About");
	odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_SIPSIMPLE_ABOUT);
	odp.pfnDlgProc = DlgProcSipSimpleOptsAbout;
	CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

#if 0

        odp.ptszTab = LPGENT("Features");
        odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_ICQFEATURES);
        odp.pfnDlgProc = DlgProcIcqFeaturesOpts;
        CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

        odp.ptszTab = LPGENT("Privacy");
        odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_ICQPRIVACY);
        odp.pfnDlgProc = DlgProcIcqPrivacyOpts;
        CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

        if (bPopUpService)
        {
                odp.position = 100000000;
                odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_POPUPS);
                odp.groupPosition = 900000000;
                odp.pfnDlgProc = DlgProcIcqPopupOpts;
                odp.ptszGroup = LPGENT("Popups");
                odp.ptszTab = NULL;
                CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );
        }
#endif
        return 0;
}

void sipe_miranda_close(SIPPROTO *pr)
{
	struct sipe_core_public *sipe_public = pr->sip;

	if (sipe_public) {
		LOCK;
		sipe_core_deallocate(sipe_public);
		pr->sip = NULL;
		UNLOCK;

//		sipe_purple_chat_destroy_rejoin(purple_private);
//		g_free(purple_private);
	}
}

void set_buddies_offline(const SIPPROTO* pr)
{
	HANDLE hContact;

	hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDFIRST, 0, 0);
	while (hContact) {
		char* szProto = (char*)CallService(MS_PROTO_GETCONTACTBASEPROTO, (WPARAM)hContact, 0);
		if (szProto != NULL && !lstrcmpA(szProto, pr->proto.m_szModuleName)) {
			if (DBGetContactSettingByte(hContact, pr->proto.m_szModuleName, "ChatRoom", 0) == 0)
				DBWriteContactSettingWord(hContact, pr->proto.m_szModuleName, "Status", ID_STATUS_OFFLINE);
		}
		hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDNEXT, (WPARAM)hContact, 0);
	}
}

int __stdcall show_vlc(void *data);
void sipe_miranda_login(SIPPROTO *pr) {
	gchar *username = sipe_miranda_getString(pr, "username");
	gchar *login = sipe_miranda_getString(pr, "login");
	gchar *email = sipe_miranda_getString(pr, "email");
	gchar *email_url = sipe_miranda_getString(pr, "email_url");
	const gchar *errmsg;
	gchar *password;
	gchar *tmp = (char*)mir_calloc(1024);
	int tmpstatus;
	int ttype;
	guint authentication_type = SIPE_AUTHENTICATION_TYPE_AUTOMATIC;
	struct sipe_core_public *sipe_public;

//	CloseHandle((HANDLE) mir_forkthreadex(show_vlc, NULL, 65536, NULL));

	if (sipe_miranda_getStaticString(pr, NULL, "password", tmp, 1024 )) tmp[0] = '\0';
	CallService(MS_DB_CRYPT_DECODESTRING, sizeof(tmp),(LPARAM)tmp);
	password = g_strdup(tmp);
	mir_free(tmp);

	LOCK;
	pr->sip = sipe_core_allocate(username,
//	/* @TODO: is this correct?
//	   "sso" is only available when SSPI/Kerberos support is compiled in */
				     sipe_miranda_getBool(pr, "sso", FALSE),
				     login,
				     password,
				     email,
				     email_url,
				     &errmsg);
	if (pr->sip) pr->sip->backend_private = pr;
	sipe_public = pr->sip;
	UNLOCK;

	mir_free(username);
	mir_free(login);
	mir_free(email);
	mir_free(email_url);
	g_free(password);

	if (!pr->sip) {
		sipe_miranda_connection_error_reason(pr,
						     SIPE_CONNECTION_ERROR_INVALID_USERNAME, 
						     errmsg);
		return;
	}

	//sipe_miranda_chat_setup_rejoin(pr);

	/* default is Auto */
	sipe_miranda_getWord(pr, NULL, "authscheme", &authentication_type);

	/* Set display name */
	sipe_miranda_setStringUtf(pr, "Nick", pr->sip->sip_name);

	/* Update connection progress */
	tmpstatus = pr->proto.m_iStatus;
	pr->proto.m_iStatus = ID_STATUS_CONNECTING;
	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)tmpstatus, ID_STATUS_CONNECTING);

	tmp = sipe_miranda_getString(pr, "transport");
	if (sipe_strequal(tmp, "auto")) {
		ttype = SIPE_TRANSPORT_AUTO;
	} else if (sipe_strequal(tmp, "tls")) {
		ttype = SIPE_TRANSPORT_TLS;
	} else {
		ttype = SIPE_TRANSPORT_TCP;
	}
	mir_free(tmp);

	LOCK;
	sipe_core_transport_sip_connect(pr->sip,
					ttype,
					authentication_type,
					NULL,
					NULL);
	UNLOCK;
}

void sipsimple_search_contact_cb( GList *columns, GList *results, GHashTable *opts, void *data )
{
	SIPPROTO *pr = (SIPPROTO *)data;
	GList *row, *col;
	HANDLE hProcess = g_hash_table_lookup(opts, "searchid");
	PROTOSEARCHRESULT psr = { 0 };

	psr.cbSize = sizeof(psr);

	row = results;
	while (row)
	{
		gchar **name;

		col = (GList*)row->data;
		psr.id = (PROTOCHAR*)col->data;

		col = g_list_next(col);
		name = g_strsplit_set(col->data, ",", 2);
		psr.nick = (FNAMECHAR*)col->data;
		psr.firstName = (PROTOCHAR*)(name[0] ? name[1] : NULL);
		psr.lastName = (PROTOCHAR*)name[0];

		col = g_list_next(col);
		/* company */

		col = g_list_next(col);
		/* country */

		col = g_list_next(col);
		psr.email = (PROTOCHAR*)col->data;

		row = g_list_next(row);
		sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_DATA, hProcess, (LPARAM) & psr);
		g_strfreev(name);
	}

	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_SUCCESS, hProcess, 0);

}

static int OnGroupChange(SIPPROTO *pr, WPARAM w, LPARAM l )
{
	CLISTGROUPCHANGE *gi = (CLISTGROUPCHANGE*)l;
	HANDLE hContact = (HANDLE)w;
	DBVARIANT dbv;

	/* No contact => it's a group add/rename/remove */
	if (!hContact)
	{
		gchar *oldname, *newname;

		/* No old name => add */
		if (!gi->pszOldName)
		{
			return 0;
		}
		/* No new name => delete */
		else if (!gi->pszNewName)
		{
			SIPE_DEBUG_INFO("Removing group <%ls>", gi->pszOldName);
			oldname = mir_t2a(gi->pszOldName);
			LOCK;
			sipe_core_group_remove(pr->sip, oldname);
			UNLOCK;
			mir_free(oldname);
			return 0;
		}

		SIPE_DEBUG_INFO("Renaming group <%S> to <%S>", gi->pszOldName, gi->pszNewName);
		oldname = mir_t2a(gi->pszOldName);
		newname = mir_t2a(gi->pszNewName);
		LOCK;
		sipe_core_group_rename(pr->sip, oldname, newname);
		UNLOCK;
		mir_free(oldname);
		mir_free(newname);
		return 0;
	}

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		gchar *oldgroup;
		gchar *who = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );

		if (oldgroup = sipe_miranda_getContactString(pr, hContact, "Group"))
		{
			SIPE_DEBUG_INFO("Moving buddy <%s> from group <%ls> to group <%ls>", who, oldgroup, gi->pszNewName);
			LOCK;
			sipe_core_buddy_group(pr->sip, who, oldgroup, TCHAR2CHAR(gi->pszNewName));
			UNLOCK;
			mir_free(oldgroup);
		} else {
			gchar *name = mir_t2a(gi->pszNewName);

			if (!g_str_has_prefix(name, "sip:")) {
				gchar *newname = sip_uri_from_name(name);
				mir_free(name);
				name = mir_strdup(newname);
				g_free(newname);
			}

			SIPE_DEBUG_INFO("Really adding buddy <%s> to list in group <%s>", who, name);
			LOCK;
			sipe_core_buddy_add(pr->sip, who, name);
			UNLOCK;
			mir_free(name);
		}

		g_free(who);
	}

	return TRUE;
}

static int sipe_miranda_build_chat_menu(SIPPROTO *pr, WPARAM w, LPARAM lParam )
{
	GCMENUITEMS *gcmi= (GCMENUITEMS*) lParam;

	if (gcmi->Type == MENU_ON_NICKLIST)
	{
		static struct gc_item Item[] = {
                                {"&Make Leader", 1, MENU_ITEM, FALSE},
		};

		gcmi->nItems = sizeof(Item)/sizeof(Item[0]);
		gcmi->Item = &Item[0];

	}
	return 0;
}

static int OnChatEvent(SIPPROTO *pr, WPARAM w, LPARAM l )
{
	GCHOOK *hook = (GCHOOK*)l;
	GCDEST *dst = hook->pDest;

	if (dst->iType == GC_USER_MESSAGE) {
		GCDEST gcd = {0};
		GCEVENT gce = {0};
		struct sipe_chat_session *session;

		gcd.pszModule = pr->proto.m_szModuleName;
		gcd.pszID = dst->pszID;
		gcd.iType = GC_EVENT_GETITEMDATA;

		gce.cbSize = sizeof(gce);
		gce.pDest = &gcd;


		if ((session = (struct sipe_chat_session*)CallService( MS_GC_EVENT, 0, (LPARAM)&gce )) == NULL)
		{
			SIPE_DEBUG_WARNING_NOFORMAT("Failed to get chat session");
			return 0;
		}

		LOCK;
		sipe_core_chat_send(pr->sip, session, hook->pszText);
		UNLOCK;

		return TRUE;
	} else if (dst->iType == GC_USER_PRIVMESS) {
	} else if (dst->iType == GC_USER_NICKLISTMENU) {
		if (hook->dwData == 1)
		{
			SIPE_DEBUG_INFO("make leader <%s>", hook->pszUID);
		}
	}

	return FALSE;
}

int OnPreBuildContactMenu(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	int chatcount = CallService(MS_GC_GETSESSIONCOUNT, 0, (LPARAM)pr->proto.m_szModuleName);
	int idx;
	CLISTMENUITEM mi = {0};
	GC_INFO gci = {0};
	gpointer tmp;

	mi.cbSize = sizeof(mi);
	gci.pszModule = pr->proto.m_szModuleName;

	/* Remove the old list */
	while (pr->contactMenuChatItems)
	{
		SIPE_DEBUG_INFO("Removing old menuitem <%08x>", pr->contactMenuChatItems->data);
		CallService(MS_CLIST_REMOVECONTACTMENUITEM, (WPARAM)pr->contactMenuChatItems->data, 0);
		pr->contactMenuChatItems = g_slist_remove(pr->contactMenuChatItems, pr->contactMenuChatItems->data);
	}

	/* Add the main entry */
	mi.pszName = "Invite to chat";
	mi.flags = CMIF_NOTOFFLINE;
	mi.position = 20;
	tmp = (gpointer)CallService(MS_CLIST_ADDCONTACTMENUITEM, 0, (LPARAM)&mi);
	pr->contactMenuChatItems = g_slist_append(pr->contactMenuChatItems, tmp);

	mi.pszName = "New chat";
	mi.hParentMenu = pr->contactMenuChatItems->data;
	mi.flags = CMIF_ROOTHANDLE;
	mi.popupPosition = 0;
	mi.position=-10;
	mi.pszService = g_strdup_printf("%s/StartChat", pr->proto.m_szModuleName);
	mi.pszContactOwner = pr->proto.m_szModuleName;
	tmp = (gpointer)CallService(MS_CLIST_ADDCONTACTMENUITEM, 0, (LPARAM)&mi);
	g_free(mi.pszService);
	pr->contactMenuChatItems = g_slist_append(pr->contactMenuChatItems, tmp);

	for (idx=0 ; idx<chatcount ; idx++)
	{
		SIPE_DEBUG_INFO("Chat <%d> Menuitem <%08x>", idx, pr->contactMenuChatItems);
		gci.iItem = idx;
		gci.Flags = BYINDEX | NAME | ID;
		if(!CallServiceSync( MS_GC_GETINFO, 0, (LPARAM)&gci )) {
			SIPE_DEBUG_INFO("Chat <%s>", gci.pszName);

			mi.pszName = gci.pszName;
			mi.hParentMenu = pr->contactMenuChatItems->data;
			mi.flags = CMIF_ROOTHANDLE;
			mi.popupPosition = g_strdup(gci.pszID);
			mi.position = idx;
			mi.pszService = g_strdup_printf("%s/InviteToChat", pr->proto.m_szModuleName);
			mi.pszContactOwner = pr->proto.m_szModuleName;
			tmp = (gpointer)CallService(MS_CLIST_ADDCONTACTMENUITEM, 0, (LPARAM)&mi);
			g_free(mi.pszService);
			pr->contactMenuChatItems = g_slist_append(pr->contactMenuChatItems, tmp);
		}
	}

	return 0;
}

INT_PTR  SvcCreateAccMgrUI(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	return (INT_PTR)CreateDialogParam(hInst, MAKEINTRESOURCE(IDD_ACCMGRUI), (HWND)lParam, DlgProcAccMgrUI, (LPARAM)pr);
}


/*
 * Miranda service functions
 *
 * The functions in our plugin that get called directly by core Miranda
 */
static DWORD_PTR GetCaps( SIPPROTO *pr, int type, HANDLE hContact )
{
	switch (type) {
		case PFLAGNUM_1:
			return PF1_IM | PF1_CHAT | PF1_FILE | PF1_MODEMSG
				| PF1_SERVERCLIST | PF1_ADDED
				| PF1_BASICSEARCH | PF1_ADDSEARCHRES
				| PF1_SEARCHBYEMAIL | PF1_USERIDISEMAIL
				| PF1_SEARCHBYNAME | PF1_EXTSEARCH
				;

		case PFLAGNUM_2:
			return PF2_ONLINE | PF2_INVISIBLE | PF2_SHORTAWAY
				| PF2_LONGAWAY | PF2_LIGHTDND | PF2_HEAVYDND
				| PF2_OUTTOLUNCH | PF2_ONTHEPHONE | PF2_IDLE;

		case PFLAGNUM_3:
			return PF2_ONLINE | PF2_INVISIBLE | PF2_SHORTAWAY
				| PF2_LONGAWAY | PF2_LIGHTDND | PF2_HEAVYDND
				| PF2_OUTTOLUNCH | PF2_ONTHEPHONE | PF2_IDLE;

		case PFLAGNUM_4:
			return PF4_NOCUSTOMAUTH | PF4_IMSENDUTF | PF4_SUPPORTTYPING
				| PF4_SUPPORTIDLE;

		case PFLAGNUM_5:
			return 0;

		case PFLAG_UNIQUEIDSETTING:
			return (DWORD_PTR) SIP_UNIQUEID;
			break;
		default:
			SIPE_DEBUG_INFO("GetCaps: unknown type <%x>", type);

	}

	return 0;
}

static HICON GetIcon( SIPPROTO *pr, int iconIndex )
{
	SIPE_DEBUG_INFO("GetIcon: unknown index <%x>", iconIndex);
	return NULL;
}

static int OnEvent( SIPPROTO *pr, PROTOEVENTTYPE eventType, WPARAM wParam, LPARAM lParam )
{
	SIPE_DEBUG_INFO("OnEvent: type <%x>", eventType);

	switch (eventType)
	{
		case EV_PROTO_ONLOAD:
			OnModulesLoaded(pr);
			break;

		case EV_PROTO_ONREADYTOEXIT:
			break;

		case EV_PROTO_ONEXIT:
			break;

		case EV_PROTO_ONRENAME:
			break;

		case EV_PROTO_ONOPTIONS:
			return OnOptionsInit( pr, wParam, lParam );
			break;

		case EV_PROTO_ONERASE:
			break;

	}

	return 0;
}

static HANDLE AddToListByEvent( SIPPROTO *pr, int flags, int iContact, HANDLE hDbEvent )
{
	DBEVENTINFO dbei = {0};

	dbei.cbSize = sizeof(dbei);
	if ((dbei.cbBlob = CallService(MS_DB_EVENT_GETBLOBSIZE, (WPARAM)hDbEvent, 0)) == -1)
		return 0;

	dbei.pBlob = (PBYTE)_alloca(dbei.cbBlob + 1);
	dbei.pBlob[dbei.cbBlob] = '\0';

	if (CallService(MS_DB_EVENT_GET, (WPARAM)hDbEvent, (LPARAM)&dbei))
		return 0; // failed to get event

	if (strcmp(dbei.szModule, pr->proto.m_szModuleName))
		return 0; // this event is not ours

	_NIF();
	SIPE_DEBUG_INFO("AddToListByEvent: flags <%x> iContact <%x>", flags, iContact);
	return NULL;
}

static int Authorize( SIPPROTO *pr, HANDLE hContact )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("Authorize");
	return 0;
}

static int AuthDeny( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szReason )
{
	_NIF();
	SIPE_DEBUG_INFO("AuthDeny: reason <%s>", szReason);
	return 0;
}

static int AuthRecv( SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* evt )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("AuthRecv");
	return 0;
}

static int AuthRequest( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szMessage )
{
	_NIF();
	SIPE_DEBUG_INFO("AuthRequest: message <%s>", szMessage);
	return 0;
}

static HANDLE ChangeInfo( SIPPROTO *pr, int iInfoType, void* pInfoData )
{
	_NIF();
	SIPE_DEBUG_INFO("ChangeInfo: infotype <%x>", iInfoType);
	return NULL;
}

static int FileCancel( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("FileCancel");
	return 0;
}

static int FileResume( SIPPROTO *pr, HANDLE hTransfer, int* action, const PROTOCHAR** szFilename )
{
	_NIF();
	SIPE_DEBUG_INFO("FileResume: action <%x>", action);
	return 0;
}

static HANDLE SearchBasic( SIPPROTO *pr, const PROTOCHAR* id )
{
	return NULL;
}

static HWND CreateExtendedSearchUI( SIPPROTO *pr, HWND owner )
{
	return CreateDialogParam(hInst, MAKEINTRESOURCE(IDD_SEARCHUI), (HWND)owner, NULL, (LPARAM)pr);
}

static HANDLE AddToList( SIPPROTO *pr, int flags, PROTOSEARCHRESULT* psr )
{
	HANDLE hContact;
	gchar *id = g_strdup(TCHAR2CHAR(psr->id));

	/* Prepend sip: if needed */
	if (strncmp("sip:", id, 4)) {
		gchar *tmp = id;
		id = sip_uri_from_name(tmp);
		g_free(tmp);
	}

	hContact = sipe_miranda_buddy_find(pr, id, NULL);
	if (hContact) {
		g_free(id);
		return hContact;
	}

	hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
	CallService( MS_PROTO_ADDTOCONTACT, (WPARAM)hContact, (LPARAM)pr->proto.m_szModuleName );
	sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, id ); // name
	if (psr->nick)
	{
		/* server_alias */
		gchar *tmp = mir_t2a(psr->nick);
		sipe_miranda_setContactStringUtf( pr, hContact, "Nick", tmp );
		mir_free(tmp);
	}

	g_free(id);
	return hContact;
}

int
sipe_miranda_window_closed(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	MessageWindowEventData* evt = (MessageWindowEventData*)lParam;

	SIPE_DEBUG_INFO("contact <%08x> module <%s> type <%02x> flags <%02x>",
		 evt->hContact, evt->szModule, evt->uType, evt->uFlags);

	return 0;
}

static int
sipe_miranda_invite_to_chat(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	gchar *id = (gchar*)lParam;
	GCDEST gcd = {0};
	GCEVENT gce = {0};
	struct sipe_chat_session *session;
	gchar *uid;

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = id;
	gcd.iType = GC_EVENT_GETITEMDATA;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;

	if ((session = (struct sipe_chat_session*)CallService( MS_GC_EVENT, 0, (LPARAM)&gce )) == NULL)
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Failed to get chat session");
		return 0;
	}

	uid = sipe_miranda_getContactString(pr, hContact, SIP_UNIQUEID);
	sipe_core_chat_invite(pr->sip, session, uid);

	mir_free(uid);
	g_free(id);
	return 0;
}

/*
 * Main Miranda interface
 *
 * The structures and functions that allow Miranda to recovnize and load
 * our plugin.
 */

/* Plugin information structure */
PLUGININFOEX pluginInfo = {
	sizeof(PLUGININFOEX),
	"Office Communicator Protocol",
	PLUGIN_MAKE_VERSION(0,11,2,1),
	"Support for Microsoft Office Communicator",
	"Miranda support by Jochen De Smet, for core sipe support see homepage",
	"jochen.libsipe@leahnim.org",
	"(C)2009-2011",
	"https://sourceforge.net/projects/sipe",
	UNICODE_AWARE,
	0,   //doesn't replace anything built-in
    #if defined( _UNICODE )
	{ 0x842395ed, 0x4e56, 0x40e5, { 0x94, 0x25, 0x28, 0x29, 0xd8, 0xab, 0xae, 0xa5 } } // {842395ED-4E56-40e5-9425-2829D8ABAEA5}
    #else
	{ 0x1ef8af37, 0xdec1, 0x4757, { 0x89, 0x78, 0xe8, 0xad, 0xd0, 0xd8, 0x6e, 0x7f } } // {1EF8AF37-DEC1-4757-8978-E8ADD0D86E7F}
    #endif
};

__declspec(dllexport) PLUGININFOEX *MirandaPluginInfoEx(DWORD mirandaVersion)
{
	// Only load for 0.8.0.29 or greater
	// We need the core stubs for PS_GETNAME and PS_GETSTATUS
	if (mirandaVersion < PLUGIN_MAKE_VERSION(0, 9, 0, 0))
	{
		MessageBoxA(
			NULL,
			"SIP/Simple plugin cannot be loaded. It requires Miranda IM 0.9.0.0 or later.",
			"SIP/Simple Plugin",
			MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST
		);
		return NULL;
	}

	return &pluginInfo;
}

static const MUUID interfaces[] = {MIID_PROTOCOL, MIID_LAST};
__declspec(dllexport) const MUUID* MirandaPluginInterfaces(void)
{
	return interfaces;
}

static PROTO_INTERFACE* sipsimpleProtoInit( const char* pszProtoName, const TCHAR* tszUserName )
{
	gchar *tmp;
	SIPPROTO *pr = (SIPPROTO *)mir_calloc(sizeof(SIPPROTO));
	pr->proto.vtbl = (PROTO_INTERFACE_VTBL*)mir_calloc(sizeof(PROTO_INTERFACE_VTBL));

	SIPE_DEBUG_INFO("protoname <%s> username <%ls>", pszProtoName, tszUserName);

	if (!InitializeCriticalSectionAndSpinCount(&pr->CriticalSection, 0))
	{
		SIPE_DEBUG_ERROR_NOFORMAT("Can't initialize critical section");
		return NULL;
	}

	tmp = sipe_miranda_getString(pr, "transport");
	if (!tmp)
	{
		sipe_miranda_setString(pr, "transport", "auto");
	} else {
		mir_free(tmp);
	}

	/* To make it easy to detect when a SIPPROTO* isn't a SIPPROTO* */
	strncpy(pr->_SIGNATURE, "AbandonAllHope..", sizeof(pr->_SIGNATURE));

	pr->main_thread_id = GetCurrentThreadId();
	pr->proto.m_iVersion = 2;
	pr->proto.m_szModuleName = mir_strdup(pszProtoName);
	pr->proto.m_tszUserName = mir_tstrdup(tszUserName);
	pr->proto.m_szProtoName = mir_strdup(pszProtoName);

//	set_buddies_offline(pr);
	fix_contact_groups(pr);

	/* Fill the function table */
#define PROTO_FUNC(name,func) ((struct sipe_backend_private)(pr->proto)).vtbl->name = func;

	pr->proto.vtbl->AddToList              = AddToList;
	pr->proto.vtbl->AddToListByEvent       = AddToListByEvent;

	pr->proto.vtbl->Authorize              = Authorize;
	pr->proto.vtbl->AuthDeny               = AuthDeny;
	pr->proto.vtbl->AuthRecv               = AuthRecv;
	pr->proto.vtbl->AuthRequest            = AuthRequest;

	pr->proto.vtbl->ChangeInfo             = ChangeInfo;

	pr->proto.vtbl->FileAllow              = sipe_miranda_FileAllow;
	pr->proto.vtbl->FileCancel             = FileCancel;
	pr->proto.vtbl->FileDeny               = sipe_miranda_FileDeny;
	pr->proto.vtbl->FileResume             = FileResume;

	pr->proto.vtbl->GetCaps                = GetCaps;
	pr->proto.vtbl->GetIcon                = GetIcon;
	pr->proto.vtbl->GetInfo                = sipe_miranda_GetInfo;

	pr->proto.vtbl->SearchBasic            = SearchBasic;
	pr->proto.vtbl->SearchByEmail          = sipe_miranda_SearchByEmail;
	pr->proto.vtbl->SearchByName           = sipe_miranda_SearchByName;
	pr->proto.vtbl->SearchAdvanced         = sipe_miranda_SearchAdvanced;
	pr->proto.vtbl->CreateExtendedSearchUI = CreateExtendedSearchUI;

	pr->proto.vtbl->RecvMsg                = sipe_miranda_RecvMsg;

	pr->proto.vtbl->SendMsg                = sipe_miranda_SendMsg;

	pr->proto.vtbl->SetStatus              = sipe_miranda_SetStatus;

	pr->proto.vtbl->GetAwayMsg             = sipe_miranda_GetAwayMsg;
	pr->proto.vtbl->SetAwayMsg             = sipe_miranda_SetAwayMsg;

	pr->proto.vtbl->UserIsTyping           = sipe_miranda_UserIsTyping;

	pr->proto.vtbl->SendFile               = sipe_miranda_SendFile;
	pr->proto.vtbl->RecvFile               = sipe_miranda_RecvFile;

	pr->proto.vtbl->OnEvent                = OnEvent;

	/* Setup services */
	CreateProtoService(pr, PS_CREATEACCMGRUI, &SvcCreateAccMgrUI );
	CreateProtoService(pr, "/InviteToChat", &sipe_miranda_invite_to_chat);
	CreateProtoService(pr, "/StartChat",&sipe_miranda_start_chat);

#define HOOKEVENT(evt,func) HookEventObj(evt, func, pr)
	HOOKEVENT(ME_OPT_INITIALISE,            &OnOptionsInit);
	HOOKEVENT(ME_CLIST_GROUPCHANGE,         &OnGroupChange);
	HOOKEVENT(ME_GC_EVENT,                  &OnChatEvent);
	HOOKEVENT(ME_CLIST_PREBUILDCONTACTMENU, &OnPreBuildContactMenu);
	HOOKEVENT(ME_DB_CONTACT_DELETED,        &sipe_miranda_buddy_delete);
	HOOKEVENT(ME_MSG_WINDOWEVENT,           &sipe_miranda_window_closed);
	HOOKEVENT(ME_GC_BUILDMENU,              &sipe_miranda_build_chat_menu);

	return (PROTO_INTERFACE*)pr;
}

static int sipsimpleProtoUninit( PROTO_INTERFACE* _pr )
{
	SIPPROTO *pr = (SIPPROTO *)_pr;

	DeleteCriticalSection(&pr->CriticalSection);

	Netlib_CloseHandle(pr->m_hServerNetlibUser);
	mir_free(pr->proto.m_szProtoName);
	mir_free(pr->proto.m_szModuleName);
	mir_free(pr->proto.m_tszUserName);
	mir_free(pr->proto.vtbl);
	mir_free(pr);

	return 0;
}

__declspec(dllexport) int Load(PLUGINLINK *link)
{
	PROTOCOLDESCRIPTOR pd = {0};
	NETLIBUSER nlu = {0};
	char *tmp;
	WORD iptype;

	pluginLink = link;

	sipe_core_init("");

	mir_getMMI( &mmi );

	/* Register the module */
	pd.cbSize   = sizeof(pd);
	pd.szName   = SIPSIMPLE_PROTOCOL_NAME;
	pd.type     = PROTOTYPE_PROTOCOL;
	pd.fnInit   = sipsimpleProtoInit;
	pd.fnUninit = sipsimpleProtoUninit;
	CallService(MS_PROTO_REGISTERMODULE, 0, (LPARAM)&pd);

	/* Protocolwide netlib user for incoming connections (also abused for logging) */
	nlu.cbSize = sizeof(nlu);
	nlu.flags = NUF_INCOMING | NUF_TCHAR | NUF_NOOPTIONS;
	nlu.szSettingsModule = SIPSIMPLE_PROTOCOL_NAME;
	nlu.minIncomingPorts = 10;

	InitializeCriticalSectionAndSpinCount(&sipe_miranda_debug_CriticalSection, 0);
	sipe_miranda_incoming_netlibuser = (HANDLE)CallService(MS_NETLIB_REGISTERUSER, 0, (LPARAM)&nlu);

	tmp = sipe_miranda_getGlobalString("public_ip");
	if (!tmp) {
		sipe_miranda_setGlobalString("public_ip", "0.0.0.0");
	} else {
		mir_free(tmp);
	}

	if (!sipe_miranda_getGlobalWord("iptype", &iptype))
	{
		sipe_miranda_setGlobalWord("iptype", SIPE_MIRANDA_IP_LOCAL);
	}

	return 0;
}

__declspec(dllexport) int Unload(void)
{
	Netlib_CloseHandle(sipe_miranda_incoming_netlibuser);
	sipe_miranda_incoming_netlibuser = NULL;
	DeleteCriticalSection(&sipe_miranda_debug_CriticalSection);
	sipe_core_destroy();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	hInst = hinstDLL;
	return TRUE;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
