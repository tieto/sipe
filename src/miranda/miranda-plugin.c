/**
 * @file miranda-plugin.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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
#define MIRANDA_VER 0x900

#include <windows.h>
#include <win2k.h>
#include <Richedit.h>
#include <stdio.h>

#include <glib.h>

#include "sipe-common.h"

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

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-nls.h"
#include "sipe-conf.h"
#include "sipe-utils.h"
#include "sipe-session.h"
#include "sipe-chat.h"
#include "sipe.h"
#include "miranda-private.h"
#include "miranda-resource.h"

/* FIXME: Not here */
void CreateProtoService(const SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc);

HANDLE sipe_miranda_incoming_netlibuser = NULL;
CRITICAL_SECTION sipe_miranda_debug_CriticalSection;

/* Sipe core activity <-> Miranda status mapping */
static const gchar * const activity_to_miranda[SIPE_ACTIVITY_NUM_TYPES] = {
	/* SIPE_ACTIVITY_UNSET       */ "unset",
	/* SIPE_ACTIVITY_ONLINE      */ "online",
	/* SIPE_ACTIVITY_INACTIVE    */ "idle",
	/* SIPE_ACTIVITY_BUSY        */ "busy",
	/* SIPE_ACTIVITY_BUSYIDLE    */ "busyidle",
	/* SIPE_ACTIVITY_DND         */ "do-not-disturb",
	/* SIPE_ACTIVITY_BRB         */ "be-right-back",
	/* SIPE_ACTIVITY_AWAY        */ "away",
	/* SIPE_ACTIVITY_LUNCH       */ "out-to-lunch",
	/* SIPE_ACTIVITY_OFFLINE     */ "offline", 
	/* SIPE_ACTIVITY_ON_PHONE    */ "on-the-phone",
	/* SIPE_ACTIVITY_IN_CONF     */ "in-a-conference",
	/* SIPE_ACTIVITY_IN_MEETING  */ "in-a-meeting",
	/* SIPE_ACTIVITY_OOF         */ "out-of-office",
	/* SIPE_ACTIVITY_URGENT_ONLY */ "urgent-interruptions-only",
};
GHashTable *miranda_to_activity = NULL;
#define MIRANDA_STATUS_TO_ACTIVITY(x) \
	GPOINTER_TO_UINT(g_hash_table_lookup(miranda_to_activity, (x)))

static void sipe_miranda_activity_init(void)
{
	sipe_activity index = SIPE_ACTIVITY_UNSET;
	miranda_to_activity = g_hash_table_new(g_str_hash, g_str_equal);
	while (index < SIPE_ACTIVITY_NUM_TYPES) {
		g_hash_table_insert(miranda_to_activity,
				    (gpointer) activity_to_miranda[index],
				    GUINT_TO_POINTER(index));
		index++;
	}
}

gchar *sipe_backend_version(void)
{
	char version[200];

	if (CallService(MS_SYSTEM_GETVERSIONTEXT, sizeof(version), (LPARAM)version)) {
		strcpy(version, "Unknown");
	}

	return g_strdup_printf("Miranda %s SIPLCS " __DATE__ " " __TIME__, version );
}

static void sipe_miranda_activity_destroy(void)
{
	g_hash_table_destroy(miranda_to_activity);
	miranda_to_activity = NULL;
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

/*
 * Dialog boxes
 */
INT_PTR CALLBACK DlgProcSipSimpleOptsAbout(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			SIPPROTO *pr = (SIPPROTO *)lParam;
			SETTEXTEX tex;
			gchar *about;
			LOCK;
			about = sipe_core_about();
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

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			lock++;

			str = DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog");
			SetDlgItemTextA(hwndDlg, IDC_DEBUGLOG, str);
			SendDlgItemMessage(hwndDlg, IDC_DEBUGLOG, EM_SETLIMITTEXT, 100, 0);
			mir_free(str);

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

			lock--;
			return TRUE;
		}

		case WM_COMMAND:
		{
			int code = wParam >> 16;
			int id = wParam & 0xffff;

			if (!lock && (code == EN_CHANGE || code == CBN_SELCHANGE)) {
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

				GetDlgItemTextA(hwndDlg, IDC_DEBUGLOG, buf, sizeof(buf));
				DBWriteContactSettingString(NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog", buf);

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

				GetDlgItemTextA(hwndDlg, IDC_PUBLICIP, buf, sizeof(buf));
				sipe_miranda_setGlobalString("public_ip", buf);

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

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);


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
			if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == GetFocus())
			{
				switch(LOWORD(wParam))
				{
					case IDC_HANDLE:
					case IDC_LOGIN:
					case IDC_PASSWORD:
						SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
				}
			}
			break;

		case WM_NOTIFY:
			if (((LPNMHDR)lParam)->code == (UINT)PSN_APPLY)
			{
				char buf[100];

				const SIPPROTO *pr = (const SIPPROTO *)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

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

static void set_if_defined(SIPPROTO *pr, GHashTable *store, HANDLE hContact, sipe_buddy_info_fields field, char *label)
{
	char *value = (char *)g_hash_table_lookup(store, (gpointer)field);
	if (value)
		sipe_miranda_setContactStringUtf(pr, hContact, label, value);
}

static INT_PTR StartChat(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	struct sipe_core_public *sipe_public = pr->sip;
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	DBVARIANT dbv;
	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		{
			LOCK;
			sipe_conf_add(sipe_private, dbv.pszVal);
			UNLOCK;
		}
		else /* 2005- multiparty chat */
		{
			gchar *self = sip_uri_self(sipe_private);
			struct sip_session *session;

			LOCK;
			session = sipe_session_add_chat(sipe_private,
							NULL,
							TRUE,
							self);
			session->chat_session->backend = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
										  session->chat_session,
										  session->chat_session->title,
										  self);
			g_free(self);

			sipe_im_invite(sipe_private, session, dbv.pszVal, NULL, NULL, NULL, FALSE);
			UNLOCK;
		}
		DBFreeVariant( &dbv );
		return TRUE;
	}

	return FALSE;
}

static void OnModulesLoaded(SIPPROTO *pr)
{
	TCHAR descr[MAX_PATH];
	NETLIBUSER nlu = {0};
	char service_name[200];
	GCREGISTER gcr;
	CLISTMENUITEM mi = {0};
	DBEVENTTYPEDESCR eventType = {0};

	SIPE_DEBUG_INFO_NOFORMAT("OnEvent::OnModulesLoaded");

	nlu.cbSize = sizeof(nlu);
	nlu.flags = NUF_OUTGOING | NUF_TCHAR;
	nlu.szSettingsModule = pr->proto.m_szModuleName;
	_sntprintf(descr, SIZEOF(descr), TranslateT("%s server connection"), pr->proto.m_tszUserName );
	nlu.ptszDescriptiveName = descr;

	pr->m_hServerNetlibUser = (HANDLE)CallService(MS_NETLIB_REGISTERUSER, 0, (LPARAM)&nlu);

	mi.cbSize = sizeof( mi );
	mi.pszContactOwner = pr->proto.m_szModuleName;
	mi.pszService = service_name;

	mir_snprintf(service_name, sizeof(service_name), "%s%s", pr->proto.m_szModuleName, "/StartChat");
	CreateProtoService(pr, "/StartChat",&StartChat);
	mi.position=-2000005060;
	mi.icolibItem = NULL; //GetIconHandle("block");
	mi.pszName = LPGEN("&Start Chat");
	mi.flags=0; //CMIF_ICONFROMICOLIB|CMIF_HIDDEN;
	CallService(MS_CLIST_ADDCONTACTMENUITEM,0,(LPARAM)&mi);

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

static void sipe_miranda_login(SIPPROTO *pr) {
	gchar *username = sipe_miranda_getString(pr, "username");
	gchar *login = sipe_miranda_getString(pr, "login");
	gchar *email = sipe_miranda_getString(pr, "email");
	gchar *email_url = sipe_miranda_getString(pr, "email_url");
	gchar **domain_user = g_strsplit_set(login, "/\\", 2);
	const gchar *errmsg;
	gchar *password;
	char *tmp = (char*)mir_calloc(1024);
	int tmpstatus;

	if (sipe_miranda_getStaticString(pr, NULL, "password", tmp, 1024 )) tmp[0] = '\0';
	CallService(MS_DB_CRYPT_DECODESTRING, sizeof(tmp),(LPARAM)tmp);
	password = g_strdup(tmp);
	mir_free(tmp);

	LOCK;
	pr->sip = sipe_core_allocate(username,
					    domain_user[0], domain_user[1],
					    password,
					    email,
					    email_url,
					    &errmsg);
	if (pr->sip) pr->sip->backend_private = pr;
	UNLOCK;

	mir_free(username);
	mir_free(login);
	mir_free(email);
	mir_free(email_url);
	g_strfreev(domain_user);
	g_free(password);

	if (!pr->sip) {
		sipe_miranda_connection_error_reason(pr,
						     SIPE_CONNECTION_ERROR_INVALID_USERNAME, 
						     errmsg);
		return;
	}

	//sipe_miranda_chat_setup_rejoin(pr);

#if defined(HAVE_LIBKRB5) || defined(HAVE_SSPI)
//	if (purple_account_get_bool(account, "krb5", FALSE))
//		SIPE_CORE_FLAG_SET(KRB5);
#endif
//	/* @TODO: is this correct?
//	   "sso" is only available when Kerberos support is compiled in */
//	if (purple_account_get_bool(account, "sso", TRUE))
//		SIPE_CORE_FLAG_SET(SSO);

	/* Set display name */
	sipe_miranda_setStringUtf(pr, "Nick", pr->sip->sip_name);

	/* Update connection progress */
	tmpstatus = pr->proto.m_iStatus;
	pr->proto.m_iStatus = ID_STATUS_CONNECTING;
	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)tmpstatus, ID_STATUS_CONNECTING);

/*
	username_split = g_strsplit(purple_account_get_string(account, "server", ""), ":", 2);
	if (sipe_strequal(transport, "auto")) {
		type = (username_split[0] == NULL) ?
			SIPE_TRANSPORT_AUTO : SIPE_TRANSPORT_TLS;
	} else if (sipe_strequal(transport, "tls")) {
		type = SIPE_TRANSPORT_TLS;
	} else {
		type = SIPE_TRANSPORT_TCP;
	}

	sipe_core_transport_sip_connect(pr->sip,
					type,
					username_split[0],
					username_split[0] ? username_split[1] : NULL);
	g_strfreev(username_split);
*/
	LOCK;
	sipe_core_transport_sip_connect(pr->sip,
					SIPE_TRANSPORT_AUTO,
					NULL,
					NULL);
	UNLOCK;
}

static gboolean
miranda_sipe_get_info_cb(struct sipe_core_public *sipe_public, const char* uri, GHashTable *results, void* data )
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact = (HANDLE) data;

	GHashTableIter iter;
	const char *id, *value;

	g_hash_table_iter_init( &iter, results);
	while (g_hash_table_iter_next (&iter, (gpointer *)&id, (gpointer *)&value)) {
		SIPE_DEBUG_INFO("miranda_sipe_get_info_cb: user info field <%d> = <%s>", id, value ? value : "(none)");
	}
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_EMAIL, "e-mail");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_CITY, "City");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_STATE, "State");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_COUNTRY, "Country");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_COMPANY, "Company");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_JOB_TITLE, "CompanyPosition");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_WORK_PHONE, "CompanyPhone");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_STREET, "CompanyStreet");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_ZIPCODE, "CompanyZIP");
	set_if_defined(pr, results, hContact, SIPE_BUDDY_INFO_DEPARTMENT, "CompanyDepartment");

	sipe_miranda_SendBroadcast(pr, hContact, ACKTYPE_GETINFO, ACKRESULT_SUCCESS, (HANDLE) 1, (LPARAM) 0);
	return TRUE;
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
		col = (GList*)row->data;
		psr.nick = (PROTOCHAR*)col->data;

		col = g_list_next(col);
		psr.lastName = (PROTOCHAR*)col->data;

		col = g_list_next(col);
		/* company */

		col = g_list_next(col);
		/* country */

		col = g_list_next(col);
		psr.email = (PROTOCHAR*)col->data;

		row = g_list_next(row);
		sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_DATA, hProcess, (LPARAM) & psr);
	}

	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_SUCCESS, hProcess, 0);

}

static int OnGroupChange(SIPPROTO *pr, WPARAM w, LPARAM l )
{
	CLISTGROUPCHANGE *gi = (CLISTGROUPCHANGE*)l;
	HANDLE hContact = (HANDLE)w;
	DBVARIANT dbv;
	char *who;

	/* No contact => it's a group add/rename/remove */
	if (!hContact)
	{
		/* No old name => add */
		if (!gi->pszOldName)
		{
			return 0;
		}
		/* No new name => delete */
		else if (!gi->pszNewName)
		{
			SIPE_DEBUG_INFO("Removing group <%ls>", gi->pszOldName);
			LOCK;
			sipe_core_group_remove(pr->sip, TCHAR2CHAR(gi->pszOldName));
			UNLOCK;
			return 0;
		}

		SIPE_DEBUG_INFO("Renaming group <%ls> to <%ls>", gi->pszOldName, gi->pszNewName);
		LOCK;
		sipe_core_group_rename(pr->sip, TCHAR2CHAR(gi->pszOldName), TCHAR2CHAR(gi->pszNewName));
		UNLOCK;
		return 0;
	}

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		gchar *oldgroup;
		who = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );

		if (oldgroup = sipe_miranda_getContactString(pr, hContact, "Group"))
		{
			SIPE_DEBUG_INFO("Moving buddy <%s> from group <%ls> to group <%ls>", who, oldgroup, gi->pszNewName);
			LOCK;
			sipe_core_buddy_group(pr->sip, who, oldgroup, TCHAR2CHAR(gi->pszNewName));
			UNLOCK;
			mir_free(oldgroup);
		} else {
			gchar *name = TCHAR2CHAR(gi->pszNewName);
			const gchar *newname;

			SIPE_DEBUG_INFO("Really adding buddy <%s> to list in group <%ls>", who, gi->pszNewName);
			LOCK;
			newname = sipe_core_buddy_add(pr->sip, who, name);
			UNLOCK;

			if (!sipe_strequal(who,newname))
			{
				sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, newname);
			}
		}

		g_free(who);
	}

	return TRUE;
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
	}

	return FALSE;
}

int OnPreBuildContactMenu(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	int chatcount = CallService(MS_GC_GETSESSIONCOUNT, 0, (LPARAM)pr->proto.m_szModuleName);
	int idx;
	GSList *menulist = pr->contactMenuChatItems;
	CLISTMENUITEM mi = {0};
	GC_INFO gci = {0};

	mi.cbSize = sizeof(mi);
	gci.pszModule = pr->proto.m_szModuleName;

	for (idx=0 ; idx<chatcount ; idx++)
	{
		SIPE_DEBUG_INFO("Chat <%d> Menuitem <%08x>", idx, menulist);
		gci.iItem = idx;
		gci.Flags = BYINDEX | NAME;
		if(!CallServiceSync( MS_GC_GETINFO, 0, (LPARAM)&gci )) {
			if (menulist)
			{
				SIPE_DEBUG_INFO("Chat <%s> Menuitem <%08x>", gci.pszName, menulist);
				mi.pszName = g_strdup_printf("Invite to %s", gci.pszName);
				mi.flags = CMIM_NAME | CMIM_FLAGS | CMIF_NOTOFFLINE;
				CallService(MS_CLIST_MODIFYMENUITEM, (WPARAM)menulist->data, (LPARAM)&mi);
				g_free(mi.pszName);
				menulist =  menulist->next;
			}
			else
			{
				gpointer tmp;
				SIPE_DEBUG_INFO("Chat <%s>", gci.pszName);

				mi.pszName = g_strdup_printf("Invite to %s", gci.pszName);
				mi.flags = CMIF_NOTOFFLINE;
				mi.position = 20+idx;
				mi.pszService = "SIPSIMPLE/InviteToChat";
				mi.pszContactOwner = pr->proto.m_szModuleName;
				tmp = CallService(MS_CLIST_ADDCONTACTMENUITEM, 0, (LPARAM)&mi);
				g_free(mi.pszName);
				pr->contactMenuChatItems = g_slist_append(pr->contactMenuChatItems, tmp);
			}
		}
	}

	while (menulist)
	{
		SIPE_DEBUG_INFO("Menuitem <%08x>", menulist);
		mi.flags = CMIM_FLAGS | CMIF_HIDDEN;
		CallService(MS_CLIST_MODIFYMENUITEM, (WPARAM)menulist, (LPARAM)&mi);
		menulist =  menulist->next;
	}

	return 0;
}

INT_PTR  SvcCreateAccMgrUI(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	return (INT_PTR)CreateDialogParam(hInst, MAKEINTRESOURCE(IDD_ACCMGRUI), (HWND)lParam, DlgProcAccMgrUI, (LPARAM)pr);
}

static void GetAwayMsgThread(SIPPROTO *pr, HANDLE hContact)
{
	const gchar *status;
	gchar *name = sipe_miranda_getContactString(pr, hContact, SIP_UNIQUEID);
	gchar *tmp = NULL;

	if (!name)
	{
		SIPE_DEBUG_INFO("Could not find name for contact <%08x>", hContact);
		SendProtoAck(pr, hContact, 1, ACKRESULT_FAILED, ACKTYPE_AWAYMSG, NULL);
		return;
	}

	LOCK;
	status = sipe_core_buddy_status(pr->sip,
					name,
					SIPE_ACTIVITY_BUSYIDLE,
					"dummy test string");
	UNLOCK;

	if (status)
		tmp = sipe_miranda_eliminate_html(status, strlen(status));

	SendProtoAck(pr, hContact, 1, ACKRESULT_SUCCESS, ACKTYPE_AWAYMSG, tmp);

	mir_free(tmp);
	mir_free(name);
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
				| PF1_SERVERCLIST | PF1_AUTHREQ | PF1_ADDED
				| PF1_BASICSEARCH | PF1_ADDSEARCHRES
				| PF1_SEARCHBYEMAIL | PF1_USERIDISEMAIL
				| PF1_SEARCHBYNAME
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

	return NULL;
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

static int SetStatus( SIPPROTO *pr, int iNewStatus )
{
	int oldStatus;
	if (!pr->m_hServerNetlibUser) return 0;
	if (pr->proto.m_iDesiredStatus == iNewStatus) return 0;

	oldStatus = pr->proto.m_iStatus;
	pr->proto.m_iDesiredStatus = iNewStatus;

	SIPE_DEBUG_INFO("SetStatus: newstatus <%x>", iNewStatus);

	if (iNewStatus == ID_STATUS_OFFLINE) {
		pr->disconnecting = TRUE;
		sipe_miranda_connection_destroy(pr);
		pr->valid = FALSE;
		pr->disconnecting = FALSE;
	} else {
		if (pr->proto.m_iStatus == ID_STATUS_OFFLINE) {
			pr->valid = TRUE;
			pr->state = SIPE_MIRANDA_CONNECTING;
			pr->proto.m_iStatus = ID_STATUS_CONNECTING;
			sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
			sipe_miranda_login(pr);
		} else if (pr->state == SIPE_MIRANDA_CONNECTED) {
			pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
			sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
			LOCK;
			if (pr->proto.m_iStatus != ID_STATUS_OFFLINE) {
				gchar *note = sipe_miranda_getString(pr, "note");
				sipe_core_set_status(pr->sip, note, MirandaStatusToSipe(iNewStatus));
				mir_free(note);
			}
			UNLOCK;
		}
	}


/*
//Will send an ack with:
//type=ACKTYPE_STATUS, result=ACKRESULT_SUCCESS, hProcess=(HANDLE)previousMode, lParam=newMode
//when the change completes. This ack is sent for all changes, not just ones
//caused by calling this function.
//Note that newMode can be ID_STATUS_CONNECTING<=newMode<ID_STATUS_CONNECTING+
//MAX_CONNECT_RETRIES to signify that it's connecting and it's the nth retry.
//Protocols are initially always in offline mode.
//Non-network-level protocol modules do not have the concept of a status and
//should leave this service unimplemented
//If a protocol doesn't support the specific status mode, it should pick the
*/

	return 0;
}

static int UserIsTyping( SIPPROTO *pr, HANDLE hContact, int type )
{
	SIPE_DEBUG_INFO("UserIsTyping: type <%x>", type);
	if (hContact)
	{
		DBVARIANT dbv;
		char *name;

		if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
			name = g_strdup(dbv.pszVal);
			DBFreeVariant(&dbv);
		} else {
			return 1;
		}

		switch (type) {
			case PROTOTYPE_SELFTYPING_ON:
				LOCK;
				sipe_core_user_feedback_typing(pr->sip, name);
				UNLOCK;
				g_free(name);
				return 0;

			case PROTOTYPE_SELFTYPING_OFF:
				/* Not supported anymore? */
				g_free(name);
				return 0;
		}

		g_free(name);
	}

	return 1;
}

static HANDLE AddToListByEvent( SIPPROTO *pr, int flags, int iContact, HANDLE hDbEvent )
{
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

static int FileDeny( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szReason )
{
	_NIF();
	SIPE_DEBUG_INFO("FileDeny: reason <%s>", szReason);
	return 0;
}

static int FileResume( SIPPROTO *pr, HANDLE hTransfer, int* action, const PROTOCHAR** szFilename )
{
	_NIF();
	SIPE_DEBUG_INFO("FileResume: action <%x>", action);
	return 0;
}

static int GetInfo( SIPPROTO *pr, HANDLE hContact, int infoType )
{
	DBVARIANT dbv;

	SIPE_DEBUG_INFO("GetInfo: infotype <%x>", infoType);

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		LOCK;
		sipe_get_info(pr->sip, dbv.pszVal, miranda_sipe_get_info_cb, hContact);
		UNLOCK;
		DBFreeVariant( &dbv );
	}

	return 0;
}

static HANDLE SearchBasic( SIPPROTO *pr, const PROTOCHAR* id )
{
	return NULL;
}

static HWND SearchAdvanced( SIPPROTO *pr, HWND owner )
{
	_NIF();
	return NULL;
}

static HWND CreateExtendedSearchUI( SIPPROTO *pr, HWND owner )
{
	_NIF();
	return NULL;
}

static HANDLE SearchByEmail( SIPPROTO *pr, const PROTOCHAR* email )
{
	GHashTable *query = g_hash_table_new(NULL,NULL);
	HANDLE ret;

	SIPE_DEBUG_INFO("SearchByEmail: email <%s>", email);

	g_hash_table_insert(query, "email", (gpointer)email);

	LOCK;
	ret = (HANDLE)sipe_core_buddy_search( pr->sip, query, sipsimple_search_contact_cb, pr);
	UNLOCK;

	return ret;

}

static HANDLE SearchByName( SIPPROTO *pr, const PROTOCHAR* nick, const PROTOCHAR* firstName, const PROTOCHAR* lastName)
{
	GHashTable *query = g_hash_table_new(NULL,NULL);
	HANDLE ret;

	SIPE_DEBUG_INFO("SearchByName: nick <%s> firstname <%s> lastname <%s>", nick, firstName, lastName);

	g_hash_table_insert(query, "givenName", (gpointer)mir_t2a(firstName));
	g_hash_table_insert(query, "sn", (gpointer)mir_t2a(lastName));

	LOCK;
	ret = (HANDLE)sipe_core_buddy_search( pr->sip, query, sipsimple_search_contact_cb, pr);
	UNLOCK;

	return ret;
}

static HANDLE AddToList( SIPPROTO *pr, int flags, PROTOSEARCHRESULT* psr )
{
	HANDLE hContact;
	gchar *nick = g_strdup(TCHAR2CHAR(psr->nick));

	/* Prepend sip: if needed */
	if (strncmp("sip:", nick, 4)) {
		gchar *tmp = nick;
		nick = sip_uri_from_name(tmp);
		g_free(tmp);
	}

	hContact = sipe_miranda_buddy_find(pr, nick, NULL);
	if (hContact) {
		g_free(nick);
		return hContact;
	}

	hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
	CallService( MS_PROTO_ADDTOCONTACT, (WPARAM)hContact, (LPARAM)pr->proto.m_szModuleName );
	sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, nick ); // name
	if (psr->lastName) sipe_miranda_setContactStringUtf( pr, hContact, "Nick", mir_t2a(psr->lastName) );               // server_alias

	g_free(nick);
	return hContact;
}

static HANDLE GetAwayMsg( SIPPROTO *pr, HANDLE hContact )
{
	ForkThread( pr, ( SipSimpleThreadFunc )&GetAwayMsgThread, hContact );
	return (HANDLE)1;
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
	"SIP/Simple Protocol",
	PLUGIN_MAKE_VERSION(9,12,19,12),
	"Support for SIP/Simple as used by Communicator 2007.",
	"Miranda support by Jochen De Smet, for core sipe support see homepage",
	"jochen.libsipe@leahnim.org",
	"(C)2009-2010",
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
	SIPPROTO *pr = (SIPPROTO *)mir_calloc(sizeof(SIPPROTO));
	pr->proto.vtbl = (PROTO_INTERFACE_VTBL*)mir_calloc(sizeof(PROTO_INTERFACE_VTBL));

	SIPE_DEBUG_INFO("protoname <%s> username <%ls>", pszProtoName, tszUserName);

	if (!InitializeCriticalSectionAndSpinCount(&pr->CriticalSection, 0))
	{
		SIPE_DEBUG_ERROR_NOFORMAT("Can't initialize critical section");
		return NULL;
	}

	/* To make it easy to detect when a SIPPROTO* isn't a SIPPROTO* */
	strncpy(pr->_SIGNATURE, "AbandonAllHope..", sizeof(pr->_SIGNATURE));

	pr->main_thread_id = GetCurrentThreadId();
	pr->proto.m_iVersion = 2;
	pr->proto.m_szModuleName = mir_strdup(pszProtoName);
	pr->proto.m_tszUserName = mir_tstrdup(tszUserName);
	pr->proto.m_szProtoName = mir_strdup(pszProtoName);

	set_buddies_offline(pr);
	fix_contact_groups(pr);

	/* Fill the function table */
	pr->proto.vtbl->AddToList              = AddToList;
	pr->proto.vtbl->AddToListByEvent       = AddToListByEvent;

	pr->proto.vtbl->Authorize              = Authorize;
	pr->proto.vtbl->AuthDeny               = AuthDeny;
	pr->proto.vtbl->AuthRecv               = AuthRecv;
	pr->proto.vtbl->AuthRequest            = AuthRequest;

	pr->proto.vtbl->ChangeInfo             = ChangeInfo;

	pr->proto.vtbl->FileAllow              = sipe_miranda_FileAllow;
	pr->proto.vtbl->FileCancel             = FileCancel;
	pr->proto.vtbl->FileDeny               = FileDeny;
	pr->proto.vtbl->FileResume             = FileResume;

	pr->proto.vtbl->GetCaps                = GetCaps;
	pr->proto.vtbl->GetIcon                = GetIcon;
	pr->proto.vtbl->GetInfo                = GetInfo;

	pr->proto.vtbl->SearchBasic            = SearchBasic;
	pr->proto.vtbl->SearchByEmail          = SearchByEmail;
	pr->proto.vtbl->SearchByName           = SearchByName;
	pr->proto.vtbl->SearchAdvanced         = SearchAdvanced;
	pr->proto.vtbl->CreateExtendedSearchUI = CreateExtendedSearchUI;

	pr->proto.vtbl->RecvMsg                = sipe_miranda_RecvMsg;

	pr->proto.vtbl->SendMsg                = sipe_miranda_SendMsg;

	pr->proto.vtbl->SetStatus              = SetStatus;

	pr->proto.vtbl->GetAwayMsg             = GetAwayMsg;
	pr->proto.vtbl->SetAwayMsg             = sipe_miranda_SetAwayMsg;

	pr->proto.vtbl->UserIsTyping           = UserIsTyping;

	pr->proto.vtbl->SendFile               = sipe_miranda_SendFile;
	pr->proto.vtbl->RecvFile               = sipe_miranda_RecvFile;

	pr->proto.vtbl->OnEvent                = OnEvent;

	/* Setup services */
	CreateProtoService(pr, PS_CREATEACCMGRUI, &SvcCreateAccMgrUI );

	HookProtoEvent(pr, ME_OPT_INITIALISE, &OnOptionsInit);
	HookProtoEvent(pr, ME_CLIST_GROUPCHANGE, &OnGroupChange );
	HookProtoEvent(pr, ME_GC_EVENT, &OnChatEvent );
	HookProtoEvent(pr, ME_CLIST_PREBUILDCONTACTMENU, &OnPreBuildContactMenu );
	HookProtoEvent(pr, ME_DB_CONTACT_DELETED, &sipe_miranda_buddy_delete );

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

	pluginLink = link;

	sipe_core_init("");
	sipe_miranda_activity_init();

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

	return 0;
}

__declspec(dllexport) int Unload(void)
{
	Netlib_CloseHandle(sipe_miranda_incoming_netlibuser);
	DeleteCriticalSection(&sipe_miranda_debug_CriticalSection);
	sipe_miranda_activity_destroy();
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
