/**
 * @file miranda-buddy.c
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

#include <windows.h>
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_protomod.h"
#include "m_database.h"
#include "m_clist.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     "unset"                  /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     "offline"                /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   "available"              /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_BUSYIDLE    "busyidle"                                                 /* BusyIdle */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_IN_MEETING  "in-a-meeting"                                             /* In a meeting */
#define SIPE_STATUS_ID_IN_CONF     "in-a-conference"                                          /* In a conference */
#define SIPE_STATUS_ID_ON_PHONE    "on-the-phone"                                             /* On the phone */
#define SIPE_STATUS_ID_INVISIBLE   "invisible"              /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        "away"                   /* Away (primitive) */
/** Reuters status (user settable) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */

#define ADD_PROP(key,value) g_hash_table_insert(info_to_property_table, (gpointer)key, value)

static GHashTable *info_to_property_table = NULL;

static void
init_property_hash(void)
{
	info_to_property_table = g_hash_table_new(NULL, NULL);

//	ADD_PROP(SIPE_BUDDY_INFO_DISPLAY_NAME, ALIAS_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_EMAIL       , "e-mail");
	ADD_PROP(SIPE_BUDDY_INFO_WORK_PHONE  , "CompanyPhone");
//	ADD_PROP(SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY, PHONE_DISPLAY_PROP);
//	ADD_PROP(SIPE_BUDDY_INFO_SITE        , SITE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_COMPANY     , "Company");
	ADD_PROP(SIPE_BUDDY_INFO_DEPARTMENT  , "CompanyDepartment");
	ADD_PROP(SIPE_BUDDY_INFO_JOB_TITLE   , "CompanyPosition");
//	ADD_PROP(SIPE_BUDDY_INFO_OFFICE      , OFFICE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_STREET      , "CompanyStreet");
	ADD_PROP(SIPE_BUDDY_INFO_CITY        , "CompanyCity");
	ADD_PROP(SIPE_BUDDY_INFO_STATE       , "CompanyState");
	ADD_PROP(SIPE_BUDDY_INFO_ZIPCODE     , "CompanyZIP");
	ADD_PROP(SIPE_BUDDY_INFO_COUNTRY     , "CompanyCountry");

	/* Summary values:
SetValue(hwndDlg,IDC_NICK,hContact,szProto,"Nick",0);
SetValue(hwndDlg,IDC_FIRSTNAME,hContact,szProto,"FirstName",0);
SetValue(hwndDlg,IDC_LASTNAME,hContact,szProto,"LastName",0);
SetValue(hwndDlg,IDC_EMAIL,hContact,szProto,"e-mail",0);
SetValue(hwndDlg,IDC_AGE,hContact,szProto,"Age",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_GENDER,hContact,szProto,"Gender",SVS_GENDER);
SetValue(hwndDlg,IDC_DOBDAY,hContact,szProto,"BirthDay",0);
SetValue(hwndDlg,IDC_DOBMONTH,hContact,szProto,"BirthMonth",SVS_MONTH);
SetValue(hwndDlg,IDC_DOBYEAR,hContact,szProto,"BirthYear",0);

		Location values:
SetValue(hwndDlg,IDC_STREET,hContact,szProto,"Street",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_CITY,hContact,szProto,"City",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_STATE,hContact,szProto,"State",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_ZIP,hContact,szProto,"ZIP",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_COUNTRY,hContact,szProto,"Country",SVS_COUNTRY);
SetValue(hwndDlg,IDC_LANGUAGE1,hContact,szProto,"Language1",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_LANGUAGE2,hContact,szProto,"Language2",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_LANGUAGE3,hContact,szProto,"Language3",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_TIMEZONE,hContact,szProto,"Timezone",SVS_TIMEZONE);

		Work values:
SetValue(hwndDlg,IDC_COMPANY,hContact,szProto,"Company",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_DEPARTMENT,hContact,szProto,"CompanyDepartment",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_POSITION,hContact,szProto,"CompanyPosition",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_STREET,hContact,szProto,"CompanyStreet",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_CITY,hContact,szProto,"CompanyCity",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_STATE,hContact,szProto,"CompanyState",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_ZIP,hContact,szProto,"CompanyZIP",SVS_ZEROISUNSPEC);
SetValue(hwndDlg,IDC_COUNTRY,hContact,szProto,"CompanyCountry",SVS_COUNTRY);
SetValue(hwndDlg,IDC_WEBPAGE,hContact,szProto,"CompanyHomepage",SVS_ZEROISUNSPEC);

		Background:
SetValue(hwndDlg,IDC_WEBPAGE,hContact,szProto,"Homepage",SVS_ZEROISUNSPEC);

		Contact:
if(DBGetContactSettingTString(hContact,szProto,"e-mail",&dbv))
mir_snprintf(idstr, SIZEOF(idstr), "e-mail%d", i );
mir_snprintf(idstr, SIZEOF(idstr), "Mye-mail%d",i);
if(!DBGetContactSettingTString(hContact,szProto,"Phone",&dbv)) {
if(!DBGetContactSettingTString(hContact,szProto,"Fax",&dbv)) {
if(!DBGetContactSettingTString(hContact,szProto,"Cellular",&dbv)) {
if(!DBGetContactSettingTString(hContact,szProto,"CompanyPhone",&dbv)) {
if(!DBGetContactSettingTString(hContact,szProto,"CompanyFax",&dbv)) {
mir_snprintf(idstr, SIZEOF(idstr), "MyPhone%d",i);

	*/
}

static int SipeStatusToMiranda(const gchar *status) {

	if (!strcmp(status, SIPE_STATUS_ID_OFFLINE))
		return ID_STATUS_OFFLINE;

	if (!strcmp(status, SIPE_STATUS_ID_AVAILABLE))
		return ID_STATUS_ONLINE;

	if (!strcmp(status, SIPE_STATUS_ID_ON_PHONE))
		return ID_STATUS_ONTHEPHONE;

	if (!strcmp(status, SIPE_STATUS_ID_DND))
		return ID_STATUS_DND;

	if (!strcmp(status, SIPE_STATUS_ID_AWAY))
		return ID_STATUS_NA;

	if (!strcmp(status, SIPE_STATUS_ID_LUNCH))
		return ID_STATUS_OUTTOLUNCH;

	if (!strcmp(status, SIPE_STATUS_ID_BUSY))
		return ID_STATUS_OCCUPIED;

	if (!strcmp(status, SIPE_STATUS_ID_INVISIBLE))
		return ID_STATUS_INVISIBLE;

	if (!strcmp(status, SIPE_STATUS_ID_BRB))
		return ID_STATUS_AWAY;

	if (!strcmp(status, SIPE_STATUS_ID_UNKNOWN))
		return ID_STATUS_OFFLINE;

	/* None of those? We'll have to guess. Online seems ok. */
	return ID_STATUS_ONLINE;

	/* Don't have SIPE equivalent of these:
		- ID_STATUS_FREECHAT
	*/

}

static const gchar *
sipe_info_to_miranda_property(sipe_buddy_info_fields info)
{
	if (!info_to_property_table)
		init_property_hash();
	return (const char *)g_hash_table_lookup(info_to_property_table, (gconstpointer)info);
}

sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *name,
					   const gchar *group)
{
	HANDLE hContact;
	SIPPROTO *pr = sipe_public->backend_private;
	SIPE_DEBUG_INFO("buddy_name <%s> group <%s>", name, group);

	hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDFIRST, 0, 0);
	while (hContact) {
		gchar* szProto = (char*)CallService(MS_PROTO_GETCONTACTBASEPROTO, (WPARAM)hContact, 0);
		if (szProto != NULL && !lstrcmpA(szProto, pr->proto.m_szModuleName)) {
			DBVARIANT dbv;
			if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
				int tCompareResult = lstrcmpiA( dbv.pszVal, name );
				DBFreeVariant( &dbv );
				if ( !tCompareResult ) {
					if (!group)
						return hContact;

					if ( !DBGetContactSettingStringUtf(hContact, "CList", "Group", &dbv )) {
						int tCompareResult = lstrcmpiA( dbv.pszVal, group );
						SIPE_DEBUG_INFO("group compare <%s> vs <%s>\n", dbv.pszVal, group);
						DBFreeVariant( &dbv );
						if ( !tCompareResult )
							return hContact;
					} else {
						return NULL;
					}
				}
			}
		}
		hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDNEXT, (WPARAM)hContact, 0);
	}

	return NULL;
}

GSList* sipe_backend_buddy_find_all(struct sipe_core_public *sipe_public,
				    const gchar *buddy_name,
				    const gchar *group_name)
{
	GSList *res = NULL;
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact;
	SIPE_DEBUG_INFO("buddy_name <%s> group <%d>\n", buddy_name, group_name);

	hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDFIRST, 0, 0);
	while (hContact) {
		gchar* szProto = (char*)CallService(MS_PROTO_GETCONTACTBASEPROTO, (WPARAM)hContact, 0);
		if (szProto != NULL && !lstrcmpA(szProto, pr->proto.m_szModuleName)) {
			if (DBGetContactSettingByte(hContact, pr->proto.m_szModuleName, "ChatRoom", 0) == 0) {
				DBVARIANT dbv;
				if (!buddy_name)
					res = g_slist_append(res, hContact);
				else if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
					int tCompareResult = lstrcmpiA( dbv.pszVal, buddy_name );
					DBFreeVariant( &dbv );
					if ( !tCompareResult ) {
						if (!group_name)
							res = g_slist_append(res, hContact);

						else if ( !DBGetContactSettingStringUtf(hContact, "CList", "Group", &dbv )) {
							int tCompareResult = lstrcmpiA( dbv.pszVal, group_name );
							SIPE_DEBUG_INFO("group compare <%s> vs <%s>", dbv.pszVal, group_name);
							DBFreeVariant( &dbv );
							if ( !tCompareResult )
								res = g_slist_append(res, hContact);
						}
					}
				} else {
					SIPE_DEBUG_INFO_NOFORMAT("Could not get SIP id from contact");
				}
			}
		}
		hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDNEXT, (WPARAM)hContact, 0);
	}

	SIPE_DEBUG_INFO("found <%d> buddies", g_slist_length(res));
	return res;
}

gchar* sipe_backend_buddy_get_name(struct sipe_core_public *sipe_public,
				   const sipe_backend_buddy who)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)who;
	gchar *alias;
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;

	if ( !DBGetContactSettingString( hContact, module, SIP_UNIQUEID, &dbv )) {
		alias = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );
		return alias;
	}

	return NULL;
}

gchar* sipe_backend_buddy_get_alias(struct sipe_core_public *sipe_public,
				    const sipe_backend_buddy who)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)who;
	gchar *alias;
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;

	if ( DBGetContactSettingString( hContact, module, "Nick", &dbv )
	  && DBGetContactSettingString( hContact, module, "Alias", &dbv )
	  && DBGetContactSettingString( hContact, module, SIP_UNIQUEID, &dbv ))
			return NULL;

	alias = g_strdup(dbv.pszVal);
	DBFreeVariant( &dbv );
	return alias;
}

gchar* sipe_backend_buddy_get_server_alias(struct sipe_core_public *sipe_public,
					   const sipe_backend_buddy who)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)who;
	char *alias;
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;

	if ( !DBGetContactSettingString( hContact, module, "Alias", &dbv )) {
		alias = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );
		return alias;
	}

	return NULL;
}

gchar* sipe_backend_buddy_get_group_name(struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)who;
	gchar *alias;
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;

	if ( !DBGetContactSettingString( hContact, "CList", "Group", &dbv )) {
		alias = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );
		return alias;
	}

	return NULL;
}

void sipe_backend_buddy_set_alias(struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact = (HANDLE)who;

	SIPE_DEBUG_INFO("miranda_sipe_set_buddy_alias: Set alias of contact <%x> to <%s>", who, alias);
	sipe_miranda_setContactStringUtf( pr, hContact, "Nick", alias );
}

void sipe_backend_buddy_set_server_alias(struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who,
					 const gchar *alias)
{
	HANDLE hContact = (HANDLE)who;
	SIPPROTO *pr = sipe_public->backend_private;

	SIPE_DEBUG_INFO("Set alias of contact <%x> to <%s>", who, alias);
	sipe_miranda_setContactStringUtf( pr, hContact, "Alias", alias );
}

gchar* sipe_backend_buddy_get_string(struct sipe_core_public *sipe_public,
				     sipe_backend_buddy buddy,
				     const sipe_buddy_info_fields key)
{
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;
	const gchar *prop_name = sipe_info_to_miranda_property(key);
	char *tmp;
	char *prop_str;

	if (!prop_name)
		return NULL;

	tmp = sipe_miranda_getContactString(pr, buddy, prop_name);
	prop_str = g_strdup(tmp);
	mir_free(tmp);

	return prop_str;
}

void sipe_backend_buddy_set_string(struct sipe_core_public *sipe_public,
				   sipe_backend_buddy buddy,
				   const sipe_buddy_info_fields key,
				   const gchar *val)
{
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;
	const gchar *prop_name = sipe_info_to_miranda_property(key);

	SIPE_DEBUG_INFO("miranda_sipe_buddy_set_string: buddy <%x> key <%d = %s> val <%s>", buddy, key, prop_name, val);
	if (!prop_name)
		return;

	sipe_miranda_setContactString(pr, buddy, prop_name, val);
}

sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *groupname)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact;

	SIPE_DEBUG_INFO("miranda_sipe_add_buddy: Adding miranda contact for buddy <%s> alias <%s> in <%s>", name, alias, groupname);
	hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
	CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
	sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, name ); // name
	if (alias) sipe_miranda_setContactStringUtf( pr, hContact, "Nick", alias );
	DBWriteContactSettingString( hContact, "CList", "Group", groupname );
	return (sipe_backend_buddy)hContact;
}

void sipe_backend_buddy_remove(struct sipe_core_public *sipe_public,
			       const sipe_backend_buddy who)
{
	CallService( MS_DB_CONTACT_DELETE, (WPARAM)who, 0 );
}

void sipe_backend_buddy_request_authorization(struct sipe_core_public *sipe_public,
					      const gchar *who,
					      const gchar *alias,
					      gboolean on_list,
					      sipe_backend_buddy_request_authorization_cb auth_cb,
					      sipe_backend_buddy_request_authorization_cb deny_cb,
					      void *data)
{
	_NIF();
	auth_cb(data);
}

void sipe_backend_buddy_request_add(struct sipe_core_public *sipe_public,
				    const gchar *who,
				    const gchar *alias)
{
	_NIF();
}

gboolean sipe_backend_buddy_is_blocked(struct sipe_core_public *sipe_public,
				       const gchar *who)
{
	_NIF();
	return FALSE;
}

void sipe_backend_buddy_set_blocked_status(struct sipe_core_public *sipe_public,
					   const gchar *who,
					   gboolean blocked)
{
	_NIF();
}

void sipe_backend_buddy_set_status(struct sipe_core_public *sipe_public,
				   const gchar *who,
				   const gchar *status_id)
{
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;
	GSList *contacts = sipe_backend_buddy_find_all(sipe_public, who, NULL);

	BUDDIES_FOREACH(contacts)
		sipe_miranda_setWord(pr, hContact, "Status", SipeStatusToMiranda(status_id));
	BUDDIES_FOREACH_END;

}

gboolean sipe_backend_buddy_group_add(struct sipe_core_public *sipe_public,
				      const gchar *group_name)
{
	TCHAR *mir_group_name = mir_a2t(group_name);
	HANDLE hGroup = (HANDLE)CallService(MS_CLIST_GROUPCREATE, 0, (LPARAM)mir_group_name);
	mir_free(mir_group_name);
	return (hGroup?TRUE:FALSE);
}

int sipe_miranda_buddy_delete(SIPPROTO *pr, HANDLE hContact, LPARAM lParam)
{
	DBVARIANT dbv;
	char *name;
	char *groupname;

	SIPE_DEBUG_INFO("Deleting contact <%08x>", hContact);

	if ( DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv ))
		return 0;

	name = g_strdup(dbv.pszVal);
	DBFreeVariant( &dbv );

	if ( DBGetContactSettingString( hContact, "CList", "Group", &dbv ))
	{
		g_free(name);
		return 0;
	}

	groupname = g_strdup(dbv.pszVal);
	DBFreeVariant( &dbv );

	sipe_core_buddy_remove(pr->sip, name, groupname);
	return 0;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
