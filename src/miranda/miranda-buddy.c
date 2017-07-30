/**
 * @file miranda-buddy.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-12 SIPE Project <http://sipe.sourceforge.net/>
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

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_protomod.h"
#include "m_database.h"
#include "m_clist.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

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

static const gchar *
sipe_info_to_miranda_property(sipe_buddy_info_fields info)
{
	if (!info_to_property_table)
		init_property_hash();
	return (const char *)g_hash_table_lookup(info_to_property_table, (gconstpointer)info);
}

sipe_backend_buddy sipe_miranda_buddy_find(SIPPROTO *pr,
					   const gchar *name,
					   const gchar *group)
{
	HANDLE hContact;

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
					{
						SIPE_DEBUG_INFO("buddy_name <%s> group <%s> found <%08x>", name, group, hContact);
						return hContact;
					}

					if ( !DBGetContactSettingStringUtf(hContact, "CList", "Group", &dbv )) {
						int tCompareResult = lstrcmpiA( dbv.pszVal, group );
						DBFreeVariant( &dbv );
						if ( !tCompareResult )
						{
							SIPE_DEBUG_INFO("buddy_name <%s> group <%s> found <%08x> in group", name, group, hContact);
							return hContact;
						}
					} else {
						SIPE_DEBUG_INFO("buddy_name <%s> group <%s> ERROR getting contact group", name, group);
						return NULL;
					}
				}
			}
		}
		hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDNEXT, (WPARAM)hContact, 0);
	}

	SIPE_DEBUG_INFO("buddy_name <%s> group <%s> NOT FOUND", name, group);
	return NULL;
}
sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *name,
					   const gchar *group)
{
	return sipe_miranda_buddy_find(sipe_public->backend_private, name, group);
}

GSList* sipe_miranda_buddy_find_all(SIPPROTO *pr,
				    const gchar *buddy_name,
				    const gchar *group_name)
{
	GSList *res = NULL;
	HANDLE hContact;

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

	SIPE_DEBUG_INFO("name <%s> group <%s> found <%d> buddies", buddy_name, group_name, g_slist_length(res));
	return res;
}

GSList* sipe_backend_buddy_find_all(struct sipe_core_public *sipe_public,
				    const gchar *buddy_name,
				    const gchar *group_name)
{
	return sipe_miranda_buddy_find_all(sipe_public->backend_private, buddy_name, group_name);
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

gchar* sipe_backend_buddy_get_local_alias(struct sipe_core_public *sipe_public,
					   const sipe_backend_buddy who)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)who;
	char *alias;
	SIPPROTO *pr = sipe_public->backend_private;
	const gchar *module = pr->proto.m_szModuleName;

	if ( DBGetContactSettingString( hContact, module, "Nick", &dbv )
	  && DBGetContactSettingString( hContact, module, SIP_UNIQUEID, &dbv ))
			return NULL;

	alias = g_strdup(dbv.pszVal);
	DBFreeVariant( &dbv );
	return alias;
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

guint sipe_backend_buddy_get_status(struct sipe_core_public *sipe_public,
					   const gchar *uri)
{
	SIPPROTO *pr = sipe_public->backend_private;
	sipe_backend_buddy buddy = sipe_backend_buddy_find(sipe_public, uri, NULL);
	WORD rv = SIPE_ACTIVITY_UNSET;

	sipe_miranda_getWord(pr, buddy, "Status", &rv);
	return MirandaStatusToSipe(rv);
}

void sipe_backend_buddy_set_alias(struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact = (HANDLE)who;

	SIPE_DEBUG_INFO("Set alias of contact <%08x> to <%s>", who, alias);
	sipe_miranda_setContactStringUtf( pr, hContact, "Nick", alias );
}

void sipe_backend_buddy_set_server_alias(struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who,
					 const gchar *alias)
{
	HANDLE hContact = (HANDLE)who;
	SIPPROTO *pr = sipe_public->backend_private;

	SIPE_DEBUG_INFO("Set alias of contact <%08x> to <%s>", who, alias);
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

	SIPE_DEBUG_INFO("buddy <%08x> key <%d = %s> val <%s>", buddy, key, prop_name, val);
	if (!prop_name)
		return;

	sipe_miranda_setContactString(pr, buddy, prop_name, val);
}

void sipe_backend_buddy_refresh_properties(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   SIPE_UNUSED_PARAMETER const gchar *uri)
{
	/* nothing to do here: already taken care of by Miranda */
}

void sipe_backend_buddy_list_processing_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
}

void sipe_backend_buddy_list_processing_finish(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
}

sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *groupname)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact;

	SIPE_DEBUG_INFO("Adding miranda contact for buddy <%s> alias <%s> in <%s>", name, alias, groupname);
	hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
	CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
	sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, name ); // name
	if (alias) sipe_miranda_setContactStringUtf( pr, hContact, "Nick", alias );
	DBWriteContactSettingString( hContact, "CList", "Group", groupname );
	sipe_miranda_setContactString( pr, hContact, "Group", groupname );
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
	SIPPROTO *pr = sipe_public->backend_private;
	CCSDATA ccs;
	PROTORECVEVENT pre = {0};
	HANDLE hContact;
	BYTE *pblob;

	hContact = sipe_backend_buddy_find( sipe_public, who, NULL );
	if (!hContact)
	{
		SIPE_DEBUG_INFO("Adding miranda contact for incoming talker <%s>", who);
		hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
		CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
		DBWriteContactSettingByte( hContact, "CList", "NotOnList", 1 );
		sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, who ); // name
	}

	ccs.szProtoService	= PSR_AUTH;
	ccs.hContact		= hContact;
	ccs.wParam		= 0;
	ccs.lParam		= (LPARAM) &pre;

	pre.flags		= PREF_UTF;
	pre.timestamp		= time(NULL);
	pre.lParam		= sizeof(DWORD)+sizeof(HANDLE)+strlen(who)+strlen(alias)+5;
	pre.szMessage		= malloc(pre.lParam);

	pblob = pre.szMessage;

	*(DWORD*)pblob = 0; /* UIN */
	pblob += sizeof(DWORD);

	*(HANDLE*)pblob = hContact; /* contact */
	pblob += sizeof(HANDLE);

	strcpy(pblob, who); /* nick */
	pblob += strlen(pblob) + 1;

	strcpy(pblob, alias); /* first name */
	pblob += strlen(pblob) + 1;

	strcpy(pblob, ""); /* last name */
	pblob += strlen(pblob) + 1;

	strcpy(pblob, ""); /* email */
	pblob += strlen(pblob) + 1;

	strcpy(pblob, ""); /* msg */
	pblob += strlen(pblob) + 1;

	CallService(MS_PROTO_CHAINRECV, 0, (LPARAM)&ccs);

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
				   guint activity)
{
	SIPPROTO *pr = sipe_public->backend_private;
	GSList *contacts = sipe_backend_buddy_find_all(sipe_public, who, NULL);

	CONTACTS_FOREACH(contacts)
		sipe_miranda_setWord(pr, hContact, "Status", SipeStatusToMiranda(activity));
	CONTACTS_FOREACH_END;

}

gboolean sipe_backend_buddy_group_add(struct sipe_core_public *sipe_public,
				      const gchar *group_name)
{
	TCHAR *mir_group_name = mir_a2t(group_name);
	HANDLE hGroup = (HANDLE)CallService(MS_CLIST_GROUPCREATE, 0, (LPARAM)mir_group_name);
	mir_free(mir_group_name);
	return (hGroup?TRUE:FALSE);
}

gboolean sipe_backend_buddy_group_rename(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 SIPE_UNUSED_PARAMETER const gchar *old_name,
					 SIPE_UNUSED_PARAMETER const gchar *new_name)
{
	/* @TODO */
	return(FALSE);
}

void sipe_backend_buddy_group_remove(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER const gchar *group_name)
{
	/* @TODO */
}

struct sipe_backend_buddy_info *sipe_backend_buddy_info_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return((struct sipe_backend_buddy_info *)g_hash_table_new_full(NULL,NULL,NULL,g_free));
}

void sipe_backend_buddy_info_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				 struct sipe_backend_buddy_info *info,
				 sipe_buddy_info_fields description,
				 const gchar *value)
{
	g_hash_table_insert((GHashTable*)info, (gpointer)description, g_strdup(value));
}

void sipe_backend_buddy_info_break(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   struct sipe_backend_buddy_info *info)
{
	/* Nothin to do */
}

static void set_if_defined(SIPPROTO *pr, GHashTable *store, HANDLE hContact, sipe_buddy_info_fields field, char *label)
{
	char *value = (char *)g_hash_table_lookup(store, (gpointer)field);
	if (value)
		sipe_miranda_setContactStringUtf(pr, hContact, label, value);
}

void sipe_backend_buddy_info_finalize(struct sipe_core_public *sipe_public,
				      struct sipe_backend_buddy_info *info,
				      const gchar *uri)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact = sipe_miranda_buddy_find(pr, uri, NULL); /* (HANDLE) data; */
	DBVARIANT dbv;
	GHashTable *results = (GHashTable*)info;

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

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		GString *content = g_string_new(NULL);
		WORD wstatus;
		gchar *status;
/*		GSList *info; */
		gboolean is_online;

		sipe_miranda_getWord(pr, hContact, "Status", &wstatus);
		status = (gchar*)CallService(MS_CLIST_GETSTATUSMODEDESCRIPTION, (WPARAM)wstatus, (LPARAM)GSMDF_PREFIXONLINE);
		is_online = g_str_has_prefix(status, "Online: ") || !g_ascii_strcasecmp(status, "Online");
/*
		info = sipe_core_buddy_info(sipe_public,
					    dbv.pszVal,
					    g_str_has_prefix(status, "Online: ") ? status+8 : status,
					    is_online);

		while (info) {
			struct sipe_buddy_info *sbi = info->data;
			g_string_append_printf(content, "%s: %s\r\n", sbi->label, sbi->text);
			g_free(sbi->text);
			g_free(sbi);
			info = g_slist_delete_link(info, info);
		}
		sipe_miranda_setContactStringUtf(pr, hContact, "About", content->str);
*/
		g_string_free(content, TRUE);
	}

	sipe_miranda_SendBroadcast(pr, hContact, ACKTYPE_GETINFO, ACKRESULT_SUCCESS, (HANDLE) 1, (LPARAM) 0);
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return(NULL);
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
							    struct sipe_backend_buddy_menu *menu,
							    const gchar *label,
							    enum sipe_buddy_menu_type type,
							    gpointer parameter)
{
	_NIF();
	return(NULL);
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_separator(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								  struct sipe_backend_buddy_menu *menu,
								  const gchar *label)
{
	_NIF();
	return(NULL);
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_sub_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								struct sipe_backend_buddy_menu *menu,
								const gchar *label,
								struct sipe_backend_buddy_menu *sub)
{
	_NIF();
	return(NULL);
}

void sipe_backend_buddy_tooltip_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    struct sipe_backend_buddy_tooltip *tooltip,
				    const gchar *description,
				    const gchar *value)
{
	_NIF();
}

int sipe_miranda_buddy_delete(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	DBVARIANT dbv;
	HANDLE hContact = (HANDLE)wParam;
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

	LOCK;
	sipe_core_buddy_remove(pr->sip, name, groupname);
	UNLOCK;

	return 0;
}

unsigned GetAwayMsgThread(SIPPROTO *pr, HANDLE hContact)
{
	const gchar *status;
	gchar *name = sipe_miranda_getContactString(pr, hContact, SIP_UNIQUEID);
	gchar *tmp = NULL;

	if (!name)
	{
		SIPE_DEBUG_INFO("Could not find name for contact <%08x>", hContact);
		sipe_miranda_SendProtoAck(pr, hContact, 1, ACKRESULT_FAILED, ACKTYPE_AWAYMSG, NULL);
		return 0;
	}

	LOCK;
	status = sipe_core_buddy_status(pr->sip,
					name,
					SIPE_ACTIVITY_BUSYIDLE,
					"dummy test string");
	UNLOCK;

	if (status)
		tmp = sipe_miranda_eliminate_html(status, strlen(status));

	sipe_miranda_SendProtoAck(pr, hContact, 1, ACKRESULT_SUCCESS, ACKTYPE_AWAYMSG, tmp);

	mir_free(tmp);
	mir_free(name);
	return 0;
}

HANDLE
sipe_miranda_GetAwayMsg( SIPPROTO *pr, HANDLE hContact )
{
	CloseHandle((HANDLE)mir_forkthreadowner(&GetAwayMsgThread, pr, hContact, NULL ));
	return (HANDLE)1;
}

int
sipe_miranda_GetInfo( SIPPROTO *pr, HANDLE hContact, int infoType )
{
	DBVARIANT dbv;

	SIPE_DEBUG_INFO("GetInfo: infotype <%x>", infoType);
	if (!pr->sip) return 0;

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		LOCK;
		sipe_core_buddy_get_info(pr->sip, dbv.pszVal);
		UNLOCK;
		DBFreeVariant( &dbv );
	}

	return 0;
}

gboolean sipe_backend_uses_photo(void)
{
	return FALSE;
}

void sipe_backend_buddy_set_photo(struct sipe_core_public *sipe_public,
				  const gchar *who,
				  gpointer photo_data,
				  gsize data_len,
				  const gchar *photo_hash)
{
	g_free(photo_data);
}

const gchar *sipe_backend_buddy_get_photo_hash(struct sipe_core_public *sipe_public,
					       const gchar *who)
{
	const gchar *result = NULL;
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
