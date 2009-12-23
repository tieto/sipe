//
//  ESSIPEAccount.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Copyright 2009 Matt Meissner. All rights reserved.
//

#import <Adium/AIStatus.h>
#import <Adium/AIHTMLDecoder.h>

#import "ESPurpleSIPEAccount.h"

#include "sipe.h"
#include "sipe-utils.h"

// taken from sipe.c
/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET)     /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE)   /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_ONPHONE     "on-the-phone"                                             /* On The Phone */
#define SIPE_STATUS_ID_INVISIBLE   purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY)      /* Away (primitive) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */


@implementation ESPurpleSIPEAccount
- (const char*)protocolPlugin
{
	return "prpl-sipe";
}

- (void)configurePurpleAccount
{
	[super configurePurpleAccount];	

	NSLog(@"AccountName: %s\n", self.purpleAccountName ? self.purpleAccountName : "NULL");
	NSLog(@"Account: %x\n", account);
	NSLog(@"Port: %d\n", self.port);
	NSLog(@"Server: %@\n", self.host);

	purple_account_set_username(account, self.purpleAccountName);

	if (self.host && [self.host length]) {
		if (self.port) {
			// TODO: figure out a better size for this!
			char tmp[512];
			sprintf(tmp, "%s:%d", [self.host UTF8String], self.port);
			purple_account_set_string(account, "server", tmp);
		} else {
			// super-class already set this
		}
	}

	// TODO: hook up the GUI to actually set this
	purple_account_set_string(account, "transport", "tls");
}

- (const char *)purpleStatusIDForStatus:(AIStatus *)statusState
							  arguments:(NSMutableDictionary *)arguments
{
    const char    *statusID = NULL;
	
    switch (statusState.statusType) {
        case AIAvailableStatusType:
            statusID = purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE);
            break;
        case AIAwayStatusType:
            statusID = purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY);
            break;
			
        case AIInvisibleStatusType:
            statusID = purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE);
            break;
			
        case AIOfflineStatusType:
            statusID = purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE);
            break;
    }    
    
    return statusID;
}


#pragma mark File transfer

- (BOOL)canSendFolders
{
	return NO;
}

- (void)beginSendOfFileTransfer:(ESFileTransfer *)fileTransfer
{
	[super _beginSendOfFileTransfer:fileTransfer];
}

- (void)acceptFileTransferRequest:(ESFileTransfer *)fileTransfer
{
    [super acceptFileTransferRequest:fileTransfer];    
}

- (void)rejectFileReceiveRequest:(ESFileTransfer *)fileTransfer
{
    [super rejectFileReceiveRequest:fileTransfer];    
}

- (void)cancelFileTransfer:(ESFileTransfer *)fileTransfer
{
	[super cancelFileTransfer:fileTransfer];
} 

#pragma mark Status Messages
/*
- (NSString *)statusNameForPurpleBuddy:(PurpleBuddy *)buddy
{
    NSString        *statusName = nil;
    PurplePresence  *presence = purple_buddy_get_presence(buddy);
    PurpleStatus        *status = purple_presence_get_active_status(presence);
    const char      *purpleStatusID = purple_status_get_id(status);
    
    if (!purpleStatusID) return nil;
	
    if (!strcmp(purpleStatusID, jabber_buddy_state_get_status_id(JABBER_BUDDY_STATE_CHAT))) {
        statusName = STATUS_NAME_FREE_FOR_CHAT;
		
    } else if (!strcmp(purpleStatusID, jabber_buddy_state_get_status_id(JABBER_BUDDY_STATE_XA))) {
        statusName = STATUS_NAME_EXTENDED_AWAY;
		
    } else if (!strcmp(purpleStatusID, jabber_buddy_state_get_status_id(JABBER_BUDDY_STATE_DND))) {
        statusName = STATUS_NAME_DND;
		
    }   
    
    return statusName;
}
*/

/*!
 * @brief Status message for a contact
 */
- (NSAttributedString *)statusMessageForPurpleBuddy:(PurpleBuddy *)buddy
{
	PurplePresence				*presence = purple_buddy_get_presence(buddy);
	PurpleStatus				*status = (presence ? purple_presence_get_active_status(presence) : NULL);
	const char					*message = (status ? purple_status_get_attr_string(status, "message") : NULL);
	char						*sipemessage = NULL;
	NSString					*statusMessage = nil;
	struct sipe_account_data	*sip;
	struct sipe_buddy			*sbuddy;

	if (!message) {

		sip = (struct sipe_account_data *) buddy->account->gc->proto_data;
		if (sip)  //happens on pidgin exit
		{
			GList *keys = g_hash_table_get_keys(sip->buddies);
			sbuddy = g_hash_table_lookup(sip->buddies, buddy->name);
			if (sbuddy) {
				if (!is_empty(sbuddy->activity) && !is_empty(sbuddy->annotation))
				{
					sipemessage = g_strdup_printf("%s. %s", sbuddy->activity, sbuddy->annotation);
				}
				else if (!is_empty(sbuddy->activity))
				{
					sipemessage = g_strdup(sbuddy->activity);
				}
				else if (!is_empty(sbuddy->annotation))
				{
					sipemessage = g_strdup(sbuddy->annotation);
				}
			}
		}
	}
	
	// Get the plugin's status message for this buddy if they don't have a status message
	if (!message && !sipemessage) {
		PurplePluginProtocolInfo  *prpl_info = self.protocolInfo;
		
		if (prpl_info && prpl_info->status_text) {
			char *status_text = (prpl_info->status_text)(buddy);
			
			// Don't display "Offline" as a status message.
			if (status_text && strcmp(status_text, _("Offline")) != 0) {
				statusMessage = [NSString stringWithUTF8String:status_text];				
			}
			
			g_free(status_text);
		}
	} else if (sipemessage) {
		statusMessage = [NSString stringWithUTF8String:sipemessage];
		g_free(sipemessage);
	} else {
		statusMessage = [NSString stringWithUTF8String:message];
	}

	return statusMessage ? [AIHTMLDecoder decodeHTML:statusMessage] : nil;
	}

@end
