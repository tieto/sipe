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

#include "sipe-core.h"

// taken from sipe.c
#define SIPE_STATUS_ID_UNKNOWN     purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET)     /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE)   /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_BUSYIDLE    "busyidle"                                                 /* BusyIdle */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_IN_MEETING  "in-a-meeting"                                             /* In a meeting */
#define SIPE_STATUS_ID_IN_CONF     "in-a-conference"                                          /* In a conference */
#define SIPE_STATUS_ID_ON_PHONE    "on-the-phone"                                             /* On the phone */
#define SIPE_STATUS_ID_INVISIBLE   purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY)      /* Away (primitive) */
/** Reuters status (user settable) */
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
	NSLog(@"Configure account: %x\n", account);

	[super configurePurpleAccount];	
  
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

	NSString *email     = [self preferenceForKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
	NSString *emailURL  = [self preferenceForKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
	NSString *emailPass = [self preferenceForKey:KEY_SIPE_EMAIL_PASSWORD group:GROUP_ACCOUNT_STATUS];
    if (email && [email length])
        purple_account_set_string(account, "email", [email UTF8String]);
    if (emailURL && [emailURL length])
        purple_account_set_string(account, "email_url", [emailURL UTF8String]);
    if (emailPass && [emailPass length])
        purple_account_set_string(account, "email_password", [emailPass UTF8String]);

	int ctype = [[self preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS] intValue];
    const char *ctypes;
    switch (ctype) {
        default:
        case 0: ctypes = "auto"; break;
        case 1: ctypes = "tcp";  break;
        case 2: ctypes = "tls";  break;
    }
    purple_account_set_string(account, "transport", ctypes);

    NSString *chatProxy = [self preferenceForKey:KEY_SIPE_GROUP_CHAT_PROXY group:GROUP_ACCOUNT_STATUS];
    NSString *userAgent = [self preferenceForKey:KEY_SIPE_USER_AGENT group:GROUP_ACCOUNT_STATUS];
    if (chatProxy && [chatProxy length])
        purple_account_set_string(account, "groupchat_user", [chatProxy UTF8String]);
    if (userAgent && [userAgent length])
        purple_account_set_string(account, "useragent", [userAgent UTF8String]);

    
    NSString *winLogin  = [self preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
    
    NSString *completeUserName = [NSString stringWithUTF8String:[self purpleAccountName]];
    
    if (winLogin && [winLogin length])
        completeUserName = [NSString stringWithFormat:@"%@,%@",completeUserName, winLogin];
    
    purple_account_set_username(account, [completeUserName UTF8String]);
    
	const char *username  = purple_account_get_username(account);
    
    NSLog(@"AccountName: %s\n", username ? username : "NULL");
    
}

- (const char *)purpleStatusIDForStatus:(AIStatus *)statusState
							  arguments:(NSMutableDictionary *)arguments
{
    const char    *statusID = NULL;
	
    switch (statusState.statusType) {
        case AIAvailableStatusType:
            statusID = SIPE_STATUS_ID_AVAILABLE;
            break;
        case AIAwayStatusType:
            statusID = SIPE_STATUS_ID_AWAY;
            break;
			
        case AIInvisibleStatusType:
            statusID = SIPE_STATUS_ID_INVISIBLE;
            break;
			
        case AIOfflineStatusType:
            statusID = SIPE_STATUS_ID_OFFLINE;
            break;
    }    
    
	//If we didn't get a purple status type, request one from super
	if (statusID == NULL) statusID = [super purpleStatusIDForStatus:statusState arguments:arguments];
	
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
	
	// TODO: get sipe activity or annotation
	
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
