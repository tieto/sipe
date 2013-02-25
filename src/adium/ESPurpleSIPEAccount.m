//
//  ESSIPEAccount.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Copyright 2009 Matt Meissner. All rights reserved.
//

#import <Adium/AIStatus.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <Adium/AIHTMLDecoder.h>

#import "ESPurpleSIPEAccount.h"

#include "sipe-core.h"


@implementation ESPurpleSIPEAccount

- (const char*)protocolPlugin
{
	return "prpl-sipe";
}

- (void)configurePurpleAccount
{
	NSLog(@"Configure account: %x\n", account);

	[super configurePurpleAccount];

		// Get the preferences
	int ctype = [[self preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS] intValue];
	NSString *email     = [self preferenceForKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
	NSString *emailURL  = [self preferenceForKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
	NSString *emailPass = [self preferenceForKey:KEY_SIPE_EMAIL_PASSWORD group:GROUP_ACCOUNT_STATUS];
	NSString *thePassword = [self preferenceForKey:KEY_SIPE_PASSWORD group:GROUP_ACCOUNT_STATUS];
	NSString *chatProxy = [self preferenceForKey:KEY_SIPE_GROUP_CHAT_PROXY group:GROUP_ACCOUNT_STATUS];
    NSString *userAgent = [self preferenceForKey:KEY_SIPE_USER_AGENT group:GROUP_ACCOUNT_STATUS];
	NSString *winLogin  = [self preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];

    
		// Configure Email settings
    if (email && [email length])
        purple_account_set_string(account, "email", [email UTF8String]);
    if (emailURL && [emailURL length])
        purple_account_set_string(account, "email_url", [emailURL UTF8String]);
    if (emailPass && [emailPass length])
        purple_account_set_string(account, "email_password", [emailPass UTF8String]);

		// Configure Password
	if (thePassword && [thePassword length])
	{
		purple_account_set_password(account, [thePassword UTF8String]);
	}

		// Configure Connnection type
    const char *ctypes;
    switch (ctype) {
        default:
        case 0: ctypes = "auto"; break;
        case 1: ctypes = "tcp";  break;
        case 2: ctypes = "tls";  break;
    }
    purple_account_set_string(account, "transport", ctypes);


		// Configure Proxy and UserAgent
    if (chatProxy && [chatProxy length])
        purple_account_set_string(account, "groupchat_user", [chatProxy UTF8String]);
    if (userAgent && [userAgent length])
        purple_account_set_string(account, "useragent", [userAgent UTF8String]);


		// Configure the AccountName
    NSString *completeUserName = [NSString stringWithUTF8String:[self purpleAccountName]];

    if (winLogin && [winLogin length])
        completeUserName = [NSString stringWithFormat:@"%@,%@",completeUserName, winLogin];

    purple_account_set_username(account, [completeUserName UTF8String]);

	const char *username  = purple_account_get_username(account);

    NSLog(@"AccountName: %s\n", username ? username : "NULL");

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
/*!
 * @brief Status name to use for a Purple buddy
 */

- (NSString *)statusNameForPurpleBuddy:(PurpleBuddy *)buddy
{
    NSString        *statusName = nil;
    PurplePresence  *presence = purple_buddy_get_presence(buddy);
    PurpleStatus        *status = purple_presence_get_active_status(presence);
    const char      *purpleStatusID = purple_status_get_id(status);
    
    if (!purpleStatusID) return nil;
	
    if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_AVAILABLE))) {
        statusName = STATUS_NAME_AVAILABLE;
		
    } else if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_AWAY))) {
        statusName = STATUS_NAME_AWAY;
		
    } else if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_BRB))) {
        statusName = STATUS_NAME_BRB;
		
    } else if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_BUSY))) {
        statusName = STATUS_NAME_BUSY;
		
    } else if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_BUSYIDLE))) {
        statusName = STATUS_NAME_BUSY;
		
    } else if (!strcmp(purpleStatusID, sipe_core_activity_description(SIPE_ACTIVITY_DND))) {
        statusName = STATUS_NAME_DND;
		 
    } // TODO: put in entries for all SIPE_ACTIVITY_xxxx values
    
    return statusName;
}



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
    
    // probably need to call something like sipe_backend_buddy_get_status();
	
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


 - (const char *)purpleStatusIDForStatus:(AIStatus *)statusState
 arguments:(NSMutableDictionary *)arguments
 {
     const char    *statusID = NULL;
     NSString		*statusName = statusState.statusName;
     NSString		*statusMessageString = [statusState statusMessageString];
     
     if (!statusMessageString) statusMessageString = @"";

     switch (statusState.statusType) {
         case AIAvailableStatusType:
             statusID = sipe_core_activity_description(SIPE_ACTIVITY_AVAILABLE);
             break;
             
         case AIAwayStatusType:
             statusID = sipe_core_activity_description(SIPE_ACTIVITY_AWAY);
             break;
             
             /* TODO:  separate away status into different parts
              if (([statusName isEqualToString:STATUS_NAME_BRB]) ||
                 ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BRB]] == NSOrderedSame))
                 statusID = "brb";
             else if (([statusName isEqualToString:STATUS_NAME_BUSY]) ||
                      ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BUSY]] == NSOrderedSame))
                 statusID = "busy";
             else if (([statusName isEqualToString:STATUS_NAME_PHONE]) ||
                      ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_PHONE]] == NSOrderedSame))
                 statusID = "phone";
             else if (([statusName isEqualToString:STATUS_NAME_LUNCH]) ||
                      ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_LUNCH]] == NSOrderedSame))
                 statusID = "lunch";  */
         
         case AIInvisibleStatusType:
             statusID = sipe_core_activity_description(SIPE_ACTIVITY_INVISIBLE);
             break;
         
         case AIOfflineStatusType:
             statusID = sipe_core_activity_description(SIPE_ACTIVITY_OFFLINE);
             break;
     }
         
     //If we didn't get a purple status type, request one from super
     if (statusID == NULL) statusID = [super purpleStatusIDForStatus:statusState arguments:arguments];
     
     return statusID;
 }
 

@end
