//
//  ESSIPEAccount.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import <AISharedAdium.h>
#import <AIAdium.h>
#import <Adium/AIStatus.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <AIUtilities/AIHostReachabilityMonitor.h>

#import "ESPurpleSIPEAccount.h"
#import "ESSIPEService.h"

#include "sipe-core.h"
#include "sipe-backend.h"
#include "purple-private.h"

// C Declarations
extern void AILog(NSString *fmt, ...);

@class AICoreComponentLoader;

@implementation ESPurpleSIPEAccount

- (const char*)protocolPlugin
{
	return "prpl-sipe";
}

- (NSString *)hostForPurple
{
    NSString *server = [self preferenceForKey:KEY_SIPE_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
    if (!server || [server length] == 0)
    {
        // set the KEY_CONNECT_HOST to "autodetect" just to make sure we don't lose it from the defaults
        [self setPreference:@"autodetect" forKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
        return @"autodetect";
    } else {
        return server;
    }
}

-(void) didConnect
{
    PurpleConnection *gc = purple_account_get_connection(account);
    struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;

    // get the resolved hostname from sipe_private
    NSString *host = [NSString stringWithUTF8String:sipe_core_transport_sip_server_name(sipe_public)];
    AILog(@"(didConnect) server: %@",host);

    // if we autodetected, the KEY_CONNECT_HOST will be "autodetect", we need to replace it with the real hostname
    if([[self preferenceForKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS] compare:@"autodetect" options:NSCaseInsensitiveSearch] == NSOrderedSame )
    {
        [self setPreference:host forKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
    }


    // Adium Host reachability depends on having KEY_CONNECT_HOST filled in earlier, so we have to hack ourselves into the reachabilityMonitor
    // TODO: Check with Adium team to see if there is a more elegant way to do this.
    AIHostReachabilityMonitor	*monitor = [AIHostReachabilityMonitor defaultMonitor];
    AICoreComponentLoader       *theComponentLoader = adium.componentLoader;
    [monitor addObserver:[theComponentLoader pluginWithClassName:@"ESAccountNetworkConnectivityPlugin"] forHost:host];

    [super didConnect];
}

#pragma mark Account Configuration
- (void)configurePurpleAccount
{
	[super configurePurpleAccount];

    // Account preferences
    AILog(@"Configuring account: %s\n", self.purpleAccountName);

    // !!! ------  HACK/Kludge alert!  ------
    /*
     * Adium's CBPurpleAccount class's implementation of configurePurpleAccount (called above)
     * has the following line:
     *
     *         if (hostName && [hostName length]) {
     *
     * Which doesn't allow us to leave the KEY_CONNECT_HOST preference empty (Adium prompts for the user to fill it out)
     * sipe-core is expecting the server account setting to be empty to engage the auto-detection piece.  The only way
     * to fix this is to fake out Adium by storing the servername in a different key (KEY_SIPE_CONNECT_HOST) and setting a
     * default KEY_CONNECT_HOST to something.  We then need to detect that we have an empty servername here, and
     * "overwrite" the default placeholder with an empty string.
     */

    // if there is no host specified, we're looking to auto-detect
    // TODO: change this to a checkbox, and enable/disable based on that.  Leaving a field blank is bad UI design.
    NSString *server = [self preferenceForKey:KEY_SIPE_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];

    // if the server is empty, clear it in purple account (because the defaults hack for the superclass set it to "autodetect").  Otherwise, use the one provided
    if([server isEqualToString:@""])
    {
        // force preference back to "autodetect" so that we can replace it when we get a hostname resolved
        [self setPreference:@"autodetect" forKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
        purple_account_set_string(account,"server", "");
    } else {
        // NOP.  Superclass already set this via the [self hostForPurple] response.
    }

    NSString *winLogin  = [self preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
    NSString *completeUserName = [NSString stringWithUTF8String:[self purpleAccountName]];

    if (winLogin && [winLogin length]) {
        // Configure the complete username ("user@domain.com,DOMAIN\user")
        completeUserName = [NSString stringWithFormat:@"%@,%@",completeUserName, winLogin];
        purple_account_set_username(account, [completeUserName UTF8String]);
    } else {
        purple_account_set_username(account, self.purpleAccountName);
    }

    NSString *thePassword = [self preferenceForKey:KEY_SIPE_PASSWORD group:GROUP_ACCOUNT_STATUS];
    if (thePassword && [thePassword length])
        purple_account_set_password(account, [thePassword UTF8String]);

	BOOL sso = [[self preferenceForKey:KEY_SIPE_SINGLE_SIGN_ON group:GROUP_ACCOUNT_STATUS] boolValue];
	purple_account_set_bool(account, "sso", sso);

    if (sso) {
            // Adium doesn't honor our "optional" password on account creation and will prompt if the password field is left blank, so we must force it to think there is one, but only if there isn't already a password saved
            if (!thePassword)
                [self setPasswordTemporarily:@"placeholder"];
    }

	BOOL dont_publish = [[self preferenceForKey:KEY_SIPE_DONT_PUBLISH group:GROUP_ACCOUNT_STATUS] boolValue];
	purple_account_set_bool(account, "dont-publish", dont_publish);

    // Connection preferences
    id connType = [self preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS];
    if([connType isKindOfClass:[NSNumber class]])
	{
	// For backwards compatibility, we pick from an array if the preference is a NSNumber
    	NSMutableArray *myArray = [[NSMutableArray alloc] initWithObjects:@"auto", @"tls", @"tcp", nil];
    	connType = (NSString *)[myArray objectAtIndex:(NSUInteger)[self preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS]];
	}
    purple_account_set_string(account, "transport", [connType UTF8String]);

    NSString *authScheme = [self preferenceForKey:KEY_SIPE_AUTH_SCHEME group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "authentication", [authScheme UTF8String]);

	NSString *userAgent = [self preferenceForKey:KEY_SIPE_USER_AGENT group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "useragent", (userAgent.length != 0) ?  [userAgent UTF8String] : "" );

    // Email preferences
    NSString *emailURL = [self preferenceForKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "email_usr", (!emailURL.length) ?  [emailURL UTF8String] : "" );

    // TODO: Use account name (user@domain) as default for this
    NSString *email = [self preferenceForKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "email", (!email.length) ?  [email UTF8String] : "" );

    // TODO: Use Windows Login (DOMAIN\user) as default for this
    NSString *emailLogin = [self preferenceForKey:KEY_SIPE_EMAIL_LOGIN group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "email_login", (!emailLogin.length) ?  [emailLogin UTF8String] : "" );

    // TODO: Use default password as default for this
    NSString *emailPassword = [self preferenceForKey:KEY_SIPE_EMAIL_PASSWORD group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "email_password", (!emailPassword.length) ?  [emailPassword UTF8String] : "" );

    // Group chat preferences
    NSString *groupchatUser = [self preferenceForKey:KEY_SIPE_GROUP_CHAT_PROXY group:GROUP_ACCOUNT_STATUS];
    purple_account_set_string(account, "groupchat_user", (!groupchatUser.length) ? [groupchatUser UTF8String] : "" );

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
    NSString *statusName = [super statusNameForPurpleBuddy:buddy];
    PurplePresence  *presence = purple_buddy_get_presence(buddy);
    PurpleStatus    *status = purple_presence_get_active_status(presence);
    const char      *purpleStatusID = purple_status_get_id(status);

    if (!purpleStatusID) return nil;

    switch (sipe_purple_token_to_activity(purpleStatusID))
    {
        case SIPE_ACTIVITY_AVAILABLE:
        case SIPE_ACTIVITY_ONLINE:
            statusName = STATUS_NAME_AVAILABLE;
            break;
        case SIPE_ACTIVITY_AWAY:
        case SIPE_ACTIVITY_INACTIVE:
            statusName = STATUS_NAME_AWAY;
            break;
        case SIPE_ACTIVITY_BRB:
            statusName = STATUS_NAME_BRB;
            break;
        case SIPE_ACTIVITY_BUSY:
        case SIPE_ACTIVITY_BUSYIDLE:
            statusName = STATUS_NAME_BUSY;
            break;
        case SIPE_ACTIVITY_DND:
            statusName = STATUS_NAME_DND;
            break;
        case SIPE_ACTIVITY_LUNCH:
            statusName = STATUS_NAME_LUNCH;
            break;
        case SIPE_ACTIVITY_INVISIBLE:
            statusName = STATUS_NAME_INVISIBLE;
            break;
        case SIPE_ACTIVITY_OFFLINE:
            statusName = STATUS_NAME_OFFLINE;
            break;
        case SIPE_ACTIVITY_ON_PHONE:
            statusName = STATUS_NAME_PHONE;
            break;
        case SIPE_ACTIVITY_IN_CONF:
        case SIPE_ACTIVITY_IN_MEETING:
            statusName = STATUS_NAME_NOT_AT_DESK;
            break;
        case SIPE_ACTIVITY_OOF:
            statusName = STATUS_NAME_NOT_IN_OFFICE;
            break;
        case SIPE_ACTIVITY_URGENT_ONLY:
            statusName = STATUS_NAME_AWAY_FRIENDS_ONLY;
            break;
        default:
            statusName = STATUS_NAME_OFFLINE;
    }

    return statusName;

}

/*!
 * @brief Maps purple status IDs to Adium statuses
 */
 - (const char *)purpleStatusIDForStatus:(AIStatus *)statusState arguments:(NSMutableDictionary *)arguments
 {
     const gchar    *statusID;
     NSString		*statusName = statusState.statusName;
     NSString		*statusMessageString = [statusState statusMessageString];

     if (!statusMessageString) statusMessageString = @"";

     // TODO: figure out why sipe_status_activity_to_token calls return junk, instead of a gchar*
     switch (statusState.statusType) {
         case AIAvailableStatusType:
             statusID = sipe_activity_map[SIPE_ACTIVITY_AVAILABLE].status_id;
             //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_AVAILABLE);
             break;

         case AIAwayStatusType:
             if (([statusName isEqualToString:STATUS_NAME_AWAY]) ||
                 ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AWAY]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_AWAY);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_AWAY].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_BRB]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BRB]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_BRB);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_BRB].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_BUSY]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BUSY]] == NSOrderedSame))
             {
                 // TODO: Figure out how to determine if they should be "busy" or "busyidle"
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_BUSY].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_DND]) ||
                      ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_DND]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_DND);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_DND].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_LUNCH]) ||
                      ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_LUNCH]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_LUNCH);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_LUNCH].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_PHONE]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_PHONE]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_ON_PHONE);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_ON_PHONE].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_NOT_AT_DESK]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_NOT_AT_DESK]] == NSOrderedSame))
             {
                 // TODO: Figure out how to determine if they should be "In a meeting" or "In a conference"
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_IN_MEETING);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_IN_MEETING].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_NOT_IN_OFFICE]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_NOT_IN_OFFICE]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_OOF);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_OOF].status_id;
             } else if (([statusName isEqualToString:STATUS_NAME_AWAY_FRIENDS_ONLY]) ||
                        ([statusMessageString caseInsensitiveCompare:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AWAY_FRIENDS_ONLY]] == NSOrderedSame))
             {
                 //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_URGENT_ONLY);
                 statusID = sipe_activity_map[SIPE_ACTIVITY_URGENT_ONLY].status_id;
             }
             break;
         case AIInvisibleStatusType:
             //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_INVISIBLE);
             statusID = sipe_activity_map[SIPE_ACTIVITY_INVISIBLE].status_id;
             break;

         case AIOfflineStatusType:
             //statusID = sipe_status_activity_to_token(SIPE_ACTIVITY_OFFLINE);
             statusID = sipe_activity_map[SIPE_ACTIVITY_OFFLINE].status_id;
             break;
     }


     //If we didn't get a purple status type, request one from super
     if (statusID == NULL) statusID = [super purpleStatusIDForStatus:statusState arguments:arguments];

     return statusID;
 }


@end
