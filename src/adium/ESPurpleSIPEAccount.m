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
#import <ESDebugAILog.h>

#import "ESPurpleSIPEAccount.h"
#import "ESSIPEService.h"

#include "sipe-core.h"
#include "sipe-backend.h"
#include "purple-private.h"

@class AICoreComponentLoader;

@implementation ESPurpleSIPEAccount

- (void)initAccount
{
    [super initAccount];
    
    sipe_to_adium_status =
    [[NSDictionary alloc] initWithObjectsAndKeys:
     STATUS_NAME_AVAILABLE,         @"available",                 //SIPE_ACTIVITY_AVAILABLE
     STATUS_NAME_AVAILABLE,         @"online",                    //SIPE_ACTIVITY_ONLINE
     STATUS_NAME_AWAY,              @"idle",                      //SIPE_ACTIVITY_INACTIVE
     STATUS_NAME_BUSY,              @"busy",                      //SIPE_ACTIVITY_BUSY
     STATUS_NAME_BUSY,              @"busyidle",                  //SIPE_ACTIVITY_BUSYIDLE
     STATUS_NAME_DND,               @"do-not-disturb",            //SIPE_ACTIVITY_DND
     STATUS_NAME_BRB,               @"be-right-back",             //SIPE_ACTIVITY_BRB
     STATUS_NAME_AWAY,              @"away",                      //SIPE_ACTIVITY_AWAY
     STATUS_NAME_LUNCH,             @"out-to-lunch",              //SIPE_ACTIVITY_LUNCH
     STATUS_NAME_INVISIBLE,         @"invisible",                 //SIPE_ACTIVITY_INVISIBLE
     STATUS_NAME_OFFLINE,           @"offline",                   //SIPE_ACTIVITY_OFFLINE
     STATUS_NAME_PHONE,             @"on-the-phone",              //SIPE_ACTIVITY_ON_PHONE
     STATUS_NAME_NOT_AT_DESK,       @"in-a-conference",           //SIPE_ACTIVITY_IN_CONF
     STATUS_NAME_NOT_AT_DESK,       @"in-a-meeting",              //SIPE_ACTIVITY_IN_MEETING
     STATUS_NAME_NOT_IN_OFFICE,     @"out-of-office",             //SIPE_ACTIVITY_OOF
     STATUS_NAME_AWAY_FRIENDS_ONLY, @"urgent-interruptions-only", //SIPE_ACTIVITY_URGENT_ONLY
     nil
     ];
    
    adium_to_sipe_status =
    [[NSDictionary alloc] initWithObjectsAndKeys:
     @"available",                 STATUS_NAME_AVAILABLE,         //SIPE_ACTIVITY_AVAILABLE
     @"busy",                      STATUS_NAME_BUSY,              //SIPE_ACTIVITY_BUSY
     @"do-not-disturb",            STATUS_NAME_DND,               //SIPE_ACTIVITY_DND
     @"be-right-back",             STATUS_NAME_BRB,               //SIPE_ACTIVITY_BRB
     @"away",                      STATUS_NAME_AWAY,              //SIPE_ACTIVITY_AWAY
     @"out-to-lunch",              STATUS_NAME_LUNCH,             //SIPE_ACTIVITY_LUNCH
     @"invisible",                 STATUS_NAME_INVISIBLE,         //SIPE_ACTIVITY_INVISIBLE
     @"offline",                   STATUS_NAME_OFFLINE,           //SIPE_ACTIVITY_OFFLINE
     @"on-the-phone",              STATUS_NAME_PHONE,             //SIPE_ACTIVITY_ON_PHONE
     @"in-a-meeting",              STATUS_NAME_NOT_AT_DESK,       //SIPE_ACTIVITY_IN_MEETING
     @"out-of-office",             STATUS_NAME_NOT_IN_OFFICE,     //SIPE_ACTIVITY_OOF
     @"urgent-interruptions-only", STATUS_NAME_AWAY_FRIENDS_ONLY, //SIPE_ACTIVITY_URGENT_ONLY
     nil
     ];
}

- (void)dealloc
{
    [adium_to_sipe_status release];
    [sipe_to_adium_status release];
    [super dealloc];
}

- (const char*)protocolPlugin
{
	return "prpl-sipe";
}

- (const char *)purpleAccountName
{
    NSString *completeUserName = [NSString stringWithUTF8String:[super purpleAccountName]];
    NSString *windowsLogin =[self preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
    
    if ( ![windowsLogin isEqualToString:@""] ) {
        completeUserName = [NSString stringWithFormat:@"%@,%@", completeUserName, windowsLogin];
    }
    
	return [completeUserName UTF8String];
}

#pragma mark Account Configuration
- (void)configurePurpleAccount
{
    // Account preferences
    AILog(@"(ESPurpleSIPEAccount) Configuring account: %s\n", self.purpleAccountName);

    NSArray *myArray = [NSArray arrayWithObjects:@"auto", @"tls", @"tcp", nil];
    
    NSDictionary *keys_to_account =
    [NSDictionary dictionaryWithObjectsAndKeys:
     @"server",                        KEY_SIPE_CONNECT_HOST,
     @"password",                      KEY_SIPE_PASSWORD,
     @"transport",                     KEY_SIPE_CONNECTION_TYPE,
     @"email",                         KEY_SIPE_EMAIL,
     @"email_login",                   KEY_SIPE_EMAIL_LOGIN,
     @"email_url",                     KEY_SIPE_EMAIL_URL,
     @"email_password",                KEY_SIPE_EMAIL_PASSWORD,
     @"groupchat_user",                KEY_SIPE_GROUP_CHAT_PROXY,
     @"useragent",                     KEY_SIPE_USER_AGENT,
     @"sso",                           KEY_SIPE_SINGLE_SIGN_ON,
     @"dont-publish",                  KEY_SIPE_DONT_PUBLISH,
     @"authentication",                KEY_SIPE_AUTH_SCHEME,
     @"ssl_cdsa_beast_tls_workaround", KEY_SIPE_BEAST_DISABLE,
     nil
     ];
    
    for (NSString* key in keys_to_account) {
        NSString *prpl_key = [keys_to_account objectForKey:key];
        id value = [self preferenceForKey:key group:GROUP_ACCOUNT_STATUS];
        
        if ([value isKindOfClass:[NSString class]]) {
            if ([key isEqualToString:KEY_SIPE_CONNECT_HOST]) {
                if ([value isEqualToString:@""]) {
                    // An empty sipe_connect_host means we're autodetecting the server
                    // So we set this to our own hostname, so that the reachability test has a *network* address (i.e. non-loopback) to check connectivity against.
                    [self setPreference:[[NSHost currentHost] localizedName] forKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
                } else {
                    // If the user entered server:port only give the server portion to adium
                    // otherwise the DNS lookup will fail the reachability test
                    NSArray *server = [value componentsSeparatedByString:@":"];
                    [self setPreference:[server objectAtIndex:0] forKey:KEY_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
                }
            }
            
            purple_account_set_string(account, [prpl_key UTF8String], [value UTF8String]);
        } else if ([value isKindOfClass:[NSNumber class]]) {
            if ([key isEqualToString:KEY_SIPE_CONNECTION_TYPE]) {
                NSString *tmp = [myArray objectAtIndex:(NSUInteger)value];
                purple_account_set_string(account, [prpl_key UTF8String], [tmp UTF8String]);
            } else {
                purple_account_set_bool(account, [prpl_key UTF8String], [value boolValue]);
            }
        } else {
            AILog(@"(ESPurpleSIPEAccount) Unknown class %@ for key %@", [value class], key);
        }
    }
    
    // Adium doesn't honor our "optional" password on account creation and will prompt if the password field is left blank, so we must force it to think there is one, but only if there isn't already a password saved
    if ( [[self preferenceForKey:KEY_SIPE_SINGLE_SIGN_ON group:GROUP_ACCOUNT_STATUS] boolValue] &&
        [[self preferenceForKey:KEY_SIPE_PASSWORD group:GROUP_ACCOUNT_STATUS] isEqualToString:@""] )
    {
        [self setPasswordTemporarily:@"placeholder"];
    }
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
    NSString        *purpleStatusID = [NSString stringWithUTF8String:purple_status_get_id(status)];
    
    if (!purpleStatusID) return nil;
    
    if (sipe_to_adium_status[purpleStatusID])
        statusName = sipe_to_adium_status[purpleStatusID];
    else {
        AILog(@"(ESPurpleSIPEAccount) Unknown purpleStatusID in statusNameForPurpleBuddy: %@", purpleStatusID);
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
     
     if ( adium_to_sipe_status[statusName] )
         statusID = [adium_to_sipe_status[statusName] UTF8String];
     else {
         AILog(@"(ESPurpleSIPEAccount): Unknown statusName in purpleStatusIDForStatus: %@", statusName);
         statusID = [super purpleStatusIDForStatus:statusState arguments:arguments];
     }
     
     return statusID;
 }


@end
