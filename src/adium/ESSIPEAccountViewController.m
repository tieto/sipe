//
//  ESSIPEAccountViewController.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import <AdiumLibpurple/CBPurpleAccount.h>
#import <ESDebugAILog.h>
#import "ESSIPEAccountViewController.h"

#include "prpl.h"
#include "ESPurpleSIPEAccount.h"

// Gotta define these here, because they're not yet in the 10.9 SDK.  :(
#define NSAppKitVersionNumber10_8 1187
#define NSAppKitVersionNumber10_8_5 1187.4
#define NSAppKitVersionNumber10_9 1265

@implementation ESSIPEAccountViewController

- (id)init {
    self = [super init];
    
    if (self) {
        sipe_key_to_gui =
            [[NSDictionary alloc] initWithObjectsAndKeys:
             textField_windowsLogin,     KEY_SIPE_WINDOWS_LOGIN,
             textField_password,         KEY_SIPE_PASSWORD,
             textField_server,           KEY_SIPE_CONNECT_HOST,
             popup_connectionType,       KEY_SIPE_CONNECTION_TYPE,
             popup_authenticationScheme, KEY_SIPE_AUTH_SCHEME,
             textField_userAgent,        KEY_SIPE_USER_AGENT,
             checkBox_singleSignOn,      KEY_SIPE_SINGLE_SIGN_ON,
             checkbox_beastDisable,      KEY_SIPE_BEAST_DISABLE,
             textField_groupchatUser,    KEY_SIPE_GROUP_CHAT_PROXY,
             textField_emailURL,         KEY_SIPE_EMAIL_URL,
             textField_email,            KEY_SIPE_EMAIL,
             textField_emailLogin,       KEY_SIPE_EMAIL_LOGIN,
             textField_emailPassword,    KEY_SIPE_EMAIL_PASSWORD,
             checkbox_dontPublish,       KEY_SIPE_DONT_PUBLISH,
             nil
             ];
    }
    
    return self;
}

- (void)dealloc
{
    [sipe_key_to_gui release];
    [super dealloc];
}

- (NSString *)nibName{
    return @"ESSIPEAccountView";
}

#pragma mark Configuration methods
- (void)configureForAccount:(AIAccount *)inAccount
{
    [super configureForAccount:inAccount];

    // BEAST mitigation for Mavericks and 10.8.5 users (with Security Update 2014-001)
    if (NSAppKitVersionNumber < NSAppKitVersionNumber10_8_5) {
        // We are not running on an OS with BEAST mitigations - Don't display this as a configuration option
        [checkbox_beastDisable setHidden:YES];
    }
    
    // Only need 1 hash for both connection & auth since there are no overlapping keys
    NSDictionary *conn_auth_dict =
    [NSDictionary dictionaryWithObjectsAndKeys:
     @"NTLM",@"ntlm",
     @"Kerberos",@"krb5",
     @"TLS-DSK",@"tls-dsk",
     @"Auto",@"auto",
     @"SSL/TLS",@"tls",
     @"TCP",@"tcp",
     nil];
    
    for (NSString* key in sipe_key_to_gui) {
        id value = [sipe_key_to_gui objectForKey:key];
        
        if ([value isKindOfClass:[NSTextField class]]) {
            NSString *tmp = [account preferenceForKey:key group:GROUP_ACCOUNT_STATUS];
            [value setStringValue:(tmp ? tmp : @"")];
        } else if ([value isKindOfClass:[NSPopUpButton class]]) {
            // NSPopUpButton *MUST* appear before NSButton in the if/else
            //   because  NSPopUpButton is a NSButton...
            NSString *tmp_key = [account preferenceForKey:key group:GROUP_ACCOUNT_STATUS];
            NSString *tmp = @"auto";
            
            if ([conn_auth_dict objectForKey:tmp_key])
                tmp = [conn_auth_dict objectForKey:tmp_key];
            
            [value selectItemWithTitle:tmp];
        } else if ([value isKindOfClass:[NSButton class]]) {
            [value setState:[[account preferenceForKey:key group:GROUP_ACCOUNT_STATUS] boolValue]];
        } else {
            AILog(@"(ESSIPEAccountViewController) Unknown class %@ for key %@", [value class], key);
        }
    }
}

- (void)saveConfiguration
{
    [super saveConfiguration];
    
    // Only need 1 hash for both connection & auth since there are no overlapping keys
    NSDictionary *conn_auth_dict =
    [NSDictionary dictionaryWithObjectsAndKeys:
     @"ntlm",@"NTLM",
     @"krb5",@"Kerberos",
     @"tls-dsk",@"TLS-DSK",
     @"auto",@"Auto",
     @"tls",@"SSL/TLS",
     @"tcp",@"TCP",
     nil];
    
    for (NSString* key in sipe_key_to_gui) {
        id value = [sipe_key_to_gui objectForKey:key];
        
        if ([value isKindOfClass:[NSTextField class]]) {
            [account
             setPreference:[[value stringValue] length] ? [value stringValue] : @""
             forKey:key
             group:GROUP_ACCOUNT_STATUS];
        } else if ([value isKindOfClass:[NSPopUpButton class]]) {
            // NSPopUpButton *MUST* appear before NSButton in the if/else
            //   because  NSPopUpButton is a NSButton...
            NSString *tmp = [conn_auth_dict objectForKey:[[value selectedItem] title]];
            [account
             setPreference:tmp
             forKey:key
             group:GROUP_ACCOUNT_STATUS];
        } else if ([value isKindOfClass:[NSButton class]]) {
            [account
             setPreference:[NSNumber numberWithBool:[value state]]
             forKey:key
             group:GROUP_ACCOUNT_STATUS];
        } else {
            AILog(@"(ESSIPEAccountViewController) Unknown class %@ for key %@", [value class], key);
        }
    }
}

@end
