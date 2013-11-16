//
//  ESSIPEAccountViewController.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//


#import "ESSIPEAccountViewController.h"

#import <AdiumLibpurple/CBPurpleAccount.h>

#include "prpl.h"
#include "ESPurpleSIPEAccount.h"

@implementation ESSIPEAccountViewController

- (NSString *)nibName{
    return @"ESSIPEAccountView";
}

#pragma mark Configuration methods
- (void)configureForAccount:(AIAccount *)inAccount
{
    [super configureForAccount:inAccount];
    
    NSString *server = [account preferenceForKey:KEY_SIPE_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
    [textField_server setStringValue:(server ? server : @"")];
    
    NSString *windowsLogin = [account preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
	[textField_windowsLogin setStringValue:(windowsLogin ? windowsLogin : @"")];
    
 	[checkBox_singleSignOn setState:[[account preferenceForKey:KEY_SIPE_SINGLE_SIGN_ON group:GROUP_ACCOUNT_STATUS] boolValue]];
    
	[checkbox_dontPublish setState:[[account preferenceForKey:KEY_SIPE_DONT_PUBLISH group:GROUP_ACCOUNT_STATUS] boolValue]];

	NSString *userAgent = [account preferenceForKey:KEY_SIPE_USER_AGENT group:GROUP_ACCOUNT_STATUS];
	[textField_userAgent setStringValue:(userAgent ? userAgent : @"")];
    
	NSString *emailURL = [account preferenceForKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
	[textField_emailURL setStringValue:(emailURL ? emailURL : @"")];
    
    NSString *email = [account preferenceForKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
	[textField_email setStringValue:(email ? email : @"")];
    
    NSString *emailLogin = [account preferenceForKey:KEY_SIPE_EMAIL_LOGIN group:GROUP_ACCOUNT_STATUS];
	[textField_emailLogin setStringValue:(emailLogin ? emailLogin : @"")];
    
    NSString *emailPassword = [account preferenceForKey:KEY_SIPE_EMAIL_PASSWORD group:GROUP_ACCOUNT_STATUS];
	[textField_emailPassword setStringValue:(emailPassword ? emailPassword : @"")];
    
    NSString *groupchatUser = [account preferenceForKey:KEY_SIPE_GROUP_CHAT_PROXY group:GROUP_ACCOUNT_STATUS];
	[textField_groupchatUser setStringValue:(groupchatUser ? groupchatUser : @"")];
    
    NSString *connType = [account preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS];
    NSDictionary *connTypeDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                  @"Auto",@"auto",
                                  @"SSL/TLS",@"tls",
                                  @"TCP",@"tcp",
                                  nil];
    [popup_connectionType selectItemWithTitle:[connTypeDict objectForKey:(connType ? connType : @"auto")]];
    
    NSString *authType = [account preferenceForKey:KEY_SIPE_AUTH_SCHEME group:GROUP_ACCOUNT_STATUS];
    NSDictionary *authTypeDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                  @"NTLM",@"ntlm",
                                  @"Kerberos",@"krb5",
                                  @"TLS-DSK",@"tls-dsk",
                                  nil];
    [popup_authenticationScheme selectItemWithTitle:[authTypeDict objectForKey:(authType ? authType : @"ntlm")]];
}

- (void)saveConfiguration
{
    [super saveConfiguration];
    
    [account setPreference:[textField_windowsLogin stringValue]
					forKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
    
    [account setPreference:[textField_server stringValue]
                    forKey:KEY_SIPE_CONNECT_HOST group:GROUP_ACCOUNT_STATUS];
    
    // TODO: Figure out how to only save the password if the user has "Save password" checked
    [account setPreference:[textField_password stringValue]
					forKey:KEY_SIPE_PASSWORD group:GROUP_ACCOUNT_STATUS];
    
	[account setPreference:[NSNumber numberWithBool:[checkBox_singleSignOn state]]
                    forKey:KEY_SIPE_SINGLE_SIGN_ON group:GROUP_ACCOUNT_STATUS];
    
	[account setPreference:[NSNumber numberWithBool:[checkbox_dontPublish state]]
                    forKey:KEY_SIPE_DONT_PUBLISH group:GROUP_ACCOUNT_STATUS];

	[account setPreference:
     ([[textField_userAgent stringValue] length] ? [textField_userAgent stringValue] : nil)
                    forKey:KEY_SIPE_USER_AGENT group:GROUP_ACCOUNT_STATUS];
    
    [account setPreference:
     ([[textField_emailURL stringValue] length] ? [textField_emailURL stringValue] : nil)
                    forKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
    
    [account setPreference:
     ([[textField_email stringValue] length] ? [textField_email stringValue] : nil)
                    forKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
    
	[account setPreference:
     ([[textField_emailLogin stringValue] length] ? [textField_emailLogin stringValue] : nil)
                    forKey:KEY_SIPE_EMAIL_LOGIN group:GROUP_ACCOUNT_STATUS];
    
    [account setPreference:
     ([[textField_emailPassword stringValue] length] ? [textField_emailPassword stringValue] : nil)
                    forKey:KEY_SIPE_EMAIL_PASSWORD group:GROUP_ACCOUNT_STATUS];
    
    [account setPreference:
     ([[textField_groupchatUser stringValue] length] ? [textField_groupchatUser stringValue] : nil)
                    forKey:KEY_SIPE_GROUP_CHAT_PROXY group:GROUP_ACCOUNT_STATUS];
    
    NSMutableArray *myArray = [[NSMutableArray alloc] initWithObjects:@"auto", @"tls", @"tcp", nil];
    [account setPreference: [myArray objectAtIndex:[popup_connectionType selectedTag]]
                    forKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS];
    [myArray release];
    
    myArray = [[NSMutableArray alloc] initWithObjects:@"ntlm", @"krb5", @"tls-dsk", nil];
    [account setPreference: [myArray objectAtIndex:[popup_authenticationScheme selectedTag]]
                    forKey:KEY_SIPE_AUTH_SCHEME group:GROUP_ACCOUNT_STATUS];
    [myArray release];
}

@end
