//
//  ESSIPEAccountViewController.m
//  SIPEAdiumPlugin
//
//  Created by Matthew Duggan on 10/12/23.
//  Copyright 2010 Matthew Duggan. All rights reserved.
//

#import "ESSIPEAccountViewController.h"

#import <AdiumLibpurple/CBPurpleAccount.h>

#include "prpl.h"
#include "ESPurpleSIPEAccount.h"

@implementation ESSIPEAccountViewController

- (NSString *)nibName{
    return @"ESSIPEAccountView";
}

- (void)awakeFromNib
{
	[super awakeFromNib];
}

- (void)configureForAccount:(AIAccount *)inAccount
{
    [super configureForAccount:inAccount];
    
	NSString *windowsLogin = [account preferenceForKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
	[textField_windowsLogin setStringValue:(windowsLogin ? windowsLogin : @"")];

	int ctype = [[account preferenceForKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS] intValue];
	[popUp_conntype selectItemWithTag:ctype];

	//NSString *email = [account preferenceForKey:KEY_SIPE_EMAIL group:GROUP_ACCOUNT_STATUS];
	//[textField_email setStringValue:(email ? email : @"")];

	//NSString *emailurl = [account preferenceForKey:KEY_SIPE_EMAIL_URL group:GROUP_ACCOUNT_STATUS];
	//[textField_emailURL setStringValue:(emailurl ? emailurl : @"")];
}

- (void)saveConfiguration
{
	[super saveConfiguration];

	//Resource
	[account setPreference:[textField_windowsLogin stringValue]
					forKey:KEY_SIPE_WINDOWS_LOGIN group:GROUP_ACCOUNT_STATUS];
    
    int ctype = [[popUp_conntype selectedItem] tag];
	[account setPreference:[NSNumber numberWithInt:ctype]
					forKey:KEY_SIPE_CONNECTION_TYPE group:GROUP_ACCOUNT_STATUS];
    
}	

@end
