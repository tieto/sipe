//
//  DCPurpleSIPEJoinChatViewController.m
//  SIPEAdiumPlugin
//
//  Created by Michael Lamb on 02/10/12.
//  Copyright 2012 Michael Lamb. All rights reserved.
//

#import "DCPurpleSIPEJoinChatViewController.h"
#import <Adium/AIChatControllerProtocol.h>
#import "DCJoinChatWindowController.h"
#import <Adium/AIAccount.h>

@implementation DCPurpleSIPEJoinChatViewController

- (id)init
{
	return [super init];
}

- (void)configureForAccount:(AIAccount *)inAccount
{
	[super configureForAccount:inAccount];
	if ( delegate )
		[(DCJoinChatWindowController *)delegate setJoinChatEnabled:YES];
}

- (void)joinChatWithAccount:(AIAccount *)inAccount
{
    NSString *uri = [textField_URI stringValue];
    NSMutableDictionary *chatCreationInfo;
 
    if (uri && [uri length]) {
        chatCreationInfo = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                            uri, @"uri",
                            nil];
 
        [self doJoinChatWithName:[NSString stringWithFormat:@"%@",uri]
                       onAccount:inAccount
                chatCreationInfo:chatCreationInfo
                invitingContacts:nil
           withInvitationMessage:nil];
    } else {
        NSLog(@"Error: No URI specified.");
    }
}

- (NSString *)nibName
{
	return @"DCPurpleSIPEJoinChatView";
}

@end
