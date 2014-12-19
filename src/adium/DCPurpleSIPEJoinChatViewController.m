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
    
    // TODO: allow creation of OCS "Conference" (different from group-chat)
    // Add a text field (UI should have radio buttons to enable/disable
    // create a PurpleBuddy* based off of the username entered in the text field
    // then call:
    //      sipe_core_buddy_new_chat(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC, purple_buddy_get_name(buddy));
    // which should kick off the Adium code to open a chat window.
    
}

- (NSString *)nibName
{
	return @"DCPurpleSIPEJoinChatView";
}

@end
