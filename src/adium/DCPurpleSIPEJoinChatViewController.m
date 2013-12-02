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
	if ((self = [super init]))
	{
		[textField_inviteUsers setDragDelegate:self];
		[textField_inviteUsers registerForDraggedTypes:[NSArray arrayWithObjects:@"AIListObject", @"AIListObjectUniqueIDs", nil]];
	}
	
	return self;
}

- (void)configureForAccount:(AIAccount *)inAccount
{
	[super configureForAccount:inAccount];
	if ( delegate )
		[(DCJoinChatWindowController *)delegate setJoinChatEnabled:YES];
}



- (void)joinChatWithAccount:(AIAccount *)inAccount
{
 
 NSString		*room = [textField_roomName stringValue];
 NSString		*handle = [textField_handle stringValue];
 NSString		*invitemsg = [textField_inviteMessage stringValue];
 NSMutableDictionary	*chatCreationInfo;
 
  if (![handle length]) handle = nil;
 
 chatCreationInfo = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                     room, @"room",
                     nil];
 
 if (handle) {
     [chatCreationInfo setObject:handle
                          forKey:@"handle"];
 }
 
 
 [self doJoinChatWithName:[NSString stringWithFormat:@"%@",room]
                onAccount:inAccount
         chatCreationInfo:chatCreationInfo
         invitingContacts:[self contactsFromNamesSeparatedByCommas:[textField_inviteUsers stringValue] onAccount:inAccount]
    withInvitationMessage:(([invitemsg length]) ? invitemsg : nil)];
 
}

- (NSString *)nibName
{
	return @"DCPurpleSIPEJoinChatView";
}

@end
