//
//  DCPurpleSIPEJoinChatViewController.h
//  SIPEAdiumPlugin
//
//  Created by Michael Lamb on 02/10/12.
//  Copyright 2012 Michael Lamb. All rights reserved.
//

#import <Adium/DCJoinChatViewController.h>
#import <AIUtilities/AITextFieldWithDraggingDelegate.h>


@class AICompletingTextField;

@interface DCPurpleSIPEJoinChatViewController : DCJoinChatViewController {
    
	IBOutlet		NSTextField		*textField_roomName;
	IBOutlet		NSTextField		*textField_handle;
	
	IBOutlet		NSTextField					*textField_inviteMessage;
	IBOutlet		AICompletingTextField		*textField_inviteUsers;
}

@end
