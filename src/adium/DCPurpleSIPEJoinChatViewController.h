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

@interface DCPurpleSIPEJoinChatViewController : DCJoinChatViewController <NSComboBoxDataSource> {
    
	IBOutlet	NSComboBox			*combo_rooms;
	IBOutlet	NSProgressIndicator *progress_fetch;

	NSTimer							*timer;
	NSMutableDictionary				*room_dict;
	struct _PurpleRoomlist			*room_list;
}

@end
