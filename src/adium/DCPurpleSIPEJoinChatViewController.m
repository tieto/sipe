//
//  DCPurpleSIPEJoinChatViewController.m
//  SIPEAdiumPlugin
//
//  Copyright (C) 2015 SIPE Project <http://sipe.sourceforge.net/>
//
//  Created by Michael Lamb on 02/10/12.
//  Copyright 2012 Michael Lamb. All rights reserved.
//

#import "DCPurpleSIPEJoinChatViewController.h"
#import <Adium/AIChatControllerProtocol.h>
#import "DCJoinChatWindowController.h"
#import <Adium/AIAccount.h>
#import <ESDebugAILog.h>
#import "CBPurpleAccount.h"
#import "roomlist.h"

@implementation DCPurpleSIPEJoinChatViewController

- (id)init
{
    self = [super init];
    if (self) {
        room_dict = [[NSMutableDictionary alloc] init];
        combo_rooms.usesDataSource = YES;
        combo_rooms.completes  = YES;
        combo_rooms.dataSource = self;
    }
    return self;
}

- (void)dealloc
{
    [timer invalidate];
    timer = nil;
    if (room_list != NULL) {
        purple_roomlist_unref(room_list);
        room_list = NULL;
    }
    [room_dict release];
    [super dealloc];
}

- (void)configureForAccount:(AIAccount *)inAccount
{
    [super configureForAccount:inAccount];
    if ( delegate ) {
        [(DCJoinChatWindowController *)delegate setJoinChatEnabled:YES];
    }

    // get room list
    if (room_list == NULL) {
        // we want to run that code only once (configureForAccount is called twice actually)
        CBPurpleAccount *pinAccount = (CBPurpleAccount*)inAccount;
        room_list = purple_roomlist_get_list(pinAccount.purpleAccount->gc);
        if (room_list) {
            purple_roomlist_ref(room_list);
            [progress_fetch startAnimation:self];
            // start a timer to control when the fetching is done
            timer = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                     target:self
                                                   selector:@selector(checkForRoomlistFetchCompletion:)
                                                   userInfo:nil
                                                    repeats:YES];
        } else {
            [progress_fetch setHidden:YES];
            AILog(@"(DCPurpleSIPEJoinChatViewController) Can't fetch room list.");
        }
    }
}

- (void)joinChatWithAccount:(AIAccount *)inAccount
{
    NSString *uri = nil;
    NSInteger idx = [combo_rooms indexOfSelectedItem];

    if (idx >= 0 && [room_dict count]) {
        // get selected entry
        NSString *key = [[room_dict allKeys] objectAtIndex:idx];

        if (key)
            uri = [room_dict valueForKey:key];

    } else
        uri = [combo_rooms stringValue];

    if (uri && [uri length]) {
        NSRange res = [uri rangeOfString:@"ma-chan://" options:NSCaseInsensitiveSearch];

        if (res.location != 0) {
            NSAlert *alert = [[NSAlert alloc] init];

            [alert setMessageText:@"Invalid room URI"];
            [alert setInformativeText:[combo_rooms toolTip]];
            [alert addButtonWithTitle:@"Ok"];
            [alert runModal];
            [alert release];

        } else {

            [self doJoinChatWithName:[NSString stringWithFormat:@"%@",uri]
                           onAccount:inAccount
                    chatCreationInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                      uri, @"uri",
                                      nil]
                    invitingContacts:nil
               withInvitationMessage:nil];

        }
    } else {
        AILog(@"(DCPurpleSIPEJoinChatViewController) No URI specified.");
    }

    // TODO: allow creation of OCS "Conference" (different from group-chat)
    // Add a text field (UI should have radio buttons to enable/disable
    // create a PurpleBuddy* based off of the username entered in the text field
    // then call:
    //        sipe_core_buddy_new_chat(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC, purple_buddy_get_name(buddy));
    // which should kick off the Adium code to open a chat window.

}

- (void)checkForRoomlistFetchCompletion:(NSTimer*) aTimer
{
    if (room_list && purple_roomlist_get_in_progress(room_list) == FALSE) {
        [progress_fetch stopAnimation:self];
        [progress_fetch setHidden:YES];
        [timer invalidate];
        timer = nil;

        // finally copy the list into our dict
        for (GList *rooms = room_list->rooms; rooms != NULL; rooms = rooms->next) {
            PurpleRoomlistRoom *room = rooms->data;
            gchar *roomName = room->name;
            gchar *uriStr    = room->fields->data;
            if (roomName != NULL && uriStr != NULL) {
                NSString *nameStr = [NSString stringWithUTF8String:roomName];
                if ([room_dict objectForKey:nameStr] == nil) {
                    [room_dict setObject:[NSString stringWithUTF8String:uriStr] forKey:nameStr];
                }
            }
        }

        purple_roomlist_unref(room_list);
        room_list = NULL;
    }
}

#pragma mark NSComboBoxDataSource

- (NSInteger) numberOfItemsInComboBox:(NSComboBox*) aComboBox
{
    return [room_dict count];
}
- (id)comboBox:(NSComboBox *)aComboBox objectValueForItemAtIndex:(NSInteger)index
{
    NSArray* keys = [room_dict allKeys];
    return [keys objectAtIndex:index];
}

// String completion
- (NSString *)comboBox:(NSComboBox *)aComboBox completedString:(NSString *)uncompletedString
{
    if ([room_dict count] == 0 || uncompletedString == nil) {
        return @"";
    }
    NSArray *keys = [room_dict allKeys];
    for (NSString *key in keys) {
        NSRange res = [key rangeOfString:uncompletedString options:NSCaseInsensitiveSearch];
        if (res.location != NSNotFound && res.location == 0) {
            return key;
        }
    }

    return @"";
}

- (NSUInteger)comboBox:(NSComboBox *)aComboBox indexOfItemWithStringValue:(NSString *)aString
{
    if ([room_dict count] == 0) {
        return NSNotFound;
    }
    NSArray *keys = [room_dict allKeys];
    return [keys indexOfObjectIdenticalTo:aString];
}

#pragma mark

- (NSString *)nibName
{
    return @"DCPurpleSIPEJoinChatView";
}

@end
