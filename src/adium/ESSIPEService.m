//
//  ESSIPEService.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//  Copyright (C) 2014 SIPE Project <http://sipe.sourceforge.net/>
//

#import <AIUtilities/AICharacterSetAdditions.h>
#import <AIUtilities/AIImageAdditions.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <AISharedAdium.h>

#import "DCPurpleSIPEJoinChatViewController.h"
#import "ESSIPEAccountViewController.h"
#import "ESPurpleSIPEAccount.h"
#import "ESSIPEService.h"

@implementation ESSIPEService

#pragma mark Account/Chat Creation
- (Class)accountClass
{
	return [ESPurpleSIPEAccount class];
}

- (AIAccountViewController *)accountViewController{
    return [ESSIPEAccountViewController accountViewController];
}

- (DCJoinChatViewController *)joinChatView{
	return [DCPurpleSIPEJoinChatViewController joinChatView];
}

- (BOOL)canCreateGroupChats{
	return YES;
}

#pragma mark Service Description Metadata
- (NSString *)serviceCodeUniqueID{
    return @"libpurple-SIPE";
}

- (NSString *)serviceID{
    return @"SIPE";
}

- (NSString *)serviceClass{
	return @"SIPE";
}

- (NSString *)shortDescription{
    return @"OCS";
}

- (NSString *)longDescription{
    return @"Office Communicator";
}

- (BOOL)caseSensitive{
	return NO;
}
- (AIServiceImportance)serviceImportance{
	return AIServiceSecondary;
}

// Some auth schemes may not need a password
- (BOOL)requiresPassword{
	return NO;
}

- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType {
	NSImage *baseImage = [NSImage imageNamed:@"sipe" forClass:[self class]];

	if ((iconType == AIServiceIconSmall) || (iconType == AIServiceIconList)) { 
        [baseImage setSize:NSMakeSize(16, 16)];
	}

	return baseImage;
}


#pragma mark Service Properties
- (NSCharacterSet *)allowedCharacters
{
	NSMutableCharacterSet *allowedCharacters = [[NSCharacterSet alphanumericCharacterSet] mutableCopy];
	NSCharacterSet *returnSet;

	//
	// NOTE: needs to be in sync with sipe-utils.c:escape_uri_part()
	//
	// @     -   XXX@YYY
	// :     -   sip:XXX@YYY
	// ._-~  -   unreserved, see RFC 3986 Appendix A
	//
	[allowedCharacters addCharactersInString:@"@:._-~"];
	returnSet = [allowedCharacters immutableCopy];
    [allowedCharacters release];
    
	return [returnSet autorelease];
}

#pragma mark Statuses
- (void)registerStatuses{
    
    NSNumber *awayStatus, *availableStatus, *invisibleStatus, *offlineStatus;
    
    awayStatus = [NSNumber numberWithInt:AIAwayStatusType];
    availableStatus = [NSNumber numberWithInt:AIAvailableStatusType];
    invisibleStatus = [NSNumber numberWithInt:AIInvisibleStatusType];
    offlineStatus = [NSNumber numberWithInt:AIOfflineStatusType];
    
    NSDictionary *statuses =
    [NSDictionary dictionaryWithObjectsAndKeys:
     availableStatus, STATUS_NAME_AVAILABLE,
     awayStatus,      STATUS_NAME_AWAY,
     awayStatus,      STATUS_NAME_BUSY,
     invisibleStatus, STATUS_NAME_INVISIBLE,
     awayStatus,      STATUS_NAME_BRB,
     awayStatus,      STATUS_NAME_DND,
     awayStatus,      STATUS_NAME_LUNCH,
     offlineStatus,   STATUS_NAME_OFFLINE,
     awayStatus,      STATUS_NAME_PHONE,
     awayStatus,      STATUS_NAME_NOT_AT_DESK,
     awayStatus,      STATUS_NAME_NOT_IN_OFFICE,
     awayStatus,      STATUS_NAME_AWAY_FRIENDS_ONLY,
     nil
     ];

    for (NSString* key in statuses) {
        AIStatusType value = [[statuses objectForKey:key] intValue];

        [adium.statusController
         registerStatus:key
         withDescription:[adium.statusController localizedDescriptionForCoreStatusName:key]
         ofType:value
         forService:self
         ];
    }
}


@end
