//
//  ESSIPEService.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
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
	
	[allowedCharacters addCharactersInString:@"._@-()[]^%#|/\\`=,"];
	returnSet = [allowedCharacters immutableCopy];
	
	return [returnSet autorelease];
}

#pragma mark Statuses
- (void)registerStatuses{
    NSDictionary *statuses =
    [NSDictionary dictionaryWithObjectsAndKeys:
     AIAvailableStatusType, STATUS_NAME_AVAILABLE,
     AIAwayStatusType,      STATUS_NAME_AWAY,
     AIAwayStatusType,      STATUS_NAME_BUSY,
     AIInvisibleStatusType, STATUS_NAME_INVISIBLE,
     AIAwayStatusType,      STATUS_NAME_BRB,
     AIAwayStatusType,      STATUS_NAME_DND,
     AIAwayStatusType,      STATUS_NAME_LUNCH,
     AIOfflineStatusType,   STATUS_NAME_OFFLINE,
     AIAwayStatusType,      STATUS_NAME_PHONE,
     AIAwayStatusType,      STATUS_NAME_NOT_AT_DESK,
     AIAwayStatusType,      STATUS_NAME_NOT_IN_OFFICE,
     AIAwayStatusType,      STATUS_NAME_AWAY_FRIENDS_ONLY,
     nil
     ];
    
    for (NSString* key in statuses) {
        AIStatusType value = [statuses objectForKey:key];
        
        [adium.statusController
         registerStatus:key
         withDescription:[adium.statusController localizedDescriptionForCoreStatusName:key]
         ofType:value
         forService:self
         ];
    }
}


@end

