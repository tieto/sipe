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
	return nil;
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
- (BOOL)canCreateGroupChats{
	return NO;
}

// Some auth schemes may not need a password
- (BOOL)requiresPassword{
	return NO;
}

- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType {
	NSImage *baseImage = [NSImage imageNamed:@"sipe" forClass:[self class]];
    
	if (iconType == AIServiceIconSmall) {
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
    
    
	[adium.statusController registerStatus:STATUS_NAME_AVAILABLE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AVAILABLE]
                                    ofType:AIAvailableStatusType
                                forService:self];
	
	[adium.statusController registerStatus:STATUS_NAME_AWAY
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AWAY]
                                    ofType:AIAwayStatusType
                                forService:self];
	
	[adium.statusController registerStatus:STATUS_NAME_BUSY
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BUSY]
                                    ofType:AIAwayStatusType
                                forService:self];
    
	[adium.statusController registerStatus:STATUS_NAME_INVISIBLE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_INVISIBLE]
                                    ofType:AIInvisibleStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_BRB
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_BRB]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_DND
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_DND]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_LUNCH
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_LUNCH]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_OFFLINE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_OFFLINE]
                                    ofType:AIOfflineStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_PHONE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_PHONE]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_NOT_AT_DESK
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_NOT_AT_DESK]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_NOT_IN_OFFICE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_NOT_IN_OFFICE]
                                    ofType:AIAwayStatusType
                                forService:self];
    
    [adium.statusController registerStatus:STATUS_NAME_AWAY_FRIENDS_ONLY
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AWAY_FRIENDS_ONLY]
                                    ofType:AIAwayStatusType
                                forService:self];
}


@end

