//
//  ESSIPEService.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Copyright 2009 Matt Meissner. All rights reserved.
//

#import <AppKit/AppKit.h>

#import <AIUtilities/AICharacterSetAdditions.h>
#import <AIUtilities/AIImageAdditions.h>
#import <Adium/AIStatusControllerProtocol.h>
#import <AISharedAdium.h>

#import "ESSIPEAccountViewController.h"
#import "ESPurpleSIPEAccount.h"
#import "ESSIPEService.h"

@implementation ESSIPEService

//Account Creation -----------------------------------------------------------------------------------------------------
#pragma mark Account Creation

- (Class)accountClass
{
	return [ESPurpleSIPEAccount class];
}

- (AIAccountViewController *)accountViewController{
    return [ESSIPEAccountViewController accountViewController];
}

//Service Description --------------------------------------------------------------------------------------------------
#pragma mark Service Description
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
    return @"Office Communicator";
}

- (NSString *)longDescription{
    return @"Office Communicator";
}

- (NSString *)UIDPlaceholder
{
	return @"username@company.com,DOMAIN\\username";
}


- (NSCharacterSet *)allowedCharacters
{
	NSMutableCharacterSet *allowedCharacters = [[NSCharacterSet alphanumericCharacterSet] mutableCopy];
	NSCharacterSet *returnSet;
	
	[allowedCharacters addCharactersInString:@"._@-()[]^%#|/\\`=,"];
	returnSet = [allowedCharacters immutableCopy];
	
	return [returnSet autorelease];
}

- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType
{
	NSImage *image;
	
	if ((iconType == AIServiceIconSmall) || (iconType == AIServiceIconList)) {
		image = [NSImage imageNamed:@"sipe-small"];
	} else {
		image = [NSImage imageNamed:@"sipe"];
	}

	return image;
}

- (NSString *)pathForDefaultServiceIconOfType:(AIServiceIconType)iconType
{
	if ((iconType == AIServiceIconSmall) || (iconType == AIServiceIconList)) {
		return [[NSBundle bundleForClass:[self class]] pathForImageResource:@"sipe-small"];
	} else {
		return [[NSBundle bundleForClass:[self class]] pathForImageResource:@"sipe"];		
	}
}

//Service Properties ---------------------------------------------------------------------------------------------------
#pragma mark Service Properties

- (BOOL)canCreateGroupChats
{
	return YES;
}

- (AIServiceImportance)serviceImportance{
	return AIServiceSecondary;
}

- (void)registerStatuses{
	[adium.statusController registerStatus:STATUS_NAME_AVAILABLE
                           withDescription:[adium.statusController localizedDescriptionForCoreStatusName:STATUS_NAME_AVAILABLE]
                                    ofType:AIAvailableStatusType
                                forService:self];
}
- (BOOL)supportsPassword
{
	return YES;
}

- (BOOL)requiresPassword
{
	return YES;
}

@end

