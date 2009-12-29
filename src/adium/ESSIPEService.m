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

#import "ESPurpleSIPEAccount.h"
#import "ESSIPEService.h"

@implementation ESSIPEService

//Account Creation -----------------------------------------------------------------------------------------------------
#pragma mark Account Creation

- (Class)accountClass
{
	return [ESPurpleSIPEAccount class];
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
	return @"first.last.company.com@company.net";
}

- (NSCharacterSet *)allowedCharacters
{
	NSMutableCharacterSet *allowedCharacters = [[NSCharacterSet alphanumericCharacterSet] mutableCopy];
	NSCharacterSet *returnSet;
	
	[allowedCharacters addCharactersInString:@"._@-()[]^%#|\\`=,"];
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

@end

